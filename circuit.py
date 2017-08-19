# Endosome: a Tor cell construction kit
#
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

from pack import *
from connect import *
from cell import *
from link import *

# Circuit-level functions




def get_circuits(context):
    '''
    Return the circuits from context. Supports link and circuit contexts.
    If context does not have circuits, return an empty dict.
    '''
    # Use the link context from circuit contexts
    if 'link' in context:
        context = context['link']
    return context.get('circuits', {})

def is_circ_id_used(context, circ_id):
    '''
    Returns True if circ_id is used in context, and False if it is not.
    Supports link and circuit contexts.
    '''
    return circ_id in get_circuits(context)

def get_unused_circ_id(context, is_initiator_flag=True,
                       force_link_version=None):
    '''
    Returns the first valid, unused circ_id in context.
    Supports link and circuit contexts.
    '''
    link_version = get_link_version(context, force_link_version)
    circ_id = get_min_valid_circ_id(link_version,
                                    is_initiator_flag=is_initiator_flag)
    while is_circ_id_used(context, circ_id):
        circ_id += 1
        assert circ_id < get_max_valid_circ_id(link_version)
    return circ_id

# See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n997
KH_LEN = HASH_LEN
DF_LEN = HASH_LEN
DB_LEN = HASH_LEN
KF_LEN = KEY_LEN
KB_LEN = KEY_LEN
KDF_TOR_LEN = KH_LEN + DF_LEN + DB_LEN + KF_LEN + KB_LEN

def circuit_create(link_context,
                   create_cell_command_string='CREATE_FAST',
                   circ_id=None,
                   force_link_version=None,
                   max_response_len=MAX_READ_BUFFER_LEN,
                   validate=True):
    '''
    Create a single-hop circuit using create_cell_command_string with circ_id,
    on the link in link_context.
    force_link_version overrides the link version in context.

    If circ_id is None, use an unused, valid circuit ID for the link version.
    If validate is true, check that that the remote KH matches the expected
    value.

    Read up to max_response_len in response, and returns a context dictionary
    required to continue using the circuit:
        'circ_id'            : the circuit id for this circuit
        'link'               : the link context for this circuit
    And the first hop (TODO: put these in a different structure):
        'K0_bytes'           : the shared key for the circuit
        'KH_bytes'           : a hash that shows the remote side knows K0
        'Df_bytes'           : the forward digest seed, derived from K0
        'Df_hash'            : the forward digest hash, seeded with Df_bytes
        'Db_bytes'           : the backward digest seed, derived from K0
        'Db_hash'            : the backward digest hash, seeded with Db_bytes
        'Kf_bytes'           : the forward encryption key, derived from K0
        'Kf_crypt'           : the forward encryption context, key Kf_bytes
        'Kb_bytes'           : the backward encryption key, derived from K0
        'Kb_crypt'           : the backward decryption context, key Kb_bytes
        'create_cell_bytes'  : the create cell sent to establish the circuit
        'created_cell_bytes' : the created cell received in response
    Also adds the following entries to the link context:
       'circuits'            : a dictionary containing the circuits on this
                               link, keyed by circuit id
       'circuits'/circ_id    : the circuit context for this circuit
    '''
    # choose an unused circuit id, not just the lowest one
    if circ_id is None:
        circ_id = get_unused_circ_id(link_context, is_initiator_flag=True,
                                     force_link_version=force_link_version)
    # Send the circuit request
    if create_cell_command_string == 'CREATE_FAST':
        # Relays drop create cells for circuit ids that are in use
        # If we don't do this check, we will hang when reading
        assert not is_circ_id_used(link_context, circ_id)
        create_cell_bytes = link_write_cell(link_context,
                                      create_cell_command_string,
                                      circ_id=circ_id,
                                      payload_bytes=pack_create_fast_payload(),
                                      force_link_version=force_link_version)
        (_, create_cell_list) = unpack_cells_link(link_context,
                                       create_cell_bytes,
                                       force_link_version=force_link_version)
        assert len(create_cell_list) == 1
        create_cell = create_cell_list[0]
        local_circ_id = create_cell['circ_id']
        X_bytes = create_cell['X_bytes']
    else:
        # TODO: TAP & ntor handshakes, which need onion keys from descriptors
        raise ValueError("{} not yet implemented"
                         .format(create_cell_command_string))
    # Make sure we sent a cell, if not, we will hang when reading
    assert local_circ_id is not None

    # Read and parse the response
    # You will hang here if you send a duplicate circuit ID
    created_cell_bytes = link_read_cell_bytes(link_context,
                                           max_response_len=max_response_len)
    (_, cell_list) = unpack_cells_link(link_context, created_cell_bytes,
                                       force_link_version=force_link_version)
    # Now find the created cell
    for cell in cell_list:
        # Find the create cell, and add it to the circuit context
        cell_command_string = cell['cell_command_string']
        if cell_command_string.startswith('CREATED'):
            created_cell = cell
            remote_circ_id = created_cell['circ_id']
            # if our circuit requests get out of order, nothing will work
            assert local_circ_id == remote_circ_id
            if cell_command_string == 'CREATED_FAST':
                KH_bytes = created_cell['KH_bytes']
                Y_bytes = created_cell['Y_bytes']
                # K0=X|Y
                # See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1007
                K0_bytes = X_bytes + Y_bytes
                # Create the circuit material using a KDF
                temp_bytes = kdf_tor(K0_bytes, KDF_TOR_LEN)
                # Extract the circuit material
                (expected_KH_bytes, temp_bytes) = split_field(KH_LEN,
                                                              temp_bytes)
                if validate:
                    #print "X: " + binascii.hexlify(X_bytes)
                    #print "Y: " + binascii.hexlify(Y_bytes)
                    #print "KH (server): " + binascii.hexlify(KH_bytes)
                    #print "KH (client): " + binascii.hexlify(expected_KH_bytes)
                    assert KH_bytes == expected_KH_bytes
                (Df_bytes, temp_bytes) = split_field(DF_LEN, temp_bytes)
                (Db_bytes, temp_bytes) = split_field(DB_LEN, temp_bytes)
                (Kf_bytes, temp_bytes) = split_field(KF_LEN, temp_bytes)
                (Kb_bytes, temp_bytes) = split_field(KB_LEN, temp_bytes)
                #print "Df: " + binascii.hexlify(Df_bytes)
                #print "Db: " + binascii.hexlify(Db_bytes)
                #print "Kf: " + binascii.hexlify(Kf_bytes)
                #print "Kb: " + binascii.hexlify(Kb_bytes)
                # Seed the hash digests
                Df_hash = hash_create()
                Df_hash = hash_update(Df_hash, Df_bytes)
                Db_hash = hash_create()
                Db_hash = hash_update(Db_hash, Db_bytes)
                # Create the crypto contexts
                Kf_crypt = crypt_create(Kf_bytes, is_encrypt_flag=True)
                Kb_crypt = crypt_create(Kb_bytes, is_encrypt_flag=False)
            else:
                # TODO: TAP & ntor handshakes, which need onion keys from
                # descriptors
                raise ValueError("{} not yet implemented"
                                 .format(cell_command_string))
            # we found the CREATED cell, so stop looking
            break

    # If we don't have the fields we need to continue using the circuit, we
    # will assert here when we try to find them, or later when we try to use
    # them

    # Create the circuit context
    circuit_context = {
        # circuit
        'circ_id'            : remote_circ_id,
        'link'               : link_context,
        # hop
        # TODO: multi-hop circuits: next_hop_context and previous_hop_context?
        # Or a hop array?
        'K0_bytes'           : K0_bytes,
        'KH_bytes'           : KH_bytes,
        'Df_bytes'           : Df_bytes,
        'Df_hash'            : Df_hash,
        'Db_bytes'           : Db_bytes,
        'Db_hash'            : Db_hash,
        'Kf_bytes'           : Kf_bytes,
        'Kf_crypt'           : Kf_crypt,
        'Kb_bytes'           : Kb_bytes,
        'Kb_crypt'           : Kb_crypt,
        'create_cell_bytes'  : create_cell_bytes,
        'created_cell_bytes' : created_cell_bytes,
        }

    # Update the link context with the circuit context
    link_context.setdefault('circuits', {})
    # This creates a circular reference, which modern python GCs can handle
    link_context['circuits'][remote_circ_id] = circuit_context
    return circuit_context

def circuit_crypt_cell_payload(context,
                               cell,
                               hop_hash_context,
                               hop_crypt_context,
                               force_link_version=None):
    '''
    Pack and crypt the relay payload in cell, using hop_hash_context and
    hop_crypt_context. The link_version in context is used to pack the cell.
    force_link_version overrides the link_version in context.
    Returns cell with a crypted cell payload, the new hop_hash_context,
    the modified hop_crypt_context, and the packed, plaintext cell bytes.
    '''
    relay_command_string = cell['relay_command_string']
    stream_id = cell.get('stream_id')
    relay_payload_bytes = cell.get('relay_payload_bytes')
    force_recognized_bytes = cell.get('force_recognized_bytes')
    force_digest_bytes = cell.get('force_digest_bytes')
    force_relay_payload_len = cell.get('force_relay_payload_len')
    (crypt_payload_bytes, plain_payload_bytes,
     hop_hash_context, hop_crypt_context) = \
            pack_relay_payload(relay_command_string,
                               hop_hash_context,
                               hop_crypt_context,
                               stream_id=stream_id,
                               relay_payload_bytes=relay_payload_bytes,
                               force_recognized_bytes=force_recognized_bytes,
                               force_digest_bytes=force_digest_bytes,
                               force_relay_payload_len=force_relay_payload_len)
    # Pack the un-crypted payload for display purposes
    cell['payload_bytes'] = plain_payload_bytes
    plain_cell_bytes = link_pack_cell(context['link'],
                                      cell,
                                      force_link_version=force_link_version)
    # Return the crypted payload
    cell['payload_bytes'] = crypt_payload_bytes
    return (cell,
            hop_hash_context,
            hop_crypt_context,
            plain_cell_bytes)

def circuit_write_cell_list(context,
                            cell_list,
                            force_link_version=None):
    '''
    Pack, encrypt and send the Tor cells specified by cell_list on the circuit
    in context, using the link_version in context. force_link_version overrides
    the link_version in context.
    The other arguments are as in pack_cell() and pack_relay_payload().
    An empty cell list is allowed: no cells are sent.
    Each dict in cell_list can have all the elements listed in
    link_write_cell_list(), with the following additions and changes:
        circ_id                : mandatory, taken from context if missing
        payload_bytes          : unused, replaced by relay content
        force_payload_len      : replaces len(relay content) in the cell header
        relay_command_string   : the name of the relay command
        stream_id              : a unique stream id for this circuit (optional)
        relay_payload_bytes    : the relay payload bytes (optional)
        force_recognized_bytes : a set value to use for the 'recognized' field
        force_digest_bytes     : a set value to use for the digest field
        force_relay_payload_len: replaces len(relay_payload_bytes) in the
                                 relay header
    Returns a tuple containing a copy of the cell list, with extra fields,
    the cell bytes sent on the wire (after cell encryption), and the
    concatenated plaintext cell bytes.
    The returned cell list includes circ_id and encrypted payload_bytes for
    each cell.
    '''
    sent_cell_list = []
    plain_cells_bytes = bytearray()
    # This hard-codes sending cells only in the forward direction
    # TODO: generalise, so we can send cells back as well
    hop_hash_context = context['Df_hash']
    hop_crypt_context = context['Kf_crypt']
    for cell in cell_list:
        sent_cell = cell.copy()
        # If the cell doesn't have a circuit_id, use the one from the context
        sent_cell.setdefault('circ_id', context['circ_id'])
        (sent_cell,
         hop_hash_context,
         hop_crypt_context,
         plain_cell_bytes) = circuit_crypt_cell_payload(context,
                                        sent_cell,
                                        hop_hash_context,
                                        hop_crypt_context,
                                        force_link_version=force_link_version)
        sent_cell_list.append(sent_cell)
        plain_cells_bytes += plain_cell_bytes
    # This hard-codes sending cells only in the forward direction
    # TODO: generalise, so we can send cells back as well
    context['Df_hash'] = hop_hash_context
    # This is redundant, since the crypt context is modified in-place.
    # But it's nice to show that we're modifying it along with the digest.
    context['Kf_crypt'] = hop_crypt_context
    crypt_cells_bytes = link_write_cell_list(context['link'],
                                        sent_cell_list,
                                        force_link_version=force_link_version)
    return (sent_cell_list, crypt_cells_bytes, plain_cells_bytes)

def circuit_make_relay_cell(cell_command_string,
                            relay_command_string,
                            circ_id=None,
                            force_link_version=None,
                            force_payload_len=None,
                            stream_id=None,
                            relay_payload_bytes=None,
                            force_relay_payload_len=None,
                            force_recognized_bytes=None,
                            force_digest_bytes=None):
    '''
    Return a dictionary containing the cell contents, as in
    circuit_write_cell(). cell_command_string must be RELAY or RELAY_EARLY.
    '''
    cell = link_make_cell(cell_command_string,
                          circ_id=circ_id,
                          force_link_version=force_link_version,
                          force_payload_len=force_payload_len)
    cell['relay_command_string'] = relay_command_string
    if stream_id is not None:
        cell['stream_id'] = stream_id
    if relay_payload_bytes is not None:
        cell['relay_payload_bytes'] = relay_payload_bytes
    if force_relay_payload_len is not None:
        cell['force_relay_payload_len'] = force_relay_payload_len
    if force_recognized_bytes is not None:
        cell['force_recognized_bytes'] = force_recognized_bytes
    if force_digest_bytes is not None:
        cell['force_digest_bytes'] = force_digest_bytes
    return cell

def circuit_write_cell(context,
                       cell_command_string,
                       relay_command_string,
                       circ_id=None,
                       force_link_version=None,
                       force_payload_len=None,
                       stream_id=None,
                       relay_payload_bytes=None,
                       force_relay_payload_len=None,
                       force_recognized_bytes=None,
                       force_digest_bytes=None):
    '''
    Pack, encrypt and send a Tor cell on the circuit in context.
    Returns a tuple containing the cell bytes sent on the wire (after cell
    encryption), and the cell bytes before encryption.
    See circuit_write_cell_list() for details.
    '''
    cell = circuit_make_relay_cell(cell_command_string,
                               relay_command_string,
                               circ_id=circ_id,
                               force_link_version=force_link_version,
                               force_payload_len=force_payload_len,
                               stream_id=stream_id,
                               relay_payload_bytes=relay_payload_bytes,
                               force_relay_payload_len=force_relay_payload_len,
                               force_recognized_bytes=force_recognized_bytes,
                               force_digest_bytes=force_digest_bytes)
    # The force_* arguments are redundant here
    return circuit_write_cell_list(context, [cell])

# The cell parsing functionality is in format_cell_bytes()
circuit_read_cell_bytes = link_read_cell_bytes

def circuit_close(context,
                  force_link_version=None,
                  payload_bytes=None,
                  force_payload_len=None):
    '''
    Close the circuit in context using a DESTROY cell.
    Returns the result of link_write_cell().
    '''
    cell_bytes = link_write_cell(context,
                                 'DESTROY',
                                 circ_id=context['circ_id'],
                                 force_link_version=force_link_version,
                                 payload_bytes=payload_bytes,
                                 force_payload_len=force_payload_len)
    # Enable re-use of the circuit id
    del context['link'][context['circ_id']]
    return cell_bytes

def circuit_request_cell_list(link_context,
                              cell_list,
                              create_cell_command_string='CREATE_FAST',
                              circ_id=None,
                              force_link_version=None,
                              max_response_len=MAX_READ_BUFFER_LEN,
                              validate=True,
                              do_shutdown=True):
    '''
    Send the Tor cells in cell_list on a newly created circuit on link_context,
    (force_link_version overrides the negotiated link_version),
    and read at most max_response_len bytes of response cells.
    If do_shutdown is true, send a DESTROY cell to shut down the circuit.
    Returns a tuple containing the modified link context, the circuit context,
    the crypted sent cell bytes, the plaintext sent cell bytes, and the
    (crypted) response cell bytes.
    '''
    circuit_context = circuit_create(link_context,
                         create_cell_command_string=create_cell_command_string,
                         circ_id=circ_id,
                         force_link_version=force_link_version,
                         max_response_len=max_response_len,
                         validate=validate)
    (sent_cell_list,
     sent_crypt_cells_bytes,
     sent_plain_cells_bytes) = circuit_write_cell_list(circuit_context,
                                        cell_list,
                                        force_link_version=force_link_version)
    response_cells_bytes = bytearray()
    if len(cell_list) > 0:
        response_cells_bytes = circuit_read_cell_bytes(circuit_context,
                                            max_response_len=max_response_len)
    if do_shutdown:
        sent_destroy_cell_bytes = circuit_close(circuit_context,
                                        force_link_version=force_link_version)
        sent_crypt_cells_bytes += sent_destroy_cell_bytes
        sent_plain_cells_bytes += sent_destroy_cell_bytes
        # we don't expect a response to a DESTROY
    return (link_context, circuit_context,
            sent_crypt_cells_bytes, sent_plain_cells_bytes,
            response_cells_bytes)

def circuit_request_cell(link_context,
                         relay_command_string,
                         cell_command_string='RELAY',
                         circ_id=None,
                         force_link_version=None,
                         force_payload_len=None,
                         stream_id=None,
                         relay_payload_bytes=None,
                         force_relay_payload_len=None,
                         force_recognized_bytes=None,
                         force_digest_bytes=None,
                         create_cell_command_string='CREATE_FAST',
                         max_response_len=MAX_READ_BUFFER_LEN,
                         validate=True,
                         do_shutdown=True):
    '''
    Send a Tor cell on a new circuit on link_context.
    See circuit_request_cell_list() for details.
    '''
    cell = circuit_make_relay_cell(cell_command_string,
                            relay_command_string,
                            circ_id=circ_id,
                            force_link_version=force_link_version,
                            force_payload_len=force_payload_len,
                            stream_id=stream_id,
                            relay_payload_bytes=relay_payload_bytes,
                            force_relay_payload_len=force_relay_payload_len,
                            force_recognized_bytes=force_recognized_bytes,
                            force_digest_bytes=force_digest_bytes)
    return circuit_request_cell_list(link_context,
                        [cell],
                        create_cell_command_string=create_cell_command_string,
                        circ_id=circ_id,
                        force_link_version=force_link_version,
                        max_response_len=max_response_len,
                        validate=validate,
                        do_shutdown=do_shutdown)

# TODO: open streams
# TODO: automatically allocate unused stream ids
