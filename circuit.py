# Endosome: a Tor cell construction kit
#
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

# Circuit-level functions

import stem.client.cell

from connect import *
from cell import *
from link import *

from stem.client import split

def get_circuit_context(context):
    '''
    Return the circuit context in context.
    '''
    # If it doesn't have a link, it's not a circuit context
    assert 'link' in context
    # TODO: extract circuit contexts from stream contexts
    return context

def get_circuit_or_link_context(context):
    '''
    Return a circuit or link context from context, preferring a circuit
    context if possible.
    '''
    # TODO: extract circuit contexts from stream contexts
    return context

def circuit_get_crypt_context(context,
                              is_cell_outbound_flag=None):
    '''
    Returns a tuple containing the hash and crypt contexts from context,
    based on is_cell_outbound_flag.
    '''
    assert is_cell_outbound_flag is not None
    context = get_circuit_context(context)
    if is_cell_outbound_flag:
        return (context['Df_hash'], context['Kf_crypt'])
    else:
        return (context['Db_hash'], context['Kb_crypt'])

def circuit_set_crypt_context(context,
                              hop_hash_context,
                              hop_crypt_context,
                              is_cell_outbound_flag=None):
    '''
    Sets the hash and crypt contexts in context, based on
    is_cell_outbound_flag.
    '''
    assert is_cell_outbound_flag is not None
    context = get_circuit_context(context)
    if is_cell_outbound_flag:
        context['Df_hash'] = hop_hash_context
        # Setting the crypt context is redundant, since the crypt context is
        # always modified in-place (it can't be copied).
        # But it's nice to show that we're modifying it along with the digest.
        context['Kf_crypt'] = hop_crypt_context
    else:
        context['Db_hash'] = hop_hash_context
        context['Kb_crypt'] = hop_crypt_context

def get_circuits(context):
    '''
    Return the circuits from context, which can be any kind of context.
    If context does not have circuits, return an empty dict.
    '''
    link_context = get_connect_context(context)
    return link_context.get('circuits', {})

def is_circ_id_used(context, circ_id):
    '''
    Returns True if circ_id is used in context, and False if it is not.
    '''
    link_context = get_connect_context(context)
    is_used = circ_id in get_circuits(link_context)
    if is_used:
        assert get_circuits(link_context)[circ_id]['link'] == link_context
    return is_used

def get_unused_circ_id(context, is_initiator_flag=True,
                       force_link_version=None):
    '''
    Returns the first valid, unused circ_id in context.
    '''
    link_context = get_connect_context(context)
    link_version = get_link_version(link_context, force_link_version)
    circ_id = get_min_valid_circ_id(link_version,
                                    is_initiator_flag=is_initiator_flag)
    # a randomised selection algorithm would be faster but more complex
    while is_circ_id_used(link_context, circ_id):
        circ_id += 1
        assert circ_id < get_max_valid_circ_id(link_version)
    return circ_id

def add_circuit_context(link_context, circuit_context):
    '''
    Add circuit_context to link_context.
    '''
    link_context = get_connect_context(link_context)
    circuit_context = get_circuit_context(circuit_context)
    # This creates a circular reference, which modern python GCs can handle
    circ_id = circuit_context['circ_id']
    assert not is_circ_id_used(link_context, circ_id)
    circuit_context['link'] = link_context
    link_context.setdefault('circuits', {})
    link_context['circuits'][circ_id] = circuit_context
    assert is_circ_id_used(link_context, circ_id)

def remove_circuit_context(link_context, circuit_context):
    '''
    Remove circuit_context from link_context.
    '''
    link_context = get_connect_context(link_context)
    circuit_context = get_circuit_context(circuit_context)
    # This breaks the circular dependency created by add_circuit_context()
    circ_id = circuit_context['circ_id']
    assert is_circ_id_used(link_context, circ_id)
    del link_context['circuits'][circ_id]
    # we can't delete this, because decryption relies on it
    #del circuit_context['link']
    assert not is_circ_id_used(link_context, circ_id)

# See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n997
KH_LEN = HASH_LEN
DF_LEN = HASH_LEN
DB_LEN = HASH_LEN
KF_LEN = KEY_LEN
KB_LEN = KEY_LEN
KDF_TOR_LEN = KH_LEN + DF_LEN + DB_LEN + KF_LEN + KB_LEN

def circuit_create(link_context):
    '''
    Create a single-hop circuit on the link in link_context.

    Returns a context dictionary required to continue using the circuit:
        'circ_id'            : the circuit id for this circuit
        'link'               : the link context for this circuit
    And the first hop request (TODO: put these in a different structure):
        'create_cell_bytes'  : the create cell sent to establish the circuit
    And response: (missing if there is no response)
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
        'created_cell_bytes' : the created cell received in response
    Also adds the following entries to the link context:
       'circuits'            : a dictionary containing the circuits on this
                               link, keyed by circuit id
       'circuits'/circ_id    : the circuit context for this circuit
    '''

    link_context = get_connect_context(link_context)
    # choose an unused circuit id, not just the lowest one
    circ_id = get_unused_circ_id(link_context, is_initiator_flag=True)

    # Relays drop create cells for circuit ids that are in use
    # If we don't do this check, we will hang when reading
    assert not is_circ_id_used(link_context, circ_id)

    create_cell_bytes = stem.client.cell.CreateFastCell.pack(get_link_version(link_context), circ_id)
    ssl_write(link_context, create_cell_bytes)

    (_, create_cell_list) = unpack_cells_link(link_context, create_cell_bytes)
    assert len(create_cell_list) == 1
    create_cell = create_cell_list[0]
    local_circ_id = create_cell['circ_id']
    X_bytes = create_cell['X_bytes']

    # Make sure we sent a cell, if not, we will hang when reading
    assert local_circ_id is not None

    # Read and parse the response
    # You will hang here if you send a duplicate circuit ID
    created_cell_bytes = link_read_cell_bytes(link_context)
    (_, cell_list) = unpack_cells_link(link_context, created_cell_bytes)
    # Now find the created cell
    created_fast_found = False
    for cell in cell_list:
        # Find the create cell, and add it to the circuit context
        cell_command_string = cell['cell_command_string']
        if cell_command_string.startswith('CREATED'):
            created_cell = cell
            remote_circ_id = created_cell['circ_id']
            assert remote_circ_id == local_circ_id
            # if our circuit requests get out of order, nothing will work
            assert local_circ_id == remote_circ_id
            if cell_command_string == 'CREATED_FAST':
                created_fast_found = True
                KH_bytes = created_cell['KH_bytes']
                Y_bytes = created_cell['Y_bytes']
                # K0=X|Y
                # See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1007
                K0_bytes = X_bytes + Y_bytes
                # Create the circuit material using a KDF
                temp_bytes = kdf_tor(K0_bytes, KDF_TOR_LEN)
                # Extract the circuit material
                (expected_KH_bytes, temp_bytes) = split(temp_bytes, KH_LEN)
                assert KH_bytes == expected_KH_bytes

                (Df_bytes, temp_bytes) = split(temp_bytes, DF_LEN)
                (Db_bytes, temp_bytes) = split(temp_bytes, DB_LEN)
                (Kf_bytes, temp_bytes) = split(temp_bytes, KF_LEN)
                (Kb_bytes, temp_bytes) = split(temp_bytes, KB_LEN)
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
        'circ_id'            : local_circ_id,
        'link'               : link_context,
        'create_cell_bytes'  : create_cell_bytes,
        }

    if created_fast_found:
        extra_context = {
            # hop
            # TODO: multi-hop circuits: next_hop_context and
            # previous_hop_context?
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
            'created_cell_bytes' : created_cell_bytes,
            }
        circuit_context.update(extra_context)
    else:
        print "Error: CREATED_FAST cell not received from remote OR"

    add_circuit_context(link_context, circuit_context)
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
    context = get_circuit_context(context)
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

def circuit_write_cell_list(context, cell_list):
    '''
    Pack, encrypt and send the Tor cells specified by cell_list on the circuit
    in context, using the link_version in context.
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
    context = get_circuit_context(context)
    sent_cell_list = []
    plain_cells_bytes = bytearray()
    # Assume we're a client
    (hop_hash_context,
     hop_crypt_context) = circuit_get_crypt_context(context,
                                                    is_cell_outbound_flag=True)
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
                                        hop_crypt_context)
        sent_cell_list.append(sent_cell)
        plain_cells_bytes += plain_cell_bytes
    # We already assumed we're the client
    circuit_set_crypt_context(context,
                              hop_hash_context,
                              hop_crypt_context,
                              is_cell_outbound_flag=True)
    crypt_cells_bytes = link_write_cell_list(context['link'], sent_cell_list)
    return (sent_cell_list, crypt_cells_bytes, plain_cells_bytes)

def circuit_read_cell_bytes(context):
    '''
    Reads bytes from the ssl_socket in circuit_context.
    Returns the cell bytes received.
    (Cell parsing functionality is in format_cell_bytes().)
    '''
    link_context = get_connect_context(context)
    return link_read_cell_bytes(link_context)

def circuit_close(context):
    '''
    Close the circuit in context using a DESTROY cell.
    Returns the result of link_write_cell_list().
    '''
    circuit_context = get_circuit_context(context)
    link_context = get_connect_context(context)
    destroy_circ_id = circuit_context['circ_id']

    cell_bytes = stem.client.cell.DestroyCell.pack(get_link_version(link_context), destroy_circ_id)
    ssl_write(link_context, cell_bytes)

    # Enable re-use of the circuit id
    remove_circuit_context(link_context, circuit_context)
    return cell_bytes

def circuit_request_cell_list(link_context,
                              cell_list,
                              do_shutdown=True):
    '''
    Send the Tor cells in cell_list on a newly created circuit on link_context,
    and read bytes of response cells.
    If do_shutdown is true, send a DESTROY cell to shut down the circuit.
    Returns a tuple containing the modified link context, the circuit context,
    the crypted sent cells bytes, the plaintext sent cells bytes, and the
    (crypted) response cell(s) bytes.
    '''
    link_context = get_connect_context(link_context)
    circuit_context = circuit_create(link_context)
    (sent_cell_list,
     sent_crypt_cells_bytes,
     sent_plain_cells_bytes) = circuit_write_cell_list(circuit_context, cell_list)
    response_cells_bytes = bytearray()
    if len(cell_list) > 0:
        response_cells_bytes = circuit_read_cell_bytes(circuit_context)
    if do_shutdown:
        sent_destroy_cell_bytes = circuit_close(circuit_context)
        sent_crypt_cells_bytes += sent_destroy_cell_bytes
        sent_plain_cells_bytes += sent_destroy_cell_bytes
        # we don't expect a response to a DESTROY
    return (link_context, circuit_context,
            sent_crypt_cells_bytes, sent_plain_cells_bytes,
            response_cells_bytes)

# TODO: open streams
# TODO: automatically allocate unused stream ids
