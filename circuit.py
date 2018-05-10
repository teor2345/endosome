# Endosome: a Tor cell construction kit
#
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

# Circuit-level functions

import stem.client.cell

from connect import *
from cell import *
from link import *

from stem.client.datatype import Size, split

def get_circuits(context):
    '''
    Return the circuits from context, which can be any kind of context.
    If context does not have circuits, return an empty dict.
    '''
    link_context = get_connect_context(context)
    return link_context.get('circuits', {})

def circuit_create(link_context):
    '''
    Create a single-hop circuit on the link in link_context.

    Returns a context dictionary required to continue using the circuit:
        'circ_id'            : the circuit id for this circuit
        'link'               : the link context for this circuit
    And response: (missing if there is no response)
        'Df_hash'            : the forward digest hash, seeded with Df_bytes
        'Db_hash'            : the backward digest hash, seeded with Db_bytes
        'Kf_crypt'           : the forward encryption context, key Kf_bytes
        'Kb_crypt'           : the backward decryption context, key Kb_bytes
    Also adds the following entries to the link context:
       'circuits'            : a dictionary containing the circuits on this
                               link, keyed by circuit id
       'circuits'/circ_id    : the circuit context for this circuit
    '''

    link_context = get_connect_context(link_context)
    circ = link_context['stem_relay'].create_circuit()

    circuit_context = {
      'circ_id'            : circ.id,
      'link'               : link_context,
      'Df_hash'            : circ.forward_digest,
      'Db_hash'            : circ.backward_digest,
      'Kf_crypt'           : circ.forward_key,
      'Kb_crypt'           : circ.backward_key,
      'circ'               : circ,
    }

    link_context.setdefault('circuits', {})
    link_context['circuits'][circ.id] = circuit_context

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

    # TODO: It works! Ish. Clearly has rough edges. This is cropping off the
    # top three bytes because we're supposed to encrypt everything except those
    # headers. We need to expand stem's pack() function to accept an encryption
    # key.

    payload_without_digest = stem.client.cell.RelayCell(
      context['circ'].id,
      cell['relay_command_string'],
      cell.get('relay_payload_bytes', ''),
      0,
      cell.get('stream_id'),
    ).pack(context['link']['link_version'])[3:]

    hop_hash_context.update(payload_without_digest)

    plain_payload_bytes = stem.client.cell.RelayCell(
      context['circ'].id,
      cell['relay_command_string'],
      cell.get('relay_payload_bytes', ''),
      Size.LONG.unpack(hop_hash_context.digest()[:RELAY_DIGEST_LEN]),
      cell.get('stream_id'),
    ).pack(context['link']['link_version'])

    plain_payload_bytes = plain_payload_bytes[3:]

    cell['payload_bytes'] = hop_crypt_context.update(plain_payload_bytes)
    return (cell, plain_payload_bytes)

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
    sent_cell_list = []
    plain_cells_bytes = bytearray()
    hop_hash_context, hop_crypt_context = context['circ'].forward_digest, context['circ'].forward_key

    for cell in cell_list:
        sent_cell = cell.copy()
        # If the cell doesn't have a circuit_id, use the one from the context
        sent_cell.setdefault('circ_id', context['circ'].id)
        (sent_cell, plain_cell_bytes) = circuit_crypt_cell_payload(context, sent_cell, hop_hash_context, hop_crypt_context)
        sent_cell_list.append(sent_cell)
        plain_cells_bytes += plain_cell_bytes
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
        circ_id = circuit_context['circ_id']
        sent_destroy_cell_bytes = stem.client.cell.DestroyCell(circ_id).pack(get_link_version(link_context))
        ssl_write(link_context, sent_destroy_cell_bytes)
        del link_context['circuits'][circ_id]

        sent_crypt_cells_bytes += sent_destroy_cell_bytes
        sent_plain_cells_bytes += sent_destroy_cell_bytes
        # we don't expect a response to a DESTROY
    return (link_context, circuit_context,
            sent_crypt_cells_bytes, sent_plain_cells_bytes,
            response_cells_bytes)

# TODO: open streams
# TODO: automatically allocate unused stream ids
