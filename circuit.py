# Endosome: a Tor cell construction kit
#
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

from connect import *
from cell import *
from link import *

# Circuit-level functions

# This function is located in circuit.py to resolve a circular dependency
def format_context(context,
                   link_version=None,
                   skip_cell_bytes=True, skip_zero_padding=True,
                   skip_cells=False, skip_circuits=False,
                   skip_link=False):
    '''
    Format context, using format_cell_bytes() to format the cells in
    context. Supports link and circuit contexts.
    Returns a string formatted according to the arguments.
    '''
    result = ''
    for key in sorted(context.keys()):
        if key.endswith('cell_bytes'):
            if skip_cells:
                continue
            # we know the link version, unless it's the initial versions
            # cell on either side
            initial_cells = key.startswith('open')
            result += '\n{} cells:\n'.format(key)
            result += format_cell_bytes(context, context[key],
                                   initial_cells=initial_cells,
                                   force_link_version=link_version,
                                   skip_cell_bytes=skip_cell_bytes,
                                   skip_zero_padding=skip_zero_padding)
        elif key.endswith('bytes'):
            result += '{} : {}\n'.format(key, binascii.hexlify(context[key]))
        elif key == 'circuits':
            if skip_circuits:
                continue
            for circ_id in context[key]:
                result += circuit_format_context(context[key][circ_id],
                                          force_link_version=link_version,
                                          skip_cell_bytes=skip_cell_bytes,
                                          skip_zero_padding=skip_zero_padding,
                                          # don't repeat details
                                          skip_cells=True,
                                          # don't recurse endlessly
                                          skip_circuits=True,
                                          skip_link=True)
                result += '\n'
        elif key == 'link':
            if skip_link:
                continue
            result += link_format_context(context[key],
                                          force_link_version=link_version,
                                          skip_cell_bytes=skip_cell_bytes,
                                          skip_zero_padding=skip_zero_padding,
                                          # don't repeat details
                                          skip_cells=True,
                                          # don't recurse endlessly
                                          skip_circuits=True,
                                          skip_link=True)
        else:
            result += '{} : {}\n'.format(key, context[key])
    return result

# This function is located in circuit.py to resolve a circular dependency
def link_format_context(context,
                        force_link_version=None,
                        skip_cell_bytes=True, skip_zero_padding=True,
                        skip_cells=False, skip_circuits=False,
                        skip_link=False):
    '''
    Format context, using format_context() to format the cells in
    context.
    Returns a string formatted according to the arguments.
    '''
    link_version = get_link_version(context, force_link_version)
    return format_context(context,
                          link_version=link_version,
                          skip_cell_bytes=skip_cell_bytes,
                          skip_zero_padding=skip_zero_padding,
                          skip_cells=skip_cells,
                          skip_circuits=skip_circuits,
                          # Don't recurse endlessly
                          skip_link=True)

def circuit_format_context(context,
                           force_link_version=None,
                           skip_cell_bytes=True, skip_zero_padding=True,
                           skip_cells=False, skip_circuits=False,
                           skip_link=False):
    '''
    Format context, using format_context() to format the cells in
    context.
    Returns a string formatted according to the arguments.
    '''
    link_version = get_link_version(context, force_link_version)
    return format_context(context,
                          link_version=link_version,
                          skip_cell_bytes=skip_cell_bytes,
                          skip_zero_padding=skip_zero_padding,
                          skip_cells=skip_cells,
                          # Don't recurse endlessly
                          skip_circuits=True,
                          skip_link=skip_link)

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

def circuit_create(link_context,
                   create_cell_command_string='CREATE_FAST',
                   circ_id=None,
                   force_link_version=None,
                   max_response_len=MAX_READ_BUFFER_LEN):
    '''
    Create a circuit using create_cell_command_string with circ_id,
    on the link in link_context.
    force_link_version overrides the link version in context.

    If circ_id is None, use an unused, valid circuit ID for the link version.

    Read up to max_response_len in response, and returns a context dictionary
    required to continue using the circuit:
        'circ_id'            : the circuit id for this circuit
        'K0_bytes'           : the shared key for the circuit
        'KH_bytes'           : a hash that shows the remote side knows K0
        'create_cell_bytes'  : the create cell sent to establish the circuit
        'created_cell_bytes' : the created cell received in response
        'link'               : the link context for this circuit
    Also adds the following entries to the link context:
       'circuits'            : a dictionary containing the circuits on this
                               link, keyed by circuit id
       'circuits'/circ_id    : the circuit context for this circuit
    '''
    create_cell_bytes = None
    X_bytes = None
    local_circ_id = None
    # choose an unused circuit id, not just the lowest one
    if circ_id is None:
        circ_id = get_unused_circ_id(link_context, is_initiator_flag=True,
                                     force_link_version=force_link_version)
    # Send the circuit request
    if create_cell_command_string == 'CREATE_FAST':
        # Relays drop create cells for circuit ids that are in use
        assert not is_circ_id_used(link_context, circ_id)
        create_cell_bytes = link_write_cell(link_context,
                                       create_cell_command_string,
                                       circ_id=circ_id,
                                       payload=pack_create_fast_payload(),
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
    # Make sure we sent a cell
    assert local_circ_id is not None

    # Read and parse the response
    # You will hang here if you send a duplicate circuit ID
    created_cell_bytes = link_read_cell_bytes(link_context,
                                         force_link_version=force_link_version,
                                         max_response_len=max_response_len)
    (_, cell_list) = unpack_cells_link(link_context, created_cell_bytes,
                                       force_link_version=force_link_version)
    # Now find the created cell
    remote_circ_id = None
    KH_bytes = None
    K0_bytes = None
    for cell in cell_list:
        # Find the create cell, and add it to the circuit context
        cell_command_string = cell['cell_command_string']
        if cell_command_string.startswith('CREATED'):
            created_cell = cell
            remote_circ_id = created_cell['circ_id']
            assert local_circ_id == remote_circ_id
            if cell_command_string == 'CREATED_FAST':
                KH_bytes = created_cell['KH_bytes']
                Y_bytes = created_cell['Y_bytes']
                # K0=X|Y
                # See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1007
                K0_bytes = X_bytes + Y_bytes
            else:
                # TODO: TAP & ntor handshakes, which need onion keys from
                # descriptors
                raise ValueError("{} not yet implemented"
                                 .format(cell_command_string))
            break

    # Make sure we have the fields we need to continue using the circuit
    assert remote_circ_id is not None
    assert K0_bytes is not None
    assert KH_bytes is not None

    # Create the circuit context
    circuit_context = {
        'circ_id'            : remote_circ_id,
        'K0_bytes'           : K0_bytes,
        'KH_bytes'           : KH_bytes,
        'create_cell_bytes'  : create_cell_bytes,
        'created_cell_bytes' : created_cell_bytes,
        'link'               : link_context,
        }

    # Update the link context with the circuit context
    link_context.setdefault('circuits', {})
    # This creates a circular reference, which modern python GCs can handle
    link_context['circuits'][remote_circ_id] = circuit_context
    return circuit_context
