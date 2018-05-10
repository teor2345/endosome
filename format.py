# Endosome: a Tor cell construction kit
#
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

# Formatting functions

from connect import *
from cell import *
from link import *
from circuit import *

def format_cells(data_bytes, link_version_list=[3,4,5],
                 force_link_version=None,
                 hop_hash_context=None, hop_crypt_context=None,
                 validate=True,
                 skip_cell_bytes=True, skip_zero_padding=True):
    '''
    Unpack and format the cells in data_bytes using unpack_cells() with
    force_link_version and the contexts.
    Returns a string formatted according to the arguments.
    You must pass the same link_version_list when packing the request and
    unpacking the response.
    Updates hop_hash_context and hop_crypt_context in-place.
    Relay digests are validated if validate is True.
    '''
    (link_version, cell_list) = unpack_cells(data_bytes, link_version_list,
                                        force_link_version=force_link_version,
                                        hop_hash_context=hop_hash_context,
                                        hop_crypt_context=hop_crypt_context,
                                        validate=validate)
    result  = 'Link Version: {}\n'.format(link_version)
    result += '{} Cell(s):\n'.format(len(cell_list))
    for cell in cell_list:
        result += '\n'
        is_var_cell_flag = cell['is_var_cell_flag']
        for key in sorted(cell.keys()):
            if skip_cell_bytes and key == 'cell_bytes':
                continue
            if key.endswith('bytes'):
                # add these extra fields when formatting so that they are
                # added for every bytes field (and so we don't duplicate data)
                data_bytes = cell[key]
                if key.endswith('payload_bytes') and not is_var_cell_flag:
                    # Just assume any zeroes at the end are padding
                    data_bytes = data_bytes.rstrip('\0')
                output_bytes = data_bytes if skip_zero_padding else cell[key]
                result += '{} : "{}"\n'.format(key, output_bytes)
                result += '{}_hex : {}\n'.format(key,
                                             binascii.hexlify(output_bytes))
                if (not is_var_cell_flag and (key == 'cell_bytes' or
                                              key == 'payload_bytes')):
                    zero_pad_len = len(cell[key]) - len(data_bytes)
                    result += '{}_{} : {}\n'.format(key, 'zero_pad_len',
                                                    zero_pad_len)
            else:
                result += '{} : {}\n'.format(key, cell[key])
    return result

def format_cell_bytes(context, cell_bytes,
                      initial_cells=False,
                      force_link_version=None,
                      is_cell_outbound_flag=None,
                      validate=True,
                      skip_cell_bytes=True, skip_zero_padding=True):
    '''
    Unpack and format the cells in cell_bytes using format_cells(), supplying
    the relevant arguments from context.
    If initial_cells is True, automatically determines the link version from
    the initial VERSIONS cell.
    Relay cells require a circuit context.
    If the is_cell_outbound_flag is not None, the cell is decrypted.
    And if validate is True, relay digests are validated.
    Returns a string formatted according to the arguments.
    '''
    link_version = None
    if not initial_cells:
        link_version = get_link_version(context, force_link_version)
    link_version_list = get_link_version_list(context,
                                        force_link_version=force_link_version)
    if is_cell_outbound_flag is not None:
        if is_cell_outbound_flag:
            hop_hash_context, hop_crypt_context = context['circ'].forward_digest, context['circ'].forward_key
        else:
            hop_hash_context, hop_crypt_context = context['circ'].backward_digest, context['circ'].backward_key
    else:
        hop_hash_context = None
        hop_crypt_context = None
    return format_cells(cell_bytes,
                        # we must use force_link_version, because only the
                        # caller knows when we are parsing a VERSIONS cell
                        link_version_list=link_version_list,
                        force_link_version=link_version,
                        hop_hash_context=hop_hash_context,
                        hop_crypt_context=hop_crypt_context,
                        validate=validate,
                        skip_cell_bytes=skip_cell_bytes,
                        skip_zero_padding=skip_zero_padding)

# This function is located in circuit.py to resolve a circular dependency
def format_context(context,
                   link_version=None,
                   skip_cell_bytes=True, skip_zero_padding=True,
                   skip_cells=False, skip_circuits=False,
                   skip_link=False):
    '''
    Format context, using format_cell_bytes() to format the cells in
    context.
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

def link_format_context(context,
                        force_link_version=None,
                        skip_cell_bytes=True, skip_zero_padding=True,
                        skip_cells=False, skip_circuits=False,
                        skip_link=False):
    '''
    Formats a link context using format_context().
    Returns a string formatted according to the arguments.
    '''
    context = get_connect_context(context)
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
    Formats a circuit context using format_context().
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
