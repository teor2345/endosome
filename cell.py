# Endosome: a Tor cell construction kit
#
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

import binascii
# ipaddress backport available for python 2.6, 2.7, 3.2
import ipaddress
import os
import time

from pack import *
from connect import *
from crypto import *

# Cells and cell fields

# Link version constants
# https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n538

LINK_VERSION_DESC = {
  None : 'negotiating link version',
     1 : 'certs up front',
     2 : 'renegotiation',
     3 : 'in-protocol',
     4 : 'circuit ID 4 bytes',
     5 : 'link padding and negotiation',
}

# The link version we use at the start of a connection
INITIAL_LINK_VERSION = 3

# Cell command field constants
# https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n419

# This table should be kept in sync with CELL_UNPACK
CELL_COMMAND = {
    # Fixed-length Cells
    'PADDING'           :   0, # (Padding)                  (See Sec 7.2)
    'CREATE'            :   1, # (Create a circuit)         (See Sec 5.1)
    'CREATED'           :   2, # (Acknowledge create)       (See Sec 5.1)
    'RELAY'             :   3, # (End-to-end data)          (See Sec 5.5 and 6)
    'DESTROY'           :   4, # (Stop using a circuit)     (See Sec 5.4)
    'CREATE_FAST'       :   5, # (Create a circuit, no PK)  (See Sec 5.1)
    'CREATED_FAST'      :   6, # (Circuit created, no PK)   (See Sec 5.1)

    'NETINFO'           :   8, # (Time and address info)    (See Sec 4.5)
    'RELAY_EARLY'       :   9, # (End-to-end data; limited) (See Sec 5.6)
    'CREATE2'           :  10, # (Extended CREATE cell)     (See Sec 5.1)
    'CREATED2'          :  11, # (Extended CREATED cell)    (See Sec 5.1)
    'PADDING_NEGOTIATE' :  12, # (Padding negotiation)      (See Sec 7.2)

    # Variable-length cells
    'VERSIONS'          :   7, # (Negotiate proto version)  (See Sec 4)

    'VPADDING'          : 128, # (Variable-length padding)  (See Sec 7.2)
    'CERTS'             : 129, # (Certificates)             (See Sec 4.2)
    'AUTH_CHALLENGE'    : 130, # (Challenge value)          (See Sec 4.3)
    'AUTHENTICATE'      : 131, # (Client authentication)    (See Sec 4.5)
    'AUTHORIZE'         : 132, # (Client authorization)     (Not yet used)
}

def get_link_version_string(link_version):
    '''
    Get a description of link_version.
    Returns a descriptive string if link_version is not a known link
    version value.
    '''
    return LINK_VERSION_DESC.get(link_version,
                                 'UNKNOWN_LINK_VERSION_{}'
                                 .format(link_version))

def get_cell_command_value(cell_command_string):
    '''
    Returns the cell command value for cell_command_string.
    Asserts if cell_command_string is not a known cell command string.
    '''
    return CELL_COMMAND[cell_command_string]

def get_cell_command_string(cell_command_value):
    '''
    Returns the cell command string for cell_command_value.
    Returns a descriptive string if cell_command_value is not a known cell
    command value.
    '''
    for cell_command_string in CELL_COMMAND:
        if cell_command_value == get_cell_command_value(cell_command_string):
            return cell_command_string
    return 'UNKNOWN_CELL_COMMAND_{}'.format(cell_command_value)

def get_payload_unpack_function(cell_command_value):
    '''
    Returns the cell unpack function for cell_command_value.
    This function takes two arguments, payload_len and payload_bytes, and
    returns a dictionary containing the destructured payload contents.
    Returns unpack_unknown_payload if cell_command_value is not a known cell
    command value, and unpack_not_implemented_payload if it is known, but
    there is no unpack implementation.
    '''
    for cell_command_string in CELL_COMMAND:
        if cell_command_value == get_cell_command_value(cell_command_string):
            return CELL_UNPACK.get(cell_command_string,
                                   unpack_not_implemented_payload)
    return unpack_unknown_payload

MIN_VAR_COMMAND_VALUE = 128

def is_cell_command_variable_length(cell_command_value):
    '''
    Returns True if cell_command_value uses a variable-length cell,
    and False otherwise.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n412
    '''
    if (cell_command_value == get_cell_command_value('VERSIONS') or
        cell_command_value >= MIN_VAR_COMMAND_VALUE):
        return True
    return False

def is_cell_command_circuit(cell_command_value):
    '''
    Returns True if cell_command_value is a circuit command,
    and False otherwise.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n455
    '''
    cell_command_string = get_cell_command_string(cell_command_value)
    if (cell_command_string.startswith('CREATE') or
        cell_command_string.startswith('RELAY') or
        cell_command_string.startswith('DESTROY')):
        return True
    return False

# Security parameters
# See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n46
#     https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n101

KEY_LEN = 16
PK_ENC_LEN = 128
PK_PAD_LEN = 42
DH_LEN = 128
DH_SEC_LEN = 40
HASH_LEN = 20
MAX_FIXED_PAYLOAD_LEN = 509

# Cell Format
# See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n387
CELL_COMMAND_LEN = 1
PAYLOAD_LENGTH_LEN = 2

def get_cell_fixed_length(link_version):
    '''
    Get the fixed-length cell length for link_version.
    Fixed-length cells aren't sent on a link until the link version has been
    negotiated.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n66
    '''
    # if link_version is None, you probably want a circ_id_len of 2
    # See https://trac.torproject.org/projects/tor/ticket/22929
    if link_version is None:
        return get_cell_fixed_length(INITIAL_LINK_VERSION)
    assert link_version > 0
    if link_version < 4:
        return 512
    else:
        return 514

def get_cell_min_var_length(link_version, cell_command_value=None):
    '''
    Get the minimum variable-length cell length for link_version and
    cell_command_value. If cell_command_value is None, returns the minimum
    length for a VERSIONS cell. Doesn't account for cell payloads.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n399
    '''
    return (get_cell_circ_id_len(link_version) +
            CELL_COMMAND_LEN + PAYLOAD_LENGTH_LEN)

def get_cell_circ_id_len(link_version):
    '''
    Get the circuit id length for link_version and cell_command_value
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n412
    '''
    # a versions cell always has a 2-byte circuit id, because it has
    # a link_version of None, unless force_link_version is used
    # See https://trac.torproject.org/projects/tor/ticket/22931
    #
    # early in the handshake, assume that all cells have 2-byte circ_ids
    # See https://trac.torproject.org/projects/tor/ticket/22929
    if link_version is None:
        return get_cell_circ_id_len(INITIAL_LINK_VERSION)
    # don't check LINK_VERSION_DESC, that would assert on new link versions
    assert link_version > 0
    if link_version >= 1 and link_version <= 3:
        return 2
    return 4

def get_min_valid_circ_id(link_version, is_initiator_flag=True):
    '''
    Get the minimum valid circuit id for link_version, based on
    is_initiator_flag.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n768
        https://trac.torproject.org/projects/tor/ticket/22882
    '''
    if link_version is None:
        return get_min_valid_circ_id(INITIAL_LINK_VERSION,
                                     is_initiator_flag=is_initiator_flag)
    assert link_version > 0
    if link_version >= 4 and is_initiator_flag:
        # v4 initiators must set the most significant bit
        return 0x80000000
    else:
        # otherwise, any non-zero circuit id is ok
        return 0x01

def get_max_valid_circ_id(link_version):
    '''
    Get the maximum valid circuit id for link_version.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n768
    '''
    return get_pack_max(get_cell_circ_id_len(link_version))

def pack_cell_header(cell_command_string, link_version=None, circ_id=None,
                     payload_len=None):
    '''
    Pack a cell header for link_version, on circuit circ_id,
    with command cell_command_string and payload_len.
    link_version can be None for VERSIONS cells.
    circ_id can be None, if it is, a valid circ_id is chosen:
        * 0 for link-level cells, or
        * get_min_valid_circ_id(link_version) for circuit-level cells.
      If you want to build more than one circuit on a connection, you'll have
      to supply unique circuit IDs yourself.
    payload_len can be None or 0 when allowed by the cell command.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n387
    '''
    cell_command_value = get_cell_command_value(cell_command_string)
    # Work out how long everything is
    circ_id_len = get_cell_circ_id_len(link_version)
    is_var_cell_flag = is_cell_command_variable_length(cell_command_value)

    # Now pack it all in
    if circ_id is None:
        if is_cell_command_circuit(cell_command_value):
            circ_id = get_min_valid_circ_id(link_version)
        else:
            circ_id = 0
    cell_header = pack_value(circ_id_len, circ_id)

    # byte order is irrelevant in this case
    cell_header += pack_value(CELL_COMMAND_LEN, cell_command_value)

    if is_var_cell_flag:
        cell_header += pack_value(PAYLOAD_LENGTH_LEN, payload_len)

    return cell_header

def unpack_cell_header(data_bytes, link_version=None):
    '''
    Unpack a cell header out of data_bytes for link_version.
    link_version can be None before versions cells have been exchanged.
    Returns a tuple containing a dict with the destructured cell contents,
    and the remainder of byte string (the cell payload).
    The returned dict contains the following string keys:
        'link_version'        : an integer link version
        'link_version_string' : a descriptive string for the link version
        'is_var_cell_flag'    : is the cell a variable-length cell?
        'cell_len'            : the length of the cell
        'cell_bytes'          : the bytes that make up the cell
        'circ_id_len'         : the length of the circuit id field
        'circ_id'             : the circuit id
        'cell_command_value'  : an integer cell command number
        'cell_command_string' : a string representing the cell command
        'payload_len'         : the length of the payload
        'payload_bytes'       : the bytes in the payload
        'is_payload_zero_bytes_flag' : is the payload all zero bytes?
                                       (can indicate misinterpreted padding)
    Asserts if data_bytes is not long enough for the cell's length.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n387
        https://trac.torproject.org/projects/tor/ticket/22929
    '''
    # Work out how long everything is
    circ_id_len = get_cell_circ_id_len(link_version)
    temp_bytes = data_bytes
    (circ_id, temp_bytes) = unpack_value(circ_id_len, temp_bytes)
    (cell_command_value, temp_bytes) = unpack_value(CELL_COMMAND_LEN,
                                                    temp_bytes)
    is_var_cell_flag = is_cell_command_variable_length(cell_command_value)
    if is_var_cell_flag:
        (payload_len, temp_bytes) = unpack_value(PAYLOAD_LENGTH_LEN,
                                                 temp_bytes)
        cell_len = (circ_id_len + CELL_COMMAND_LEN + PAYLOAD_LENGTH_LEN +
                    payload_len)
    else:
        cell_len = get_cell_fixed_length(link_version)
        payload_len = MAX_FIXED_PAYLOAD_LEN
    # Print out a diagnostic if we're about to assert
    # You might need to enable this for every cell to work out what's wrong
    if len(data_bytes) < cell_len or len(temp_bytes) < payload_len: # or True:
        print 'Cell Parsing Details:'
        print 'Link Version: {} CircID Length: {}'.format(link_version,
                                                          circ_id_len)
        print 'Cell Length: Expected: {} Actual: {}'.format(cell_len,
                                                            len(data_bytes))
        print 'Payload Length: Expected: {} Actual: {}'.format(payload_len,
                                                               len(temp_bytes))
        print 'Data Bytes:\n{}'.format(binascii.hexlify(data_bytes))
    # check the received data is long enough
    # if you parse a cell using the wrong link version, you will probably
    # trigger an assertion here
    (cell_bytes, remaining_bytes) = split_field(cell_len, data_bytes)
    (payload_bytes, payload_remaining_bytes) = split_field(payload_len,
                                                           temp_bytes)
    assert remaining_bytes == payload_remaining_bytes
    is_payload_zero_bytes_flag = (payload_bytes == get_zero_pad(payload_len))
    cell = {
        'link_version'        : link_version,
        'link_version_string' : get_link_version_string(link_version),
        'is_var_cell_flag'    : is_var_cell_flag,
        'cell_len'            : cell_len,
        'cell_bytes'          : cell_bytes,
        'circ_id_len'         : circ_id_len,
        'circ_id'             : circ_id,
        'cell_command_value'  : cell_command_value,
        'cell_command_string' : get_cell_command_string(cell_command_value),
        'payload_len'         : payload_len,
        'payload_bytes'       : payload_bytes,
        'is_payload_zero_bytes_flag' : is_payload_zero_bytes_flag,
        }
    return (cell, remaining_bytes)

def pack_cell(cell_command_string, link_version=None, circ_id=None,
              payload_bytes=None, force_payload_len=None):
    '''
    Pack a cell with a cell header and payload_bytes.
    payload_bytes can be None when allowed by the cell command.
    If force_payload_len is not None, it is used instead of len(payload_bytes)
    in the cell header.
    See pack_cell_header() for other arfument details.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n387
    '''
    # Find the values
    cell_command_value = get_cell_command_value(cell_command_string)
    circ_id_len = get_cell_circ_id_len(link_version)
    payload_len = 0 if payload_bytes is None else len(payload_bytes)
    is_var_cell_flag = is_cell_command_variable_length(cell_command_value)
    if is_var_cell_flag:
        cell_len = (circ_id_len + CELL_COMMAND_LEN + PAYLOAD_LENGTH_LEN +
                    payload_len)
    else:
        data_len = circ_id_len + CELL_COMMAND_LEN + payload_len
        cell_len = get_cell_fixed_length(link_version)
        zero_pad_len = cell_len - data_len
        assert payload_len <= MAX_FIXED_PAYLOAD_LEN

    # Pack the bytes
    if force_payload_len is None:
        force_payload_len = payload_len
    cell = pack_cell_header(cell_command_string, link_version=link_version,
                            circ_id=circ_id, payload_len=force_payload_len)

    if payload_bytes is not None:
        cell += payload_bytes

    # pad fixed-length cells to their length
    if not is_var_cell_flag:
        assert len(cell) == data_len
        cell += get_zero_pad(zero_pad_len)

    assert len(cell) == cell_len
    return cell

def unpack_unused_payload(payload_len, payload_bytes):
    '''
    Unpack an unused payload.
    Returns a dictonary containing a placeholder key:
        'is_payload_unused_flag' : always True
    Asserts if payload_bytes is not exactly payload_len bytes long.
    '''
    assert len(payload_bytes) == payload_len
    return {
        'is_payload_unused_flag' : True,
        }

def unpack_unknown_payload(payload_len, payload_bytes):
    '''
    Unpack a payload for an unknown cell command.
    Returns a dictonary containing a placeholder key:
        'is_payload_unknown_flag' : always True
    Asserts if payload_bytes is not exactly payload_len bytes long.
    '''
    assert len(payload_bytes) == payload_len
    return {
        'is_payload_unknown_flag' : True,
        }

def unpack_not_implemented_payload(payload_len, payload_bytes):
    '''
    Unpack a payload for a command that has no unpack implementation.
    Returns a dictonary containing a placeholder key:
        'is_payload_unpack_implemented_flag' : always False
    Asserts if payload_bytes is not exactly payload_len bytes long.
    '''
    assert len(payload_bytes) == payload_len
    return {
        'is_payload_unpack_implemented_flag' : False,
        }

VERSION_LEN = 2

def pack_versions_payload(link_version_list=[3,4,5]):
    '''
    Pack a versions payload with link_version_list.
    We use versions 3-5 to match ssl_request(), which initiates a version
    3 or later connection.
    You must pass the same link_version_list when packing the request and
    unpacking the response.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n503
    '''
    packed_version_list = []
    for version in link_version_list:
        packed_version_list.append(pack_value(VERSION_LEN, version))
    return bytearray().join(packed_version_list)

def pack_versions_cell(link_version_list=[3,4,5],
                       force_link_version=None, force_payload_len=None):
    '''
    Pack a versions cell with link_version_list.
    If force_link_version is not None, use that circ_id_len.
    We use versions 3-5 to match ssl_request(), which initiates a version
    3 or later connection.
    You must pass the same link_version_list when packing the request and
    unpacking the response.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n503
    '''
    return pack_cell('VERSIONS',
                     payload_bytes=pack_versions_payload(link_version_list),
                     link_version=force_link_version,
                     force_payload_len=force_payload_len)

def unpack_versions_payload(payload_len, payload_bytes):
    '''
    Unpack a versions cell payload from payload_bytes.
    Returns a dict containing a single key:
        'link_version_list' : a list of supported integer link versions
    Asserts if payload_bytes is not exactly payload_len bytes long.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n503
    '''
    assert len(payload_bytes) == payload_len
    unpacked_version_list = []
    temp_bytes = payload_bytes
    while len(temp_bytes) >= VERSION_LEN:
        (version, temp_bytes) = unpack_value(VERSION_LEN, temp_bytes)
        unpacked_version_list.append(version)
    return {
        'link_version_list' : unpacked_version_list,
        }

def get_highest_common_version(remote_link_version_list,
                               link_version_list=[3,4,5]):
    '''
    Returns the highest common version in remote_link_version_list and
    link_version_list.
    If there is no common version, returns None.
    You must pass the same link_version_list when packing the request and
    unpacking the response.
    '''
    remote_set = set(remote_link_version_list)
    local_set = set(link_version_list)
    common_set = remote_set.intersection(local_set)
    if len(common_set) == 0:
        return None
    return max(common_set)

# TODO:
# pack_certs_cell
# pack_certs_payload
# unpack_certs_payload (and verify certs)
# pack_auth_challenge_cell
# pack_auth_challenge_payload
# unpack_auth_challenge_payload

def pack_padding_payload():
    '''
    Pack a fixed-length padding cell's payload with random bytes.
    (Tor uses zero bytes, which isn't what the spec says.)
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n419
        https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1534
        https://trac.torproject.org/projects/tor/ticket/22948
    '''
    return get_random_bytes(MAX_FIXED_PAYLOAD_LEN)

def pack_padding_cell(link_version=None, force_payload_len=None):
    '''
    Pack a fixed-length padding cell with random bytes, using link_version.
    '''
    return pack_cell('PADDING',
                     payload_bytes=pack_padding_payload(),
                     link_version=link_version,
                     force_payload_len=force_payload_len)

def pack_vpadding_payload(payload_len):
    '''
    Pack a variable-length padding cell's payload with payload_len random
    bytes.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n419
        https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1534
    '''
    return get_random_bytes(payload_len)

def pack_vpadding_cell(payload_len, link_version=None, force_payload_len=None):
    '''
    Pack a variable-length padding cell with payload_len random bytes,
    using link_version.
    '''
    return pack_cell('VPADDING',
                     payload_bytes=pack_vpadding_payload(payload_len),
                     link_version=link_version,
                     force_payload_len=force_payload_len)

RESOLVE_TYPE_LEN = 1
RESOLVE_VALUE_LENGTH_LEN = 1
RESOLVE_TTL_LEN = 4
RESOLVE_ERROR_VALUE_LEN = 0

# See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1480
HOST_ADDRESS_TYPE            = 0x00
IPV4_ADDRESS_TYPE            = 0x04
IPV6_ADDRESS_TYPE            = 0x06
TRANSIENT_ERROR_ADDRESS_TYPE = 0xF0
PERMANENT_ERROR_ADDRESS_TYPE = 0xF1

IPV4_ADDRESS_LEN =  4
IPV6_ADDRESS_LEN = 16

MIN_RESOLVE_HEADER_LEN = RESOLVE_TYPE_LEN + RESOLVE_VALUE_LENGTH_LEN
MIN_ADDRESS_LEN = MIN_RESOLVE_HEADER_LEN + IPV4_ADDRESS_LEN
MIN_RESOLVE_LEN = MIN_RESOLVE_HEADER_LEN + RESOLVE_TTL_LEN

def pack_resolve_error(error_type):
    '''
    Returns a packed address error_type value.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1480
        https://trac.torproject.org/projects/tor/ticket/22937
    '''
    result  = pack_value(RESOLVE_TYPE_LEN, error_type)
    result += pack_value(RESOLVE_VALUE_LENGTH_LEN, RESOLVE_ERROR_VALUE_LEN)

# TODO: unpack_resolve_error

def pack_address(address):
    '''
    Returns a packed address.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1480
        https://trac.torproject.org/projects/tor/ticket/22937
    '''
    try:
        addr_value = ipaddress.ip_address(unicode(address))
        addr_type = addr_value.version
        if addr_type == IPV4_ADDRESS_TYPE:
            addr_len = IPV4_ADDRESS_LEN
            addr_bytes = ipaddress.v4_int_to_packed(int(addr_value))
        else:
            addr_len = IPV6_ADDRESS_LEN
            addr_bytes = ipaddress.v6_int_to_packed(int(addr_value))
    except ValueError:
        # must be a hostname
        addr_bytes = address
        addr_type = HOST_ADDRESS_TYPE
        addr_len = len(address)

    result  = pack_value(RESOLVE_TYPE_LEN, addr_type)
    result += pack_value(RESOLVE_VALUE_LENGTH_LEN, addr_len)
    assert len(addr_bytes) == addr_len
    result += addr_bytes
    return result

def get_addr_type_len(addr_type):
    '''
    Return the packed byte length of addr_type, which must be either
    IPV4_ADDRESS_TYPE or IPV4_ADDRESS_TYPE.
    '''
    if addr_type == IPV4_ADDRESS_TYPE:
        return IPV4_ADDRESS_LEN
    elif addr_type == IPV6_ADDRESS_TYPE:
        return IPV6_ADDRESS_LEN
    else:
        raise ValueError('Unexpected address type: {}'.format(addr_type))

def unpack_ip_address_bytes(data_bytes, addr_type):
    '''
    Return a tuple containing the unpacked addr_type IP address string, and the
    remainder of data_bytes.
    addr_type must be either IPV4_ADDRESS_TYPE or IPV6_ADDRESS_TYPE.
    data_bytes must be at least IPV4_ADDRESS_LEN or IPV6_ADDRESS_LEN long.
    '''
    addr_len = get_addr_type_len(addr_type)
    assert len(data_bytes) >= addr_len
    if addr_type == IPV4_ADDRESS_TYPE:
        assert addr_len == IPV4_ADDRESS_LEN
        (addr_bytes, remaining_bytes) = split_field(addr_len, data_bytes)
        addr_value = ipaddress.IPv4Address(bytearray(addr_bytes))
    elif addr_type == IPV6_ADDRESS_TYPE:
        assert addr_len == IPV6_ADDRESS_LEN
        (addr_bytes, remaining_bytes) = split_field(addr_len, data_bytes)
        addr_value = ipaddress.IPv6Address(bytearray(addr_bytes))
    else:
        raise ValueError('Unexpected address type: {}'.format(addr_type))
    return (str(addr_value), remaining_bytes)

def unpack_address(data_bytes):
    '''
    Return a tuple containing the unpacked IP address string in data_bytes,
    and the remainder of data_bytes.
    Asserts if data_bytes is shorter than MIN_ADDRESS_LEN.
    '''
    assert len(data_bytes) >= MIN_ADDRESS_LEN
    temp_bytes = data_bytes
    (addr_type, temp_bytes) = unpack_value(RESOLVE_TYPE_LEN, temp_bytes)
    (addr_len, temp_bytes) = unpack_value(RESOLVE_VALUE_LENGTH_LEN, temp_bytes)
    assert len(data_bytes) >= addr_len
    assert addr_len == get_addr_type_len(addr_type)
    return unpack_ip_address_bytes(temp_bytes, addr_type)

def pack_resolve(address=None, error_type=None, ttl=None):
    '''
    Returns a packed address and ttl, or an error_type value and TTL.
    If ttl is None, the TTL field is left out of the result.
    Exactly one of address and error_type must be None.
    Raises a ValueError if this condition is not satisfied.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1480
    '''
    # Find the type
    # Exactly one of these must be None
    if address is None and error_type is None:
        raise ValueError('Must supply exactly one of address or error_type')
    elif address is not None:
        result = pack_address(address, ttl)
    elif error_type is not None:
        result = pack_resolve_error(error_type, ttl)
    else:
        raise ValueError('Must supply exactly one of address or error_type')
    if ttl is not None:
        result += pack_value(RESOLVE_TTL_LEN, ttl)
    return result

# TODO: unpack_resolve

TIMESTAMP_LEN = 4
ADDRESS_COUNT_LEN = 1

def pack_netinfo_payload(receiver_ip_string, sender_timestamp=None,
                         sender_ip_list=None):
    '''
    Pack a netinfo payload with sender_timestamp, receiver_ip_string,
    and sender_ip_list, using link_version.
    If sender_timestamp is None, uses the current time.
    If sender_ip_list is None, no local IP addresses are sent..
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n684
        https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1480
    '''
    if sender_timestamp is None:
        sender_timestamp = int(time.time())
    if sender_ip_list is None:
        sender_ip_list = []
    payload_bytes  = pack_value(TIMESTAMP_LEN, sender_timestamp)
    payload_bytes += pack_address(receiver_ip_string)
    payload_bytes += pack_value(ADDRESS_COUNT_LEN, len(sender_ip_list))
    # The caller should ensure an IPv4 address is first
    # See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1503
    for sender_ip_string in sender_ip_list:
        payload_bytes += pack_address(sender_ip_string)
    return payload_bytes

def pack_netinfo_cell(receiver_ip_string, sender_timestamp=None,
                      sender_ip_list=None, link_version=None,
                      force_payload_len=None):
    '''
    Pack a fixed-length netinfo cell with sender_timestamp, receiver_ip_string,
    and sender_ip_list, using link_version.
    If sender_timestamp is None, uses the current time.
    If sender_ip_list is None, no local IP addresses are sent..
    '''
    payload_bytes = pack_netinfo_payload(receiver_ip_string,
                                   sender_timestamp=sender_timestamp,
                                   sender_ip_list=sender_ip_list)
    return pack_cell('NETINFO', payload_bytes=payload_bytes,
                     link_version=link_version,
                     force_payload_len=force_payload_len)

def unpack_netinfo_payload(payload_len, payload_bytes):
    '''
    Unpack a netinfo cell payload from payload_bytes.
    Returns a dict containing these keys:
        'sender_timestamp'   : the sender's time in seconds since the epoch
        'receiver_ip_string' : the public IP address of the receiving end of
                               the connection, as seen by the sending node
        'sender_ip_list'     : the public IP addresses of the sending end of
                               the connection
    Asserts if payload_bytes is not exactly payload_len bytes long.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n503
    '''
    assert len(payload_bytes) == payload_len
    temp_bytes = payload_bytes
    (sender_timestamp, temp_bytes) = unpack_value(TIMESTAMP_LEN, temp_bytes)
    (receiver_ip_string, temp_bytes) = unpack_address(temp_bytes)
    (sender_ip_count, temp_bytes) = unpack_value(ADDRESS_COUNT_LEN, temp_bytes)
    # now parse the rest of the addresses
    sender_ip_list = []
    i = 0
    while i < sender_ip_count:
        assert len(temp_bytes) >= MIN_ADDRESS_LEN
        (sender_ip_string, temp_bytes) = unpack_address(temp_bytes)
        sender_ip_list.append(sender_ip_string)
        i += 1
        assert len(sender_ip_list) == sender_ip_count
    # and construct the result
    return {
        'sender_timestamp'   : sender_timestamp,
        'receiver_ip_string' : receiver_ip_string,
        'sender_ip_list'     : sender_ip_list,
        }

def pack_create_fast_payload():
    '''
    Pack HASH_LEN random bytes into a CREATE_FAST payload.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n962
    '''
    return get_random_bytes(HASH_LEN)

def pack_create_fast_cell(circ_id, link_version=None, force_payload_len=None):
    '''
    Pack HASH_LEN random bytes into a fixed-length CREATE_FAST cell,
    opening circ_id using link_version.
    This handshake should only be used after verifying the certificates
    in the CERTS cell.
    '''
    return pack_cell('CREATE_FAST', circ_id=circ_id,
                     payload_bytes=pack_create_fast_payload(),
                     link_version=link_version,
                     force_payload_len=force_payload_len)

def unpack_create_fast_payload(payload_len, payload_bytes):
    '''
    Unpack X from a CREATE_FAST payload.
    Returns a dict containing this key:
        'X_bytes' : the client's key material
    Asserts if payload_bytes is not payload_len long.
    Asserts if payload_len is less than HASH_LEN.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n962
    '''
    assert len(payload_bytes) == payload_len
    (X_bytes, _) = split_field(HASH_LEN, payload_bytes)
    return {
        'X_bytes' : X_bytes,
        }

# TODO: pack_created_fast_cell

def unpack_created_fast_payload(payload_len, payload_bytes):
    '''
    Unpack Y and KH from a CREATED_FAST payload.
    Returns a dict containing these keys:
        'Y_bytes'  : the server's key material
        'KH_bytes' : a hash proving that the server knows the shared key
    Asserts if payload_bytes is not payload_len long.
    Asserts if payload_len is less than HASH_LEN*2.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n962
        https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n997
    '''
    assert len(payload_bytes) == payload_len
    assert payload_len >= HASH_LEN*2
    remaining_bytes = payload_bytes
    (Y_bytes,  remaining_bytes) = split_field(HASH_LEN, remaining_bytes)
    (KH_bytes, remaining_bytes) = split_field(HASH_LEN, remaining_bytes)
    return {
        'Y_bytes'  : Y_bytes,
        'KH_bytes' : KH_bytes,
        }

# Relay cell packing and unpacking
# this depends on unpack_cell_header(), and is used by unpack_cell()

# Relay command field constants

# This table should be kept in sync with RELAY_UNPACK
RELAY_COMMAND = {
    # General Relay Commands
    # https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1257
    # [c] means [control], [c?] means [sometimes control].
    # [f] means [forward], [b] means backward.
    # node can be guard, middle, or end.
    # end can be exit, dir (inc. hsdir), intro, or rend.
    # edge can be an exit, hidden service (hs), or dir.
    'RELAY_BEGIN'                  :  1, # [f]      [client to exit/hs]
    'RELAY_DATA'                   :  2, # [f or b] [client to/from edge]
    'RELAY_END'                    :  3, # [f or b] [client to/from edge]
    'RELAY_CONNECTED'              :  4, # [b]      [edge to client]
    'RELAY_SENDME'                 :  5, # [f or b] [client to/from edge] [c?]
    'RELAY_EXTEND'                 :  6, # [f]      [client to node]      [c]
    'RELAY_EXTENDED'               :  7, # [b]      [node to client]      [c]
    'RELAY_TRUNCATE'               :  8, # [f]      [client to node]      [c]
    'RELAY_TRUNCATED'              :  9, # [b]      [node to client]      [c]
    'RELAY_DROP'                   : 10, # [f or b] [c/n to/from n/c]     [c]
    'RELAY_RESOLVE'                : 11, # [f]      [client to exit]
    'RELAY_RESOLVED'               : 12, # [b]      [exit to client]
    'RELAY_BEGIN_DIR'              : 13, # [f]      [client to dir]
    'RELAY_EXTEND2'                : 14, # [f]      [client to node]      [c]
    'RELAY_EXTENDED2'              : 15, # [b]      [node to client]      [c]

    # Onion Service (Hidden Service) Relay Commands
    # https://gitweb.torproject.org/torspec.git/tree/rend-spec.txt#n102
    # We use RELAY_* for all of these, despite what they're called in the spec.
    # See https://trac.torproject.org/projects/tor/ticket/22994
    'RELAY_ESTABLISH_INTRO'        : 32, # [f]      [service to intro]    [c]
    'RELAY_ESTABLISH_RENDEZVOUS'   : 33, # [f]      [client to rend]      [c]
    'RELAY_INTRODUCE1'             : 34, # [f]      [client to intro]     [c]
    'RELAY_INTRODUCE2'             : 35, # [b]      [intro to service]    [c]
    'RELAY_RENDEZVOUS1'            : 36, # [f]      [service to rend]     [c]
    'RELAY_RENDEZVOUS2'            : 37, # [b]      [rend to client]      [c]
    'RELAY_INTRO_ESTABLISHED'      : 38, # [b]      [intro to service]    [c]
    'RELAY_RENDEZVOUS_ESTABLISHED' : 39, # [b]      [rend to client]      [c]
    'RELAY_INTRODUCE_ACK'          : 40, # [b]      [intro to client]     [c]
}

def get_relay_command_value(relay_command_string):
    '''
    Returns the relay command value for relay_command_string.
    Asserts if relay_command_string is not a known relay command string.
    '''
    return RELAY_COMMAND[relay_command_string]

def get_relay_command_string(relay_command_value):
    '''
    Returns the relay command string for relay_command_value.
    Returns a descriptive string if relay_command_value is not a known relay
    command value.
    '''
    for relay_command_string in RELAY_COMMAND:
        if (relay_command_value ==
            get_relay_command_value(relay_command_string)):
            return relay_command_string
    return 'UNKNOWN_RELAY_COMMAND_{}'.format(relay_command_value)

RELAY_COMMAND_LEN = 1
RECOGNIZED_LEN = 2
STREAM_ID_LEN = 2
RELAY_DIGEST_LEN = 4
RELAY_PAYLOAD_LENGTH_LEN = 2

RELAY_HEADER_LEN = (RELAY_COMMAND_LEN + RECOGNIZED_LEN + STREAM_ID_LEN +
                    RELAY_DIGEST_LEN + RELAY_PAYLOAD_LENGTH_LEN)
MAX_FIXED_RELAY_PAYLOAD_LEN = MAX_FIXED_PAYLOAD_LEN - RELAY_HEADER_LEN

def pack_relay_header(relay_command_string,
                      stream_id=None,
                      relay_digest_bytes=None,
                      relay_payload_len=None,
                      force_recognized_bytes=None):
    '''
    Pack the relay header into a sequence of bytes.
    If stream_id is None, 0 is used.
    If relay_digest_bytes is None, zero bytes are used.
    If relay_payload_len is None, 0 is used.
    If force_recognized_bytes is not none, its value is used.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1240
    '''
    # Find the values
    relay_command_value = get_relay_command_value(relay_command_string)
    recognized_value = (0 if force_recognized_bytes is None else
                        force_recognized_bytes)
    stream_id_value = 0 if stream_id is None else stream_id
    relay_payload_len_value = (0 if relay_payload_len is None else
                               relay_payload_len)
    # Now pack the bytes
    relay_header  = pack_value(RELAY_COMMAND_LEN, relay_command_value)
    relay_header += pack_value(RECOGNIZED_LEN, recognized_value)
    relay_header += pack_value(STREAM_ID_LEN, stream_id_value)
    if relay_digest_bytes is not None:
        assert len(relay_digest_bytes) == RELAY_DIGEST_LEN
        # No byte-swapping here
        relay_header += relay_digest_bytes
    else:
        relay_header += get_zero_pad(RELAY_DIGEST_LEN)
    relay_header += pack_value(RELAY_PAYLOAD_LENGTH_LEN,
                               relay_payload_len_value)
    return relay_header

def is_relay_header_valid(relay_payload_len, recognized_bytes):
    '''
    Perform quick checks on recognized_bytes and relay_payload_len to see if
    a relay header is valid.
    '''
    # TODO: if variable-length relay payloads are ever allowed, this will break
    if relay_payload_len > MAX_FIXED_RELAY_PAYLOAD_LEN:
        return False
    if recognized_bytes != get_zero_pad(len(recognized_bytes)):
        return False
    # We can't check the digest: we don't have the context
    return True

def unpack_relay_header(payload_len, payload_bytes):
    '''
    Unpack the relay header from a RELAY or RELAY_FAST cell.
    Returns a dict containing these keys:
        relay_command_string             : the relay command as a string
        relay_command_value              : the relay command integer value
        stream_id                        : the stream id, or 0 for circuit
                                           control commands
        recognized_bytes                 : 0 if the cell belongs to this hop
        relay_digest_bytes               : a digest of all bytes sent to this
                                           hop of this circuit, including this
                                           cell's bytes with a zero digest
        relay_payload_len                : the length of the relay payload
        relay_payload_bytes              : the bytes in the relay payload
        is_relay_payload_zero_bytes_flag : True if the relay payload is all
                                           zero bytes (can indicate
                                           misinterpreted padding)
        is_relay_header_valid_flag       : is the relay header valid?
                                           this flag is approximate, it will
                                           be True with probability 498/2**32
                                           for random cells
    in a tuple with the remainder of the byte string (the relay payload).
    Asserts if relay_payload_bytes is not relay_payload_len long.
    Asserts if relay_payload_len is less than RELAY_HEADER_LEN.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1240
    '''
    assert len(payload_bytes) == payload_len
    assert payload_len >= RELAY_HEADER_LEN
    assert payload_len <= MAX_FIXED_PAYLOAD_LEN
    # Unpack the bytes
    temp_bytes = payload_bytes
    (relay_command_value, temp_bytes) = unpack_value(RELAY_COMMAND_LEN,
                                                     temp_bytes)
    (recognized_bytes, temp_bytes) = split_field(RECOGNIZED_LEN, temp_bytes)
    (stream_id, temp_bytes) = unpack_value(STREAM_ID_LEN, temp_bytes)
    (relay_digest_bytes, temp_bytes) = split_field(RELAY_DIGEST_LEN,
                                                    temp_bytes)
    (relay_payload_len, temp_bytes) = unpack_value(RELAY_PAYLOAD_LENGTH_LEN,
                                                   temp_bytes)
    # Find derived values
    is_relay_header_valid_flag = is_relay_header_valid(relay_payload_len,
                                                       recognized_bytes)
    result = {
        'relay_command_value'              : relay_command_value,
        'stream_id'                        : stream_id,
        'recognized_bytes'                 : recognized_bytes,
        'relay_digest_bytes'               : relay_digest_bytes,
        'relay_payload_len'                : relay_payload_len,
        'is_relay_header_valid_flag'       : is_relay_header_valid_flag,
        }
    if is_relay_header_valid_flag:
        relay_command_string = get_relay_command_string(relay_command_value)
        (relay_payload_bytes, _) = split_field(relay_payload_len, temp_bytes)
        is_relay_payload_zero_bytes_flag = (relay_payload_bytes ==
                                            get_zero_pad(relay_payload_len))
        result.update({
        'relay_command_string'             : relay_command_string,
        'relay_payload_bytes'              : relay_payload_bytes,
        'is_relay_payload_zero_bytes_flag' : is_relay_payload_zero_bytes_flag,
        })
    return result

def pack_relay_payload_impl(relay_command_string,
                            stream_id=None,
                            digest_bytes=None,
                            relay_payload_bytes=None,
                            force_recognized_bytes=None,
                            force_relay_payload_len=None):
    '''
    Pack relay_payload_bytes into a RELAY or RELAY_EARLY cell payload.
    If relay_payload_bytes is None, the relay payload part of the payload is
    empty. The relay payload is padded with zero bytes.
    If force_relay_payload_len is not None, it is used in the relay header
    instead of len(relay_payload_bytes).
    See pack_relay_header() for other argument details.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1240
    '''
    # Find the values
    relay_payload_len = (0 if relay_payload_bytes is None else
                         len(relay_payload_bytes))
    assert relay_payload_len <= MAX_FIXED_RELAY_PAYLOAD_LEN
    payload_data_len = RELAY_HEADER_LEN + relay_payload_len
    assert payload_data_len <= MAX_FIXED_PAYLOAD_LEN
    zero_pad_len = MAX_FIXED_RELAY_PAYLOAD_LEN - relay_payload_len

    # Pack the payload
    if force_relay_payload_len is None:
        force_relay_payload_len = relay_payload_len
    payload_bytes = pack_relay_header(relay_command_string,
                                     relay_digest_bytes=digest_bytes,
                                     stream_id=stream_id,
                                     relay_payload_len=force_relay_payload_len)

    if relay_payload_bytes is not None:
        payload_bytes += relay_payload_bytes

    # pad fixed-length cells to their length
    assert len(payload_bytes) == payload_data_len
    payload_bytes += get_zero_pad(zero_pad_len)

    assert len(payload_bytes) == MAX_FIXED_PAYLOAD_LEN
    return payload_bytes

def pack_relay_payload(relay_command_string,
                       hop_hash_context,
                       hop_crypt_context,
                       stream_id=None,
                       relay_payload_bytes=None,
                       force_recognized_bytes=None,
                       force_digest_bytes=None,
                       force_relay_payload_len=None):
    '''
    Pack relay_payload_bytes into a RELAY or RELAY_EARLY cell payload,
    calculating the digest based on the running digest of all relay cell
    payloads on this circuit hop (hop_hash_context), after updating it with
    this relay cell's payload (with all zero digest bytes).
    Then encrypt the payload with hop_crypt_context.
    If force_recognized_bytes, force_digest_bytes, or force_relay_payload_len
    are not None, their values are used instead of the default or calculated
    values.
    See pack_relay_payload_impl() for other argument details.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1240
    Returns a tuple with the encrypted payload bytes, plaintext payload bytes,
    and the new circuit hop hash and crypt states.
    '''
    if force_digest_bytes:
        return pack_relay_payload_impl(relay_command_string,
                               stream_id=stream_id,
                               digest_bytes=force_digest_bytes,
                               relay_payload_bytes=relay_payload_bytes,
                               force_recognized_bytes=force_recognized_bytes,
                               force_relay_payload_len=force_relay_payload_len)

    payload_zero_digest_bytes = pack_relay_payload_impl(relay_command_string,
                               stream_id=stream_id,
                               digest_bytes=None,
                               relay_payload_bytes=relay_payload_bytes,
                               force_recognized_bytes=force_recognized_bytes,
                               force_relay_payload_len=force_relay_payload_len)

    hop_hash_context = hash_update(hop_hash_context, payload_zero_digest_bytes)
    digest_bytes = hash_extract(hop_hash_context, output_len=RELAY_DIGEST_LEN)

    plain_payload_bytes = pack_relay_payload_impl(
                               relay_command_string,
                               stream_id=stream_id,
                               digest_bytes=digest_bytes,
                               relay_payload_bytes=relay_payload_bytes,
                               force_recognized_bytes=force_recognized_bytes,
                               force_relay_payload_len=force_relay_payload_len)

    (hop_crypt_context, crypt_payload_bytes) = crypt_bytes_context(
                                                         hop_crypt_context,
                                                         plain_payload_bytes)

    return (crypt_payload_bytes, plain_payload_bytes,
            hop_hash_context, hop_crypt_context)

def pack_relay_drop_data():
    '''
    Return a RELAY_DROP relay payload data, containing
    MAX_FIXED_RELAY_PAYLOAD_LEN random bytes.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1534
        https://trac.torproject.org/projects/tor/ticket/22948
    '''
    return get_random_bytes(MAX_FIXED_RELAY_PAYLOAD_LEN)

def pack_relay_drop_payload(circuit_hash_context,
                            force_recognized_bytes=None,
                            force_digest_bytes=None,
                            force_relay_payload_len=None):
    '''
    Pack a RELAY_DROP cell payload.
    See pack_relay_payload() for argument and return value details.
    '''
    return pack_relay_payload('RELAY_DROP',
                              circuit_hash_context,
                              stream_id=None,
                              relay_payload_bytes=pack_relay_drop_data(),
                              force_recognized_bytes=force_recognized_bytes,
                              force_digest_bytes=force_digest_bytes,
                              force_relay_payload_len=force_relay_payload_len)

def pack_relay_sendme_payload(circuit_hash_context,
                              stream_id=None,
                              force_recognized_bytes=None,
                              force_digest_bytes=None,
                              force_relay_payload_len=None):
    '''
    Pack a RELAY_SENDME cell payload.
    If stream_id is None, the SENDME cell is for the circuit, otherwise, it is
    for the specified stream.
    See pack_relay_payload() for argument and return value details.
    '''
    return pack_relay_payload('RELAY_SENDME',
                              circuit_hash_context,
                              stream_id=stream_id,
                              relay_payload_bytes=None,
                              force_recognized_bytes=force_recognized_bytes,
                              force_digest_bytes=force_digest_bytes,
                              force_relay_payload_len=force_relay_payload_len)

def pack_relay_begin_dir_payload(circuit_hash_context,
                                 stream_id,
                                 force_recognized_bytes=None,
                                 force_digest_bytes=None,
                                 force_relay_payload_len=None):
    '''
    Pack a RELAY_BEGIN_DIR cell payload.
    stream_id is the id of the resulting stream, it must be a positive,
    non-zero integer and unique on the circuit.
    See pack_relay_payload() for argument and return value details.
    '''
    assert stream_id > 0
    return pack_relay_payload('RELAY_BEGIN_DIR',
                              circuit_hash_context,
                              stream_id=stream_id,
                              relay_payload_bytes=None,
                              force_recognized_bytes=force_recognized_bytes,
                              force_digest_bytes=force_digest_bytes,
                              force_relay_payload_len=force_relay_payload_len)

CONNECTED_ADDRESS_TYPE_LEN = 1
CONNECTED_TTL_LEN = 4
MIN_RELAY_CONNECTED_LEN = 8

def unpack_relay_connected_payload(relay_payload_len, relay_payload_bytes):
    '''
    Unpack the relay payload from a RELAY_CONNECTED cell.
    Returns a dict containing these keys:
        connected_ip_string : the IP address that the remote relay connected to
        connected_ttl       : the TTL for which this address can be cached
    Asserts if relay_payload_bytes is not relay_payload_len long.
    Asserts if relay_payload_len is less than MIN_RELAY_CONNECTED_LEN.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1354
    '''
    assert len(relay_payload_bytes) == relay_payload_len
    assert relay_payload_len >= MIN_RELAY_CONNECTED_LEN
    temp_bytes = relay_payload_bytes
    if (temp_bytes == get_zero_pad(IPV4_ADDRESS_LEN)):
        # Four zero-valued octets followed by a type/IPv6/TTL
        (_, temp_bytes) = split_field(IPV4_ADDRESS_LEN, temp_bytes)
        (addr_type, temp_bytes) = split_field(CONNECTED_ADDRESS_TYPE_LEN,
                                              temp_bytes)
        assert addr_type == IPV6_ADDRESS_TYPE
    else:
        # IPv4/TTL
        addr_type = IPV4_ADDRESS_TYPE
    (connected_ip_string, temp_bytes) = unpack_ip_address_bytes(temp_bytes,
                                                                addr_type)
    (connected_ttl, _) = unpack_value(CONNECTED_TTL_LEN, temp_bytes)
    return {
        'connected_ip_string' : connected_ip_string,
        'connected_ttl'       : connected_ttl,
        }

# This table should be kept in sync with RELAY_COMMAND
RELAY_UNPACK = {
    # General Relay Commands
#   'RELAY_BEGIN'                  : unpack_relay_begin_payload,
#   'RELAY_DATA'                   : unpack_relay_data_payload,
#   'RELAY_END'                    : unpack_relay_end_payload,
    'RELAY_CONNECTED'              : unpack_relay_connected_payload,
    'RELAY_SENDME'                 : unpack_unused_payload,
#   'RELAY_EXTEND'                 : unpack_relay_extend_payload,
#   'RELAY_EXTENDED'               : unpack_relay_extended_payload,
    'RELAY_TRUNCATE'               : unpack_unused_payload,
#   'RELAY_TRUNCATED'              : unpack_destroy_payload,
    'RELAY_DROP'                   : unpack_unused_payload,
#   'RELAY_RESOLVE'                : unpack_relay_resolve_payload,
#   'RELAY_RESOLVED'               : unpack_relay_resolved_payload,
    'RELAY_BEGIN_DIR'              : unpack_unused_payload,
#   'RELAY_EXTEND2'                : unpack_relay_extend2_payload,
#   'RELAY_EXTENDED2'              : unpack_relay_extended2_payload,

    # Onion Service (Hidden Service) Relay Commands
#   'RELAY_ESTABLISH_INTRO'        : unpack_relay_establish_intro_payload,
#   'RELAY_ESTABLISH_RENDEZVOUS'   : unpack_relay_establish_rendezvous_payload,
#   'RELAY_INTRODUCE1'             : unpack_relay_introduce1_payload,
#   'RELAY_INTRODUCE2'             : unpack_relay_introduce2_payload,
#   'RELAY_RENDEZVOUS1'            : unpack_relay_rendezvous1_payload,
#   'RELAY_RENDEZVOUS2'            : unpack_relay_rendezvous2_payload,
    # Only unused for legacy introduction points:
#   'RELAY_INTRO_ESTABLISHED'      : unpack_relay_intro_established_payload,
    'RELAY_RENDEZVOUS_ESTABLISHED' : unpack_unused_payload,
#   'RELAY_INTRODUCE_ACK'          : unpack_relay_introdurc_ack_payload,
}

def get_relay_payload_unpack_function(relay_command_value):
    '''
    Returns the relay unpack function for relay_command_value.
    This function takes two arguments, relay_payload_len and
    relay_payload_bytes, and returns a dictionary containing the destructured
    payload contents.
    Returns unpack_unknown_payload if relay_command_value is not a known relay
    command value, and unpack_not_implemented_payload if it is known, but
    there is no unpack implementation.
    '''
    for relay_command_string in RELAY_COMMAND:
        if (relay_command_value ==
            get_relay_command_value(relay_command_string)):
            return RELAY_UNPACK.get(relay_command_string,
                                    unpack_not_implemented_payload)
    return unpack_unknown_payload

def unpack_relay_payload_impl(data_bytes, link_version=None):
    '''
    Calls unpack_relay_header(), then adds relay-command-specific fields,
    if available. You must pass the same link_version when packing the request
    and unpacking the response.
    Asserts if the relay structure is missing mandatory fields.
    Returns a dict containing the relay payload fields.
    '''
    relay_header = unpack_relay_header(data_bytes, link_version)
    if not relay_header['is_relay_header_valid_flag']:
        # We can't trust anything in the relay header: it's encrypted or
        # corrupted
        return relay_header
    relay_command_value = relay_header['relay_command_value']
    unpack_function = get_payload_unpack_function(relay_command_value)
    relay_payload_len = relay_header['relay_payload_len']
    relay_payload_bytes = relay_header['relay_payload_bytes']
    relay_payload = unpack_function(relay_payload_len,
                                    relay_payload_bytes)
    # Not just the relay header any more
    relay_content = relay_header
    relay_content.update(relay_payload)
    return relay_content

def unpack_relay_payload(crypt_bytes, hop_hash_context,
                         hop_crypt_context,
                         link_version=None, validate=True):
    '''
    Decrypt the relay payload in crypt_bytes with hop_crypt_context, then
    unpack the relay cell payload, using hop_hash_context to check integrity.
    Adds the following fields:
        expected_relay_digest_bytes : the expected relay digest, based on the
                                      cell's payload bytes, with a zero digest
    If validate, check the digest and recognized are correct.
    See unpack_relay_payload_impl() for other argument details.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1240
    Returns a tuple containing the unpacked cell, the modified crypt context,
    and the updated hash context.
    '''
    (hop_crypt_context, data_bytes) = crypt_bytes_context(hop_crypt_context,
                                                          crypt_bytes)
    relay_content = unpack_relay_payload_impl(data_bytes,
                                              link_version=link_version)

    if validate:
        assert relay_header['is_relay_header_valid_flag']
    else if not relay_header['is_relay_header_valid_flag']:
        return (relay_content, hop_crypt_context, hop_hash_context)

    # We could just zero out the relevant bytes in the payload instead
    relay_command_string = relay_content['relay_command_string']
    stream_id = relay_content['stream_id']
    relay_payload_bytes = relay_content['relay_payload_bytes']
    recognized_bytes = relay_content['recognized_bytes']
    payload_zero_digest_bytes = pack_relay_payload_impl(relay_command_string,
                                 stream_id=stream_id,
                                 digest_bytes=None,
                                 relay_payload_bytes=relay_payload_bytes,
                                 force_recognized_bytes=recognized_bytes)

    hop_hash_context = hash_update(hop_hash_context, payload_zero_digest_bytes)
    expected_relay_digest_bytes = hash_extract(hop_hash_context,
                                               RELAY_DIGEST_LEN)
    if validate:
        # check the cell was decoded correctly
        assert (expected_relay_digest_bytes ==
                relay_content['relay_digest_bytes'])
        assert recognized_bytes == get_zero_pad(RECOGNIZED_LEN)
    digest_dict = {
        'expected_relay_digest_bytes' : expected_relay_digest_bytes,
        }
    relay_content.update(digest_dict)
    return (relay_content, hop_crypt_context, hop_hash_context)

# This table should be kept in sync with CELL_COMMAND
CELL_UNPACK = {
    # Fixed-length Cells
    'PADDING'           : unpack_unused_payload,
#   'CREATE'            : unpack_create_payload,
#   'CREATED'           : unpack_created_payload,
    # We can't pass the circuit context to unpack_relay_payload via unpack_cell
    'RELAY'             : unpack_relay_payload_impl,
#   'DESTROY'           : unpack_destroy_payload,
    'CREATE_FAST'       : unpack_create_fast_payload,
    'CREATED_FAST'      : unpack_created_fast_payload,

    'NETINFO'           : unpack_netinfo_payload,
    # We can't pass the circuit context to unpack_relay_payload via unpack_cell
    'RELAY_EARLY'       : unpack_relay_payload_impl,
#   'CREATE2'           : unpack_create2_payload,
#   'CREATED2'          : unpack_created2_payload,
#   'PADDING_NEGOTIATE' : unpack_padding_negotiate_payload,

    # Variable-length cells
    'VERSIONS'          : unpack_versions_payload,

    'VPADDING'          : unpack_unused_payload,
#   'CERTS'             : unpack_certs_payload,
#   'AUTH_CHALLENGE'    : unpack_auth_challenge_payload,
#   'AUTHENTICATE'      : unpack_authenticate_payload,
#   'AUTHORIZE'         : unpack_authorize_payload           # (Not yet used)
}

def unpack_cell(data_bytes, link_version=None):
    '''
    Calls unpack_cell_header(), then adds cell-command-specific fields,
    if available.
    Asserts if the cell structure is missing mandatory fields.
    You must pass the same link_version when packing the request and unpacking
    the response.
    '''
    (cell, remaining_bytes) = unpack_cell_header(data_bytes, link_version)
    cell_command_value = cell['cell_command_value']
    unpack_function = get_payload_unpack_function(cell_command_value)
    payload_len = cell['payload_len']
    payload_bytes = cell['payload_bytes']
    payload_dict = unpack_function(payload_len, payload_bytes)
    cell.update(payload_dict)
    return (cell, remaining_bytes)

def unpack_cells(data_bytes, link_version_list=[3,4,5],
                 force_link_version=None):
    '''
    Unpack a stream of cells out of data_bytes, using
    link_version_list. If link_version_list has multiple
    elements, and data_bytes contains a VERSIONS cell, the highest common
    supported link version will be used to destructure subsequent cells.
    Returns a tuple containing a list of dicts with the destructured cells'
    contents, and the highest common supported link version, which is used
    to interpret the cells.
    This may be None if there were multiple supported versions, and no
    VERSIONS cell was received, or if there were no common link versions.
    You must pass the same link_version_list when packing the request and
    unpacking the response.
    force_link_version overrides any negotiated link version.
    Asserts if data_bytes is not the exact length of the cells it contains.
    Asserts if there is no common link version.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n503
    '''
    link_version = force_link_version
    cell_list = []
    temp_bytes = data_bytes
    while len(temp_bytes) >= get_cell_min_var_length(link_version):
        (cell, temp_bytes) = unpack_cell(temp_bytes, link_version)
        cell_list.append(cell)
        # If it's a versions cell, interpret all future cells as the highest
        # common supported version
        # Should we ignore subsequent versions cells?
        # See https://trac.torproject.org/projects/tor/ticket/22931
        if (cell['cell_command_string'] == 'VERSIONS' and
            link_version is None):
            remote_version_list = cell['link_version_list']
            link_version = get_highest_common_version(
                remote_version_list,
                link_version_list)
            assert link_version is not None
    assert len(temp_bytes) == 0
    return (link_version, cell_list)

def format_cells(data_bytes, link_version_list=[3,4,5],
                 force_link_version=None,
                 skip_cell_bytes=True, skip_zero_padding=True):
    '''
    Unpack and format the cells in data_bytes using unpack_cells().
    Returns a string formatted according to the arguments.
    You must pass the same link_version_list when packing the request and
    unpacking the response.
    '''
    (link_version, cell_list) = unpack_cells(data_bytes, link_version_list,
                                         force_link_version=force_link_version)
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
                if not is_var_cell_flag:
                    # Just assume any zeroes at the end are padding
                    data_bytes = data_bytes.rstrip('\0')
                output_bytes = data_bytes if skip_zero_padding else cell[key]
                result += '{} : {}\n'.format(key,
                                             binascii.hexlify(output_bytes))
                if (not is_var_cell_flag and (key == 'cell_bytes' or
                                              key == 'payload_bytes')):
                    zero_pad_len = len(cell[key]) - len(data_bytes)
                    result += '{}_{} : {}\n'.format(key, 'zero_pad_len',
                                                    zero_pad_len)
            else:
                result += '{} : {}\n'.format(key, cell[key])
    return result
