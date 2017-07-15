# Endosome: a Tor cell construction kit
#
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

import binascii
import os
import socket
import ssl
import struct

# Connection utility functions

def tcp_request(ip, port, request, max_response_len):
    '''
    Send a TCP request to ip and port, and return at most max_response_len
    bytes of the response.
    '''
    dsock = socket.create_connection((ip, port))
    dsock.sendall(request)
    return dsock.recv(max_response_len)

def ssl_request(ip, port, request, max_response_len):
    '''
    Send a SSL request to ip and port, and return at most max_response_len
    bytes of the response.
    Unless you're using a *very* weird version of OpenSSL, this initiates
    a Tor link version 3 or later connection.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n226
    '''
    dsock = socket.create_connection((ip, port))
    ssock = ssl.wrap_socket(dsock)
    ssock.sendall(request)
    return ssock.recv(max_response_len)

# Link version constants
# https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n538

LINK_VERSION_DESC = {
  None : "negotiating link version",
     1 : "certs up front",
     2 : "renegotiation",
     3 : "in-protocol",
     4 : "circuit ID 4 bytes",
     5 : "link padding and negotiation",
}

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
                                 "UNKNOWN_LINK_VERSION_{}"
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
    return "UNKNOWN_CELL_COMMAND_{}".format(cell_command_value)

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
        return 512
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
    # Assume the shorter cell length
    if cell_command_value is None:
        cell_command_value = get_cell_command_value('VERSIONS')
    return (get_cell_circ_id_len(link_version, cell_command_value) +
            CELL_COMMAND_LEN + PAYLOAD_LENGTH_LEN)

def get_cell_circ_id_len(link_version, cell_command_value=None):
    '''
    Get the circuit id length for link_version and cell_command_value
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n412
    '''
    # a versions cell always has a 2-byte circuit id, because it has
    # a link_version of None, unless force_link_version is used
    # See https://trac.torproject.org/projects/tor/ticket/22931
    #if cell_command_value == get_cell_command_value('VERSIONS'):
    #    return 2
    # early in the handshake, assume that all cells have 2-byte circ_ids
    # See https://trac.torproject.org/projects/tor/ticket/22929
    if link_version is None:
        return 2
    # don't check LINK_VERSION_DESC, that would assert on new link versions
    assert link_version > 0
    if link_version >= 1 and link_version <= 3:
        return 2
    return 4

# struct formats. See
# https://docs.python.org/2/library/struct.html#byte-order-size-and-alignment
PACK_FMT = {
    1 : "!B",
    2 : "!H",
    4 : "!L",
}

def get_pack_fmt(byte_len):
    '''
    Return the struct.pack format for an unsigned network-order byte_len field.
    Asserts if there is no format for byte_len.
    '''
    return PACK_FMT[byte_len]

def get_pack_limit(byte_len):
    '''
    Returns the maximum unsigned value that will fit in byte_len.
    '''
    assert byte_len > 0
    return 2**(8*byte_len)

def pack_value(byte_len, value):
    '''
    Return value packed as a network-order unsigned byte_len-byte field.
    Asserts if value is not byte_len bytes long.
    Assumes value is unsigned.
    '''
    fmt = get_pack_fmt(byte_len)
    assert struct.calcsize(fmt) == byte_len
    assert value >= 0
    assert value < get_pack_limit(byte_len)
    return struct.pack(fmt, value)

def get_zero_pad(zero_pad_len):
    '''
    Return zero_pad_len zero bytes.
    '''
    assert zero_pad_len >= 0
    zero_pad = pack_value(1, 0) * zero_pad_len
    assert len(zero_pad) == zero_pad_len
    return zero_pad

def get_random_bytes(random_len):
    '''
    Return random_len cryptographically random bytes.
    '''
    assert random_len >= 0
    result = os.urandom(random_len)
    assert len(result) == random_len
    return result

def pack_cell(cell_command_string, link_version=None, circ_id=None,
              payload=None):
    '''
    Pack a cell for link_version, on circuit circ_id,
    with command cell_command_string and payload.
    link_version can be None for VERSIONS cells.
    circ_id can be None for link-level cells.
    payload can be None when allowed by the cell command.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n387
    '''
    cell_command_value = get_cell_command_value(cell_command_string)
    # Work out how long everything is
    circ_id_len = get_cell_circ_id_len(link_version, cell_command_value)
    payload_len = 0 if payload is None else len(payload)
    is_var_cell_flag = is_cell_command_variable_length(cell_command_value)
    if is_var_cell_flag:
        cell_len = (circ_id_len + CELL_COMMAND_LEN + PAYLOAD_LENGTH_LEN +
                    payload_len)
    else:
        data_len = circ_id_len + CELL_COMMAND_LEN + payload_len
        cell_len = get_cell_fixed_length(link_version)
        zero_pad_len = cell_len - data_len
        assert payload_len <= MAX_FIXED_PAYLOAD_LEN

    # Now pack it all in
    if circ_id is None:
        circ_id = 0
    cell = pack_value(circ_id_len, circ_id)

    # byte order is irrelevant in this case
    cell += pack_value(CELL_COMMAND_LEN, cell_command_value)

    if is_var_cell_flag:
        cell += pack_value(PAYLOAD_LENGTH_LEN, payload_len)

    if payload is not None:
        cell += payload

    # pad fixed-length cells to their length
    if not is_var_cell_flag:
        assert len(cell) == data_len
        cell += get_zero_pad(zero_pad_len)

    assert len(cell) == cell_len
    return cell

def unpack_value(byte_len, data_bytes):
    '''
    Return a tuple containing the unpacked network-order unsigned
    byte_len-byte field in data_bytes, and the remainder of data_bytes.
    Asserts if data_bytes is not at least byte_len bytes long.
    '''
    fmt = get_pack_fmt(byte_len)
    assert struct.calcsize(fmt) == byte_len
    assert len(data_bytes) >= byte_len
    value_tuple = struct.unpack(fmt, data_bytes[0:byte_len])
    assert len(value_tuple) == 1
    value, = value_tuple
    assert value >= 0
    assert value < get_pack_limit(byte_len)
    return (value, data_bytes[byte_len:])

def unpack_cell_header(data_bytes, link_version=None):
    '''
    Unpack a cell header out of data_bytes for link_version.
    link_version can be None before versions cells have been exchanged.
    Returns a tuple containing a dict with the destructured cell contents,
    and the remainder of byte string.
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
    # check the received data is long enough
    # if you pass different versions in the request and response, you will
    # probably trigger an assertion here
    assert len(data_bytes) >= cell_len
    assert len(temp_bytes) >= payload_len
    cell_bytes = data_bytes[0:cell_len]
    payload_bytes = temp_bytes[0:payload_len]
    temp_bytes = temp_bytes[payload_len:]
    is_payload_zero_bytes_flag = (payload_bytes == get_zero_pad(payload_len))
    cell_structure = {
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
    return (cell_structure, temp_bytes)

# Unpack placeholders

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

def pack_versions_cell(link_version_list=[3,4,5], force_link_version=None):
    '''
    Pack a versions cell with link_version_list.
    If force_link_version is not None, use that circ_id_len.
    We use versions 3-5 to match ssl_request(), which initiates a version
    3 or later connection.
    You must pass the same link_version_list when packing the request and
    unpacking the response.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n503
    '''
    packed_version_list = []
    for version in link_version_list:
        packed_version_list.append(pack_value(VERSION_LEN, version))
    return pack_cell('VERSIONS', payload=''.join(packed_version_list),
                     link_version=force_link_version)

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

def pack_padding_cell(link_version=None):
    '''
    Pack a fixed-length padding cell with random bytes, using link_version.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n419
        https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1534
    '''
    return pack_cell('PADDING',
                     payload=get_random_bytes(MAX_FIXED_PAYLOAD_LEN),
                     link_version=link_version)

def pack_vpadding_cell(payload_len, link_version=None):
    '''
    Pack a variable-length padding cell with payload_len random bytes,
    using link_version.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n419
        https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1534
    '''
    return pack_cell('VPADDING',
                     payload=get_random_bytes(payload_len),
                     link_version=link_version)

# This table should be kept in sync with CELL_COMMAND
CELL_UNPACK = {
    # Fixed-length Cells
    'PADDING'           : unpack_unused_payload,
#   'CREATE'            : unpack_create_payload,
#   'CREATED'           : unpack_created_payload,
#   'RELAY'             : unpack_relay_payload,
#   'DESTROY'           : unpack_destroy_payload,
#   'CREATE_FAST'       : unpack_create_fast_payload,
#   'CREATED_FAST'      : unpack_created_fast_payload,

#   'NETINFO'           : unpack_netinfo_payload,
#   'RELAY_EARLY'       : unpack_relay_payload,
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
    You must pass the same link_version_list when packing the request and
    unpacking the response.
    '''
    (cell_structure, remaining_bytes) = unpack_cell_header(data_bytes,
                                                           link_version)
    cell_command_value = cell_structure['cell_command_value']
    unpack_function = get_payload_unpack_function(cell_command_value)
    payload_len = cell_structure['payload_len']
    payload_bytes = cell_structure['payload_bytes']
    payload_structure = unpack_function(payload_len, payload_bytes)
    cell_structure.update(payload_structure)
    return (cell_structure, remaining_bytes)

def unpack_cells(data_bytes, link_version_list=[3,4,5]):
    '''
    Unpack a stream of cells out of data_bytes, using
    link_version_list. If link_version_list has multiple
    elements, and data_bytes contains a VERSIONS cell, the highest common
    supported link version will be used to destructure subsequent cells.
    Returns a tuple containing a list of dicts with the destructured cells'
    contents, and the highest common supported link version, which is used
    to interpret the cells.
    This may be None if there were multiple supported versions, and no
    VERSIONS cell was received.
    You must pass the same link_version_list when packing the request and
    unpacking the response.
    Asserts if data_bytes is not the exact length of the cells it contains.
    Asserts if there is no common link version.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n503
    '''
    link_version = None
    cell_list = []
    temp_bytes = data_bytes
    while len(temp_bytes) >= get_cell_min_var_length(link_version):
        (cell_structure, temp_bytes) = unpack_cell(temp_bytes, link_version)
        cell_list.append(cell_structure)
        # If it's a versions cell, interpret all future cells as the highest
        # common supported version
        # Should we ignore subsequent versions cells?
        # See https://trac.torproject.org/projects/tor/ticket/22931
        if cell_structure['cell_command_string'] == 'VERSIONS':
            remote_version_list = cell_structure['link_version_list']
            link_version = get_highest_common_version(
                remote_version_list,
                link_version_list)
            assert link_version is not None
    assert len(temp_bytes) == 0
    return (link_version, cell_list)

def format_cells(data_bytes, link_version_list=[3,4,5],
                 skip_cell_bytes=True, skip_zero_padding=True):
    '''
    Unpack and format the cells in data_bytes using unpack_cells().
    Returns a string formatted according to the arguments.
    You must pass the same link_version_list when packing the request and
    unpacking the response.
    '''
    (link_version, cell_list) = unpack_cells(data_bytes, link_version_list)
    result  = "Link Version: {}\n".format(link_version)
    result += "{} Cell(s):\n".format(len(cell_list))
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
                result += "{} : {}\n".format(key,
                                             binascii.hexlify(output_bytes))
                if not is_var_cell_flag:
                    zero_pad_len = len(cell[key]) - len(data_bytes)
                    result += "{}_{} : {}\n".format(key, 'zero_pad_len',
                                                    zero_pad_len)
            else:
                result += "{} : {}\n".format(key, cell[key])
    return result
