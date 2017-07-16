# Endosome: a Tor cell construction kit
#
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

import binascii
# ipaddress backport available for python 2.6, 2.7, 3.2
import ipaddress
import os
import socket
import ssl
import struct
import time

# Connection utility functions

MAX_READ_BUFFER_LEN = 10*1024*1024

def tcp_open(ip, port):
    '''
    Send a TCP request to ip and port.
    Returns a context dictionary required to continue the connection:
        'tcp_socket'  : a TCP socket connected to ip and port
    '''
    tcp_socket = socket.create_connection((ip, port))
    return {
        'tcp_socket' : tcp_socket,
        }

def tcp_write(context, request_bytes):
    '''
    Send a TCP request to the tcp_socket in context.
    '''
    context['tcp_socket'].sendall(request_bytes)

def tcp_read(context, max_response_len=MAX_READ_BUFFER_LEN):
    '''
    Reads and returns at most max_response_len bytes from the tcp_socket in
    context.
    '''
    return context['tcp_socket'].recv(max_response_len)

def tcp_close(context, do_shutdown=True):
    '''
    Closes the tcp_socket in context.
    If do_shutdown is True, shut down communication on the socket immediately,
    rather than waiting for the system to potentially clear buffers.
    '''
    if do_shutdown:
        context['tcp_socket'].shutdown(socket.SHUT_RDWR)
    context['tcp_socket'].close()

def tcp_request(ip, port, request_bytes,
                max_response_len=MAX_READ_BUFFER_LEN, do_shutdown=True):
    '''
    Send a TCP request to ip and port, and return at most max_response_len
    bytes of the response. If do_shutdown is True, shut down the socket
    immediately after reading the response.
    '''
    context = tcp_open(ip, port)
    tcp_write(context, request_bytes)
    response_bytes = tcp_read(context, max_response_len)
    tcp_close(context, do_shutdown)
    return response_bytes

def ssl_open(ip, port):
    '''
    Open a SSL connection to ip and port.
    Doesn't verify server certificates.
    Returns a context dictionary required to continue the connection:
        'ssl_socket'  : a SSL-wrapped TCP socket connected to ip and port
        'tcp_socket'  : a TCP socket connected to ip and port
    Unless you're using a *very* weird version of OpenSSL, this initiates
    a Tor link version 3 or later connection.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n226
    '''
    context = tcp_open(ip, port)
    # TODO: verify server certificates
    ssl_socket = ssl.wrap_socket(context['tcp_socket'])
    context.update({
            'ssl_socket' : ssl_socket
            })
    return context

def ssl_write(context, request_bytes):
    '''
    Send a SSL request to the ssl_socket in context.
    '''
    context['ssl_socket'].sendall(request_bytes)

def ssl_read(context, max_response_len=MAX_READ_BUFFER_LEN):
    '''
    Reads and returns at most max_response_len bytes from the ssl_socket in
    context.
    '''
    return context['ssl_socket'].recv(max_response_len)

def ssl_close(context, do_shutdown=True):
    '''
    Closes the ssl_socket in context.
    If do_shutdown is True, shut down communication on the socket immediately,
    rather than waiting for the system to potentially clear buffers.
    '''
    if do_shutdown:
        context['ssl_socket'].shutdown(socket.SHUT_RDWR)
    context['ssl_socket'].close()

def ssl_request(ip, port, request_bytes,
                max_response_len=MAX_READ_BUFFER_LEN, do_shutdown=True):
    '''
    Send a SSL request to ip and port, and return at most max_response_len
    bytes of the response. If do_shutdown is True, shut down the socket
    immediately after reading the response.
    Unless you're using a *very* weird version of OpenSSL, this makes
    a Tor link version 3 or later connection.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n226
    '''
    context = ssl_open(ip, port)
    ssl_write(context, request_bytes)
    response_bytes = ssl_read(context, max_response_len)
    ssl_close(context, do_shutdown)
    return response_bytes

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

# struct formats. See
# https://docs.python.org/2/library/struct.html#byte-order-size-and-alignment
PACK_FMT = {
    1 : '!B',
    2 : '!H',
    4 : '!L',
    8 : '!Q',
}

def get_pack_fmt(byte_len):
    '''
    Return the struct.pack format for an unsigned network-order byte_len field.
    Asserts if there is no format for byte_len.
    '''
    return PACK_FMT[byte_len]

def get_pack_max(byte_len):
    '''
    Returns the maximum unsigned value that will fit in byte_len.
    '''
    assert byte_len > 0
    return 2**(8*byte_len) - 1

def pack_value(byte_len, value):
    '''
    Return value packed as a network-order unsigned byte_len-byte field.
    Asserts if value is not byte_len bytes long.
    Assumes value is unsigned.
    '''
    fmt = get_pack_fmt(byte_len)
    assert struct.calcsize(fmt) == byte_len
    assert value >= 0
    assert value <= get_pack_max(byte_len)
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
    circ_id can be None, if it is, a valid circ_id is chosen:
        * 0 for link-level cells, or
        * get_min_valid_circ_id(link_version) for circuit-level cells.
      If you want to build more than one circuit on a connection, you'll have
      to supply unique circuit IDs yourself.
    payload can be None when allowed by the cell command.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n387
    '''
    cell_command_value = get_cell_command_value(cell_command_string)
    # Work out how long everything is
    circ_id_len = get_cell_circ_id_len(link_version)
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
        if is_cell_command_circuit(cell_command_value):
            circ_id = get_min_valid_circ_id(link_version)
        else:
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
    assert value <= get_pack_max(byte_len)
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
    return ''.join(packed_version_list)

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
    return pack_cell('VERSIONS',
                     payload=pack_versions_payload(link_version_list),
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

def pack_padding_cell(link_version=None):
    '''
    Pack a fixed-length padding cell with random bytes, using link_version.
    '''
    return pack_cell('PADDING',
                     payload=pack_padding_payload(),
                     link_version=link_version)

def pack_vpadding_payload(payload_len):
    '''
    Pack a variable-length padding cell's payload with payload_len random
    bytes.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n419
        https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1534
    '''
    return get_random_bytes(payload_len)

def pack_vpadding_cell(payload_len, link_version=None):
    '''
    Pack a variable-length padding cell with payload_len random bytes,
    using link_version.
    '''
    return pack_cell('VPADDING',
                     payload=pack_vpadding_payload(payload_len),
                     link_version=link_version)

RESOLVE_TYPE_LEN = 1
RESOLVE_VALUE_LENGTH_LEN = 1
RESOLVE_TTL_LEN = 4
RESOLVE_ERROR_VALUE_LEN = 0

# See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1480
ADDRESS_TYPE_HOST       = 0x00
ADDRESS_TYPE_IPV4       = 0x04
ADDRESS_TYPE_IPV6       = 0x06
ADDRESS_ERROR_TRANSIENT = 0xF0
ADDRESS_ERROR_PERMANENT = 0xF1

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
        if addr_type == ADDRESS_TYPE_IPV4:
            addr_len = IPV4_ADDRESS_LEN
            addr_bytes = ipaddress.v4_int_to_packed(int(addr_value))
        else:
            addr_len = IPV6_ADDRESS_LEN
            addr_bytes = ipaddress.v6_int_to_packed(int(addr_value))
    except ValueError:
        # must be a hostname
        addr_bytes = address
        addr_type = ADDRESS_TYPE_HOST
        addr_len = len(address)

    result  = pack_value(RESOLVE_TYPE_LEN, addr_type)
    result += pack_value(RESOLVE_VALUE_LENGTH_LEN, addr_len)
    assert len(addr_bytes) == addr_len
    result += addr_bytes
    return result

def unpack_address(data_bytes):
    '''
    Return a tuple containing the unpacked IP address string in data_bytes,
    and the remainder of data_bytes.
    Asserts if data_bytes is shorter than MIN_ADDRESS_LEN.
    '''
    assert len(data_bytes) >= MIN_ADDRESS_LEN
    temp_bytes = data_bytes
    (type, temp_bytes) = unpack_value(RESOLVE_TYPE_LEN, temp_bytes)
    (addr_len, temp_bytes) = unpack_value(RESOLVE_VALUE_LENGTH_LEN, temp_bytes)
    addr_bytes = temp_bytes[0:addr_len]
    if type == ADDRESS_TYPE_IPV4:
        assert addr_len == IPV4_ADDRESS_LEN
        addr_value = ipaddress.IPv4Address(bytes(addr_bytes))
    elif type == ADDRESS_TYPE_IPV6:
        assert addr_len == IPV6_ADDRESS_LEN
        addr_value = ipaddress.IPv6Address(bytes(addr_bytes))
    else:
        raise ValueError('Unexpected address type: {}'.format(type))
    addr_string = str(addr_value)
    return (addr_string, temp_bytes[addr_len:])

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
    payload  = pack_value(TIMESTAMP_LEN, sender_timestamp)
    payload += pack_address(receiver_ip_string)
    payload += pack_value(ADDRESS_COUNT_LEN, len(sender_ip_list))
    # The caller should ensure an IPv4 address is first
    # See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1503
    for sender_ip_string in sender_ip_list:
        payload += pack_address(sender_ip_string)
    return payload

def pack_netinfo_cell(receiver_ip_string, sender_timestamp=None,
                      sender_ip_list=None, link_version=None):
    '''
    Pack a fixed-length netinfo cell with sender_timestamp, receiver_ip_string,
    and sender_ip_list, using link_version.
    If sender_timestamp is None, uses the current time.
    If sender_ip_list is None, no local IP addresses are sent..
    '''
    payload = pack_netinfo_payload(receiver_ip_string,
                                   sender_timestamp=sender_timestamp,
                                   sender_ip_list=sender_ip_list)
    return pack_cell('NETINFO', payload=payload, link_version=link_version)

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

def pack_create_fast_cell(circ_id, link_version=None):
    '''
    Pack HASH_LEN random bytes into a fixed-length CREATE_FAST cell,
    opening circ_id using link_version.
    This handshake should only be used after verifying the certificates
    in the CERTS cell.
    '''
    return pack_cell('CREATE_FAST', circ_id=circ_id,
                     payload=pack_create_fast_payload(),
                     link_version=link_version)

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
    assert payload_len >= HASH_LEN
    return {
        'X_bytes' : payload_bytes[0:HASH_LEN],
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
    return {
        'Y_bytes'  : payload_bytes[0:HASH_LEN],
        'KH_bytes' : payload_bytes[HASH_LEN:HASH_LEN*2],
        }

# This table should be kept in sync with CELL_COMMAND
CELL_UNPACK = {
    # Fixed-length Cells
    'PADDING'           : unpack_unused_payload,
#   'CREATE'            : unpack_create_payload,
#   'CREATED'           : unpack_created_payload,
#   'RELAY'             : unpack_relay_payload,
#   'DESTROY'           : unpack_destroy_payload,
    'CREATE_FAST'       : unpack_create_fast_payload,
    'CREATED_FAST'      : unpack_created_fast_payload,

    'NETINFO'           : unpack_netinfo_payload,
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

def link_open(ip, port,
              link_version_list=[3,4,5], force_link_version=None,
              send_netinfo=True, sender_timestamp=None, sender_ip_list=None,
              max_response_len=MAX_READ_BUFFER_LEN):
    '''
    Open a link-level Tor connection to ip and port, using the highest
    link version in link_version_list supported by both sides.
    force_link_version overrides the negotiated link_version.

    If send_netinfo is true, send a NETINFO cell after the link version
    is negotiated, using ip as the receiver IP address, sender_timestamp
    and sender_ip_list. NETINFO cells are required by Tor.
    See https://trac.torproject.org/projects/tor/ticket/22951

    max_response_len is the maximum response size that will be read from the
    connection while setting up the link.

    Returns a context dictionary required to continue the connection:
        'link_version'             : the Tor cell link version used on the link
        'open_sent_cell_bytes'     : the cell bytes sent to open the connection
        'open_received_cell_bytes' : the cell bytes received when opening the
                                     connection
        'ssl_socket'               : a SSL-wrapped TCP socket connected to ip
                                    and port
        'tcp_socket'               : a TCP socket connected to ip and port

    Unless you're using a *very* weird version of OpenSSL, this initiates
    a Tor link version 3 or later connection.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n226
    '''
    context = ssl_open(ip, port)
    versions_cell_bytes = pack_versions_cell(link_version_list)
    open_sent_cell_bytes = versions_cell_bytes
    ssl_write(context, versions_cell_bytes)
    open_received_cell_bytes = ssl_read(context, max_response_len)
    (link_version, _) = unpack_cells(open_received_cell_bytes,
                                     link_version_list=link_version_list,
                                     force_link_version=force_link_version)
    if force_link_version:
        link_version = force_link_version
    # Now we know the link version, send a netinfo cell
    if send_netinfo:
        netinfo_cell_bytes = pack_netinfo_cell(ip,
                                             sender_timestamp=sender_timestamp,
                                             sender_ip_list=sender_ip_list,
                                             link_version=link_version)
        open_sent_cell_bytes += netinfo_cell_bytes
        ssl_write(context, netinfo_cell_bytes)
        # We don't expect anything in response to our NETINFO
    context.update({
            'link_version'             : link_version,
            'open_sent_cell_bytes'     : open_sent_cell_bytes,
            'open_received_cell_bytes' : open_received_cell_bytes,
            })
    return context

def link_write_cell_list(context,
                         cell_list,
                         force_link_version=None):
    '''
    Pack and send the Tor cells specified by cell_list to the ssl_socket in
    context, using the link_version in context. force_link_version overrides
    the link_version in context.
    An empty cell list is allowed: no cells are sent.
    Each dict in cell_list can have the following elements:
        cell_command_string, circ_id (optional), payload (optional),
        force_link_version (optional).
    '''
    cell_bytes = ''
    link_version = context['link_version']
    if force_link_version is not None:
        link_version = force_link_version
    for cell in cell_list:
        cell_link_version = cell.get('force_link_version', link_version)
        cell_bytes += pack_cell(cell['cell_command_string'],
                                circ_id=cell.get('circ_id'),
                                payload=cell.get('payload'),
                                link_version=cell_link_version)
    ssl_write(context, cell_bytes)

def make_cell(cell_command_string, circ_id=None, payload=None,
                 force_link_version=None):
    '''
    Return a dictionary containing the cell contents, as in link_write_cell().
    '''
    cell = {}
    cell['cell_command_string'] = cell_command_string
    if circ_id is not None:
        cell['circ_id'] = circ_id
    if payload is not None:
        cell['payload'] = payload
    if force_link_version is not None:
        cell['force_link_version'] = force_link_version
    return cell

def link_write_cell(context,
                    cell_command_string, circ_id=None, payload=None,
                    force_link_version=None):
    '''
    Write a Tor cell with cell_command_string, circ_id, and payload.
    See link_write_cell_list() for details.    
    '''
    cell = make_cell(cell_command_string, circ_id=circ_id, payload=payload,
                     force_link_version=force_link_version)
    link_write_cell_list(context,
                         [cell],
                         # This is redundant, but do it anyway
                         force_link_version=force_link_version)
    
def link_read_cell_bytes(context,
                         force_link_version=None,
                         max_response_len=MAX_READ_BUFFER_LEN):
    '''
    Reads and returns at most max_response_len bytes from the ssl_socket in
    context, using the link_version in context.
    Returns the cell bytes received.
    force_link_version overrides the link_version in context.
    '''
    received_bytes = ssl_read(context, max_response_len)
    link_version = context['link_version']
    if force_link_version is not None:
        link_version = force_link_version
    return received_bytes

def link_close(context,
               do_shutdown=True):
    '''
    Closes the Tor link in context.
    If do_shutdown is True, shut down communication on the socket immediately,
    rather than waiting for the system to potentially clear buffers.
    '''
    # There is no Tor cell command for closing a link
    ssl_close(context, do_shutdown)

def link_request_cell_list(ip, port,
                           cell_list,
                           link_version_list=[3,4,5], force_link_version=None,
                           send_netinfo=True, sender_timestamp=None,
                           sender_ip_list=None,
                           max_response_len=MAX_READ_BUFFER_LEN,
                           do_shutdown=True):
    '''
    Send the Tor cells in cell_list to ip and port, using link_version_list,
    (force_link_version overrides the negotiated link_version),
    and read at most max_response_len bytes of response cells.
    If do_shutdown is True, shut down the socket immediately after reading the
    response.
    Returns a tuple containing the context, and the response bytes.
    Unless you're using a *very* weird version of OpenSSL, this makes
    a Tor link version 3 or later connection.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n226
    '''
    context = link_open(ip, port,
                        link_version_list=link_version_list,
                        force_link_version=force_link_version,
                        send_netinfo=send_netinfo,
                        sender_timestamp=sender_timestamp,
                        sender_ip_list=sender_ip_list,
                        max_response_len=max_response_len)
    link_write_cell_list(context,
                         cell_list,
                         force_link_version=force_link_version)
    response_cell_bytes = ''
    if len(cell_list) > 0:
        response_cell_bytes = link_read_cell_bytes(context,
                                        force_link_version=force_link_version,
                                        max_response_len=max_response_len)
    link_close(context, do_shutdown)
    return (context, response_cell_bytes)

def link_request_cell(ip, port,
                      cell_command_string, circ_id=None, payload=None,
                      link_version_list=[3,4,5], force_link_version=None,
                      send_netinfo=True, sender_timestamp=None,
                      sender_ip_list=None,
                      max_response_len=MAX_READ_BUFFER_LEN,
                      do_shutdown=True):
    '''
    Send a Tor cell with cell_command_string, circ_id, and payload.
    See link_request_cell_list() for details.
    '''
    cell = make_cell(cell_command_string, circ_id=circ_id, payload=payload,
                     force_link_version=force_link_version)
    return link_request_cell_list(ip, port,
                                  [cell],
                                  link_version_list=link_version_list,
                                  force_link_version=force_link_version,
                                  send_netinfo=send_netinfo,
                                  sender_timestamp=sender_timestamp,
                                  sender_ip_list=sender_ip_list,
                                  max_response_len=max_response_len,
                                  do_shutdown=do_shutdown)

def link_format_cell_bytes(context, cell_bytes,
                           force_link_version=None,
                           skip_cell_bytes=True, skip_zero_padding=True):
    '''
    Unpack and format the cells in cell_bytes using format_cells(), supplying
    the relevant arguments from context.
    Returns a string formatted according to the arguments.
    '''
    link_version = context.get('link_version')
    if force_link_version is not None:
        link_version = force_link_version
    return format_cells(cell_bytes,
                        link_version_list=[link_version],
                        # we must use force_link_version, because we already
                        # know the link version from the context
                        force_link_version=link_version,
                        skip_cell_bytes=skip_cell_bytes,
                        skip_zero_padding=skip_zero_padding)

def link_format_context(context,
                        force_link_version=None,
                        skip_cell_bytes=True, skip_zero_padding=True,
                        skip_cells=False):
    '''
    Format context, using link_format_cell_bytes() to format the cells in
    context.
    Returns a string formatted according to the arguments.
    '''
    result = ''
    link_version = context['link_version']
    if force_link_version:
        link_version = force_link_version
    for key in sorted(context.keys()):
        if key.endswith('cell_bytes'):
            if skip_cells:
                continue
            # we know the link version, unless it's the initial versions
            # cell on either side
            cell_link_version = link_version
            if key.startswith('open'):
                cell_link_version = None
            result += '{} cells:\n'.format(key)
            result += format_cells(context[key],
                                   link_version_list=[link_version],
                                   force_link_version=cell_link_version,
                                   skip_cell_bytes=skip_cell_bytes,
                                   skip_zero_padding=skip_zero_padding)
        else:
            result += '{} : {}\n'.format(key, context[key])
    return result
