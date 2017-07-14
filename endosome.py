# Endosome: a Tor cell construction kit
#
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

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
    '''
    dsock = socket.create_connection((ip, port))
    ssock = ssl.wrap_socket(dsock)
    ssock.sendall(request)
    return ssock.recv(max_response_len)

# Link version constants
# https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n538

LINK_VERSION_DESC = {
     1 : "certs up front",
     2 : "renegotiation",
     3 : "in-protocol",
     4 : "circuit ID 4 bytes",
     5 : "link padding and negotiation",
}

# Cell command field constants
# https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n419

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

def get_cell_command_value(command_string):
    '''
    Returns the cell command value for command_string.
    Asserts if command_string is not a known cell command string.
    '''
    return CELL_COMMAND[command_string]

def get_cell_command_string(command_value):
    '''
    Returns the cell command string for command_value.
    Returns a descriptive string if command_value is not a known cell command
    value.
    '''
    for command_string in CELL_COMMAND:
        if command_value == get_cell_command_value(command_string):
            return command_string
    return "UNKNOWN_CELL_COMMAND_{}".format(command_value)

MIN_VAR_COMMAND_VALUE = 128

def is_cell_command_variable_length(command_value):
    '''
    Returns True if command_value uses a variable-length cell,
    and False otherwise.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n412
    '''
    if (command_value == get_cell_command_value('VERSIONS') or
        command_value >= MIN_VAR_COMMAND_VALUE):
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
MAX_PAYLOAD_LEN = 509

def get_cell_fixed_length(link_version):
    '''
    Get the fixed-length cell length for link_version.
    Fixed-length cells aren't sent on a link until the link version has been
    negotiated.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n66
    '''
    # if link_version is None, you shouldn't even be asking this question
    if link_version is None:
        return None
    assert link_version > 0
    if link_version < 4:
        return 512
    else:
        return 514

def get_cell_circ_id_len(link_version, command_value):
    '''
    Get the circuit id length for link_version and command_value
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n412
    '''
    # don't check CELL_COMMAND, that would assert on new command values
    assert command_value >= 0
    # a versions cell always has a 2-byte circuit id
    if command_value == get_cell_command_value('VERSIONS'):
        return 2
    # don't check LINK_VERSION_DESC, that would assert on new link versions
    assert link_version > 0
    if link_version >= 1 and link_version <= 3:
        return 2
    return 4

COMMAND_LEN = 1
PAYLOAD_LENGTH_LEN = 2

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

def pack_cell(command_string, link_version=None, circ_id=None, payload=None):
    '''
    Pack a cell for link_version, on circuit circ_id,
    with command command_string and payload.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n387
    '''
    command_value = get_cell_command_value(command_string)
    # Work out how long everything is
    circ_id_len = get_cell_circ_id_len(link_version, command_value)
    payload_len = 0 if payload is None else len(payload)
    is_var = is_cell_command_variable_length(command_value)
    if is_var:
        cell_len = (circ_id_len + COMMAND_LEN + PAYLOAD_LENGTH_LEN +
                    payload_len)
    else:
        data_len = circ_id_len + COMMAND_LEN + payload_len
        cell_len = get_cell_fixed_length(link_version)
        zero_pad_len = cell_len - data_len
        assert payload_len <= MAX_PAYLOAD_LEN

    # Now pack it all in
    if circ_id is None:
        circ_id = 0
    cell = pack_value(circ_id_len, circ_id)

    # byte order is irrelevant in this case
    cell += pack_value(COMMAND_LEN, command_value)

    if is_var:
        cell += pack_value(PAYLOAD_LENGTH_LEN, payload_len)

    if payload is not None:
        cell += payload

    # pad fixed-length cells to their length
    if not is_var:
        assert len(cell) == data_len
        zero_pad = pack_value(1, 0) * zero_pad_len
        assert len(zero_pad) == zero_pad_len
        cell += zero_pad
        
    assert len(cell) == cell_len
    return cell

VERSION_LEN = 2

def pack_versions_cell(supported_version_list=[3,4,5]):
    '''
    Pack a versions cell with supported_version_list.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n503
    '''
    packed_version_list = []
    for version in supported_version_list:
        packed_version_list.append(pack_value(VERSION_LEN, version))
    return pack_cell('VERSIONS', payload=''.join(packed_version_list))
