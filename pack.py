# Endosome: a Tor cell construction kit
#
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

import os
import struct

# Field packing and unpacking

def split_field(byte_len, data_bytes):
    '''
    Return a tuple containing the first byte_len bytes in data_bytes, and the
    remainder of data_bytes.
    Asserts if data_bytes is not at least byte_len bytes long.
    '''
    assert len(data_bytes) >= byte_len
    return (data_bytes[0:byte_len], data_bytes[byte_len:])

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
    return bytearray(struct.pack(fmt, value))

def unpack_value(byte_len, data_bytes):
    '''
    Return a tuple containing the unpacked network-order unsigned
    byte_len-byte field in data_bytes, and the remainder of data_bytes.
    Asserts if data_bytes is not at least byte_len bytes long.
    '''
    (value_bytes, remaining_bytes) = split_field(byte_len, data_bytes)
    fmt = get_pack_fmt(byte_len)
    assert struct.calcsize(fmt) == byte_len
    value_tuple = struct.unpack(fmt, value_bytes)
    assert len(value_tuple) == 1
    value, = value_tuple
    assert value >= 0
    assert value <= get_pack_max(byte_len)
    return (value, remaining_bytes)

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
