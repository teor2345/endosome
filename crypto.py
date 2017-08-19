# Endosome: a Tor cell construction ki
#
# Tested: Python 2.7.13 on macOS 10.12.5 with OpenSSL 1.0.2l and tor 0.3.0.9.
# (The default OpenSSL on macOS is *very* old.)

# Cryptographic Functions

import binascii

import cryptography.hazmat.primitives.ciphers as ciphers
import cryptography.hazmat.primitives.ciphers.algorithms as ciphers_algorithms
import cryptography.hazmat.primitives.ciphers.modes as ciphers_modes
import cryptography.hazmat.primitives.hashes as hashes
import cryptography.hazmat.primitives.kdf.hkdf as hkdf

import cryptography.hazmat.backends as backends

from pack import *

BITS_IN_BYTE = 8

def hash_create(algorithm=hashes.SHA1()):
    '''
    Create and return a new hash context for algorithm.
    Tor cells use SHA1 as a hash algorithm, except for v3 onion services,
    which use SHA3-256 for client to service cells.
    '''
    # cryptography doesn't have a SHA3 implementation (as of July 2017)
    return hashes.Hash(algorithm, backend=backends.default_backend())

def hash_update(hash_context, data_bytes, make_context_reusable=True):
    '''
    Update hash_context with data_bytes.
    Returns the updated hash_context.
    If make_context_reusable is False, the passed hash_context will be
    modified in-place.
    '''
    update_context = hash_context
    if make_context_reusable:
        update_context = hash_context.copy()
    update_context.update(bytes(data_bytes))
    return update_context

def hash_extract(hash_context, output_len=None, make_context_reusable=True):
    '''
    Extract and return output_len bytes from hash_context.
    If output_len is None, return the full hash length.
    If make_context_reusable is False, future uses of hash_context will throw
    cryptography.exceptions.AlreadyFinalized.
    '''
    # The digest_size is in bytes
    if output_len is None:
        output_len = hash_context.algorithm.digest_size
    assert output_len <= hash_context.algorithm.digest_size
    extract_context = hash_context
    if make_context_reusable:
        extract_context = hash_context.copy()
    (output_bytes, _) = split_field(output_len, extract_context.finalize())
    return output_bytes

# TODO: hash_finalize? hash_destroy?

def hash_bytes(data_bytes, output_len=None, algorithm=hashes.SHA1()):
    '''
    Extract and return output_len bytes from a hash of data_bytes.
    If output_len is None, return the full hash length.
    '''
    hash_context = hash_create(algorithm=algorithm)
    hash_context = hash_update(hash_context, data_bytes)
    return hash_extract(hash_context,
                        output_len=output_len,
                        make_context_reusable=False)

# Tor-specific hash functions

COUNTER_BYTE_LEN = 1

def kdf_tor(K0_bytes, output_len):
    '''
    Return output_len bytes generated from K0_bytes using KDF-TOR (sic).
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n997
    '''
    output_bytes = bytearray()
    i = 0
    while len(output_bytes) < output_len:
        assert i < 256
        counter_byte = pack_value(COUNTER_BYTE_LEN, i)
        output_bytes += hash_bytes(K0_bytes + counter_byte)
        i += 1
    (output_bytes, _) = split_field(output_len, output_bytes)
    return output_bytes

# TODO: test the ntor KDF

# See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n895
PROTOID = 'ntor-curve25519-sha256-1'
M_EXPAND_NTOR = PROTOID + ':key_expand'
T_KEY_NTOR = PROTOID + ':key_extract'

def kdf_rfc5869_derive(secret_input_bytes, output_len, m_expand=M_EXPAND_NTOR,
                       t_key=T_KEY_NTOR):
    '''
    Return output_len bytes generated from secret_input_bytes using RFC5869
    with HKDF-SHA256.
    There is no equivalent verification function, as only the nonce part of
    the KDF result is verified directly.
    See https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n1026
    '''
    hkdf_sha256 = hkdf.HKDF(algorithm=hashes.SHA256(),
                            length=output_len,
                            info=bytes(m_expand),
                            salt=bytes(t_key),
                            backend=backends.default_backend())
    output_bytes = hkdf_sha256.derive(bytes(secret_input_bytes))
    assert len(output_bytes) == output_len
    return bytearray(output_bytes)

def crypt_create(key_bytes,
                 is_encrypt_flag=None,
                 iv_bytes=None,
                 algorithm=ciphers_algorithms.AES,
                 mode=ciphers_modes.CTR):
    '''
    Create and return a crypto context for symmetric key encryption using the
    key key_bytes.
    
    Uses algorithm in mode with an IV of iv_bytes.
    If iv_bytes is None, an all-zero IV is used.

    AES CTR mode uses the same operations for encryption and decyption.
    '''
    #print "Key: " + binascii.hexlify(bytes(key_bytes))
    algo = algorithm(bytes(key_bytes))
    # The block_size is in bits
    if iv_bytes is None:
        iv_bytes = get_zero_pad(algo.block_size/BITS_IN_BYTE)
    cipher = ciphers.Cipher(algo, mode(bytes(iv_bytes)),
                            backend=backends.default_backend()) 
    if is_encrypt_flag:
        return cipher.encryptor()
    else:
        return cipher.decryptor()

def crypt_bytes_context(crypt_context, data_bytes):
    '''
    Use crypt_context to encrypt or decrypt data_bytes.
    Returns a tuple containing an updated context, and the crypted
    data_bytes.
    The passed crypt_context is alway modified in-place.
    '''
    #print "Bytes: " + binascii.hexlify(bytes(data_bytes))
    # we don't need to call finalize() on stream ciphers
    crypt_bytes = crypt_context.update(bytes(data_bytes))
    return (crypt_context, bytearray(crypt_bytes))

# TODO: crypt_destroy?

def crypt_bytes_key(key_bytes,
                    data_bytes,
                    is_encrypt_flag=None,
                    iv_bytes=None,
                    algorithm=ciphers_algorithms.AES,
                    mode=ciphers_modes.CTR):
    '''
    Use symmetric key encryption to encrypt or decrypt data_bytes with
    key_bytes.
    Returns the crypted data_bytes.
    See crypt_create() and crypt_bytes_context() for details.
    '''
    crypt_context = crypt_create(key_bytes,
                                 is_encrypt_flag=is_encrypt_flag,
                                 iv_bytes=iv_bytes,
                                 algorithm=algorithm,
                                 mode=mode)
    (_, crypt_bytes) = crypt_bytes_context(crypt_context, data_bytes)
    return crypt_bytes
