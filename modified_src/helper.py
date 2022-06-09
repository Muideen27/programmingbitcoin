#!/usr/bin/python3

"""`helper` - module for format conversion subroutines.

Contains methods to assist other modules in (de)serialization, hashing,
 and variable type conversion.

Modified from original repository developed by Jimmy Song for his book
Programming Bitcoin, O'Reilly Media Inc, March 2019. See
https://github.com/jimmysong/programmingbitcoin

"""

import hashlib


BASE58_NUMERALS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def hash160(s):
    """Hashes a byte sequence with sha256 followed by ripemd160.

    Args:
        s (str/bytes): sequence to hash

    Returns:
        bytes: hashed sequence

    """
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()


def hash256(s):
    """Hashes a byte sequence with two rounds of sha256.

    Args:
        s (str/bytes): sequence to hash

    Returns:
        bytes: hashed sequence

    """
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


# TBD: never called outside this module, only by encode_base58_checksum
def encode_base58(b):
    """Encodes a byte sequence into a base 58 numeral string.

    Base 58 numerals are the set of digits + uppercase + lowercase - '01Ol'.

    Args:
        b (bytes): big endian sequence to encode

    Returns:
        str: int value in base 58 representation

    """
    count = 0
    for c in b:
        if c == 0:
            count += 1
        else:
            break
    num = int.from_bytes(b, 'big')
    prefix = '1' * count
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_NUMERALS[mod] + result
    return prefix + result


# TBD: rename base58_checksum?
def encode_base58_checksum(b):
    """Converts a value and the first four bytes of its checksum into a base 58
    string.

    Args:
        b (bytes): sequence to encode

    Returns:
        str: base 58 representation of sequence and first 4 bytes of checksum

    """
    return encode_base58(b + hash256(b)[:4])


def decode_base58(b):
    """Encodes a byte sequence into a base 58 numeral string.

    Base 58 numerals are the set of digits + uppercase + lowercase - '01Ol'.

    Args:
        b (bytes): big endian sequence to encode

    Returns:
        str: int value in base 58 representation

    """
    num = 0
    for c in b:
        num *= 58
        num += BASE58_NUMERALS.index(b)
    combined = num.to_bytes(25, 'big')
    checksum = combined[-4:]
    if hash256(combined[:-4])[:4] != checksum:
        raise ValueError('bad address: {} {}'.format(
            checksum, hash256(combined[:-4])[:4]))
    return combined[1:-4]


# TBD: replace with from_bytes, as to_bytes is already frequently used
def little_endian_to_int(b):
    """Converts a little-endian byte sequence to an integer.

    """
    return int.from_bytes(b, 'little')

# TBD: replace with to_bytes, as to_bytes(x, 'big') is already frequently used
def int_to_little_endian(n, length):
    """Converts an integer to a little-endian byte sequence.

    """
    return n.to_bytes(length, 'little')
