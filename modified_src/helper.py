#!/usr/bin/python3
"""`helper` - module for format conversion subroutines.

Contains methods to assist other modules in (de)serialization, hashing,
 and variable type conversion.

Part of an educational mockup of Bitcoin Core; adapted from original
repository developed by Jimmy Song, et al:

    https://github.com/jimmysong/programmingbitcoin

for his book Programming Bitcoin, O'Reilly Media Inc, March 2019.

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


def encode_base58(b):
    """Encodes a byte sequence into a base 58 numeral string.

    Base 58 numerals are the set of digits + uppercase + lowercase - '01Ol'.

    Args:
        b (bytes): big endian sequence to encode

    Returns:
        str: int value in base 58 representation

    """
    # TBD: re-establish that this initial safety check needed
    if b == b'':
        return ''
    leading_null_bytes = 0
    for c in b:
        if c == 0x00:
            leading_null_bytes += 1
        else:
            break
    num = int.from_bytes(b, 'big')
    prefix = '1' * leading_null_bytes
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_NUMERALS[mod] + result
    return prefix + result


def encode_base58_checksum(b):
    """Converts a value and the first four bytes of its checksum into a base 58
    string.

    Intended for use in WIF and Bitcoin address formats.

    Args:
        b (bytes): sequence to encode

    Returns:
        str: base 58 representation of sequence and first 4 bytes of checksum

    """
    return encode_base58(b + hash256(b)[:4])


def decode_base58(s):
    """Decodes a base 58 numeral string into a big endian byte sequence.

    Base 58 numerals are the set of digits + uppercase + lowercase - '01Ol'.

    Args:
        s (str): base 58 numeral string

    Returns:
        bytes: vbig endian byte sequence

    """
    # TBD: re-establish that this initial safety check needed
    if s == '':
        return b''
    leading_nulls = 0
    for c in s:
        if c == '1':
            leading_nulls += 1
        else:
            break
    num = 0
    for c in s[leading_nulls:]:
        num *= 58
        num += BASE58_NUMERALS.index(c)
    byte_ct, ex_bits = divmod(num.bit_length(), 8)
    byte_ct = byte_ct if ex_bits == 0 else byte_ct + 1
    byte_ct += leading_nulls
    return num.to_bytes(byte_ct, 'big')


# TBD: Song's later use of decode_base58 assumes use with addresses,
#     returning combined[1:-4], instead of the combined[1:-4] here. Why
#     the trimming of the first byte?
def decode_base58_checksum(s):
    """Decodes a base 58 checksum string and verifies checksum.

    Intended for use in WIF and Bitcoin address formats.

    Args:
        s (str): base 58 checksum string

    Returns:
        bytes: big endian byte sequence verified by checksum

    """
    combined = decode_base58(s)
    checksum = combined[-4:]
    data = combined[:-4]
    if hash256(data)[:4] != checksum:
        raise ValueError('invalid checksum: '
                         f'{checksum.hex()} {hash256(data)[:4].hex()}')
    return data


# Note: little_endian_to_int replaced with int.from_bytes(b, 'little'),
#   as to_bytes is already frequently used in codebase


# Note: int_to_little_endian replaced with n.to_bytes(length, 'little'),
#   as n.to_bytes(length, 'big') is already frequently used in codebase


def encode_varint(i):
    """Encodes an integer as a varint.

    varints, or variable integers, are a means of serializing unsigned values
    in a variable byte count, depending on the value.

    Args:
        i (int): value to encode

    Returns:
        bytes: varint encoded value

    """
    if i < 0:
        raise ValueError(f"only unsigned integers can be encoded")
    elif i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + i.to_bytes(2, 'little')
    elif i < 0x100000000:
        return b'\xfe' + i.to_bytes(4, 'little')
    elif i < 0x10000000000000000:
        return b'\xff' + i.to_bytes(8, 'little')
    else:
        raise ValueError(f"integer too large to encode: {i}")


def read_varint(s):
    """Reads and decodes a variable integer from a stream.

    First byte of the varint, if >= 253, serves as a flag to indicate
    the byte count of the following encoding.

    Args:
        s (_io.*): stream to read

    Returns:
        i (int): decoded value

    """
    i = s.read(1)[0]
    if i == 0xfd:
        return int.from_bytes(s.read(2), 'little')
    elif i == 0xfe:
        return int.from_bytes(s.read(4), 'little')
    elif i == 0xff:
        return int.from_bytes(s.read(8), 'little')
    else:
        return i
