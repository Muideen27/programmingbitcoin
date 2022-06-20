#!/usr/bin/python3
"""`test_helper` - Unit test module for helper.py

Part of an educational mockup of Bitcoin Core; adapted from original
repository developed by Jimmy Song, et al:

    https://github.com/jimmysong/programmingbitcoin

for his book Programming Bitcoin, O'Reilly Media Inc, March 2019.

"""

from unittest import TestCase
from unittest import main
import string

from helper import (
    hash160,
    hash256,
    encode_base58,
    encode_base58_checksum,
    decode_base58,
    decode_base58_checksum,
    encode_varint,
    read_varint,
)


class SongTestHelper(TestCase):
    """Song's unit tests for helper module methods.

    """
    # Note: test_little_endian_to_int removed, as was little_endian_to_int
    # Note: test_int_to_little_endian removed, as was int_to_little_endian
    pass


if __name__ == '__main__':
    unittest.main()
