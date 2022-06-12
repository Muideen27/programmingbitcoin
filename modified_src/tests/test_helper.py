#!/usr/bin/python3
"""`test_helper` - Unit test module for helper.py

Modified from original code base developed by Jimmy Song for his book
Programming Bitcoin, O'Reilly Media Inc, March 2019. See
https://github.com/jimmysong/programmingbitcoin

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
    little_endian_to_int,
    int_to_little_endian,
)


class SongTestHelper(TestCase):
    """Song's unit tests for helper module methods.

    """

    def test_little_endian_to_int(self):
        h = bytes.fromhex('99c3980000000000')
        want = 10011545
        self.assertEqual(little_endian_to_int(h), want)
        h = bytes.fromhex('a135ef0100000000')
        want = 32454049
        self.assertEqual(little_endian_to_int(h), want)

    def test_int_to_little_endian(self):
        n = 1
        want = b'\x01\x00\x00\x00'
        self.assertEqual(int_to_little_endian(n, 4), want)
        n = 10011545
        want = b'\x99\xc3\x98\x00\x00\x00\x00\x00'
        self.assertEqual(int_to_little_endian(n, 8), want)


if __name__ == '__main__':
    unittest.main()
