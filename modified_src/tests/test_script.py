#!/usr/bin/python3
"""`test_script` - Unit test module for script.py

Part of an educational mockup of Bitcoin Core; adapted from original
repository developed by Jimmy Song, et al:

    https://github.com/jimmysong/programmingbitcoin

for his book Programming Bitcoin, O'Reilly Media Inc, March 2019.

"""

from unittest import TestCase
from unittest import main
from io import BytesIO

from script import Script


class SongTestScript(TestCase):
    """Song's unit tests for script module methods.

    """
    def test_parse(self):
        script_pubkey = BytesIO(bytes.fromhex(
            '6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d'
            '71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9'
            'aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe'
            '85a872e6a19b43c15a2937'))
        script = Script.deserialize(script_pubkey)
        want = bytes.fromhex(
            '304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1'
            'cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3'
            '649071c1a71601')
        self.assertEqual(script.cmds[0].hex(), want.hex())
        want = bytes.fromhex(
            '035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a29'
            '37')
        self.assertEqual(script.cmds[1], want)

    def test_serialize(self):
        want = '6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f'+\
            '5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7'+\
            'c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009de'+\
            'd7c62efe85a872e6a19b43c15a2937'
        script_pubkey = BytesIO(bytes.fromhex(want))
        script = Script.deserialize(script_pubkey)
        self.assertEqual(script.serialize().hex(), want)


if __name__ == '__main__':
    unittest.main()
