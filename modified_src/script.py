#!/usr/bin/python3
"""`script` - module implementing the Bitcoin smart contract language, Script.

Part of an educational mockup of Bitcoin Core; adapted from original
repository developed by Jimmy Song, et al:

    https://github.com/jimmysong/programmingbitcoin

for his book Programming Bitcoin, O'Reilly Media Inc, March 2019.

"""

from io import BytesIO
from logging import getLogger
from collections import deque

from helper import (
    encode_varint,
    read_varint,
)
from op import (
    OP_CODE_FUNCTIONS,
    OP_CODE_NAMES,
)


# TBD: Why Logger and not direct raising of exceptions? Python `logging`
#   tutorial at: https://docs.python.org/3.8/howto/logging.html
LOGGER = getLogger(__name__)
"""TBD: LOGGER description, once explained

"""

class Script:
    """Representation of Bitcoin Core Script command sequence.

    Script is the Bitcoin Core smart contract programming language, and is
    used to validate transactions. Commands are either elements, byte
    sequences to be used as data inputs, or operations, designated with
    opcodes (see `op` module.)

    TBD: reread ch06 and add description of combining ScriptPubKey and
    ScriptSig, and the standard Bitcoin scripts.

    Attributes:
        cmds (deque) FIFO command list

    """
    def __init__(self, cmds=deque()):
        """Instantiate a Script object.

        Args:
            cmds (deque): FIFO command list

        """
        self.cmds = cmds

    def __repr__(self):
        """Developer-oriented representation of a Bitcoin Core Script.

        Returns:
            str: representation of Script

        """
        result = []
        for cmd in self.cmds:
            if type(cmd) == int:
                if cmd in OP_CODE_NAMES:
                    name = OP_CODE_NAMES[cmd]
                else:
                    name = f'OP_[{cmd}]'
                result.append(name)
            else:
                result.append(cmd.hex())
        return ' '.join(result)

    def serialize(self):
        """Encodes Script into byte sequence.

        TBD: description of serialization

        Returns:
            bytes: serialized Script

        """
        result = b''
        for cmd in self.cmds:
            if type(cmd) == int:
                # opcodes are ints less than 256
                result += cmd.to_bytes(1, 'little')
            else:
                # elements are bytes
                length = len(cmd)
                if length <= 75:
                    # opcode is data length (including 0 for empty bytes obj)
                    result += length.to_bytes(1, 'little')
                elif length < 256:
                    # op_pushdata1
                    result += bytes([76])
                    result += length.to_bytes(1, 'little')
                elif length <= 520:
                    # op_pushdata2
                    result += bytes([77])
                    result += length.to_bytes(2, 'little')
                else:
                    raise ValueError('invalid element length')
                result += cmd
        return encode_varint(len(result)) + result

    @classmethod
    def deserialize(cls, s):
        """Deserialize a Script from a stream.

        See Script.serialize for serialization format.

        Args:
            s (_io.*): stream to read

        Returns:
            Script: parsed Script

        """
        length = read_varint(s)
        cmds = deque()
        byte_ct = 0
        while byte_ct < length:
            current_byte = s.read(1)[0]  # convert current byte to integer
            byte_ct += 1
            if current_byte >= 1 and current_byte <= 75:
                # opcode indicating next n bytes to be read as element
                n = current_byte
                cmds.append(s.read(n))
                byte_ct += n
            elif current_byte == 76:
                # op_pushdata1
                data_length = int.from_bytes(s.read(1), 'little')
                cmds.append(s.read(data_length))
                byte_ct += data_length + 1
            elif current_byte == 77:
                # op_pushdata2
                data_length = int.from_bytes(s.read(2), 'little')
                cmds.append(s.read(data_length))
                byte_ct += data_length + 2
            else:
                # all other opcodes, valid or invalid
                cmds.append(current_byte)
        if byte_ct != length:
            raise SyntaxError('parsing script failed')
        return cls(cmds)

    def evaluate(self, z):
        """Determine validity of a transaction by processing Script commands.

        Args:
            z (bytes): TBD: is (int)? TBD: add note about sig_hash in ch07

        Returns:
            bool: True if transaction is validated, False otherwise

        """
        # create a copy in case of adding to cmd list with a RedeemScript
        cmds = self.cmds[:]
        stack = deque()
        altstack = deque()
        while len(cmds) > 0:
            # execute commands in FIFO order, as opposed to LIFO stack
            cmd = cmds.popleft()
            if type(cmd) == int:
                # opcodes are ints less than 256
                if cmd in OP_CODE_FUNCTIONS:
                    operation = OP_CODE_FUNCTIONS[cmd]
                else:
                    if cmd in OP_CODE_NAMES:
                        error = 'reserved/disabled/unimplemented op: ' + \
                            f'{OP_CODE_NAMES[cmd]}'
                    else:
                        error = f'unrecognized op: OP_[{cmd}]'
                    LOGGER.info(error)
                    return False
                if cmd in (99, 100):
                    # op_if/op_notif require the cmds array
                    if not operation(stack, cmds):
                        LOGGER.info(f'bad op: {OP_CODE_NAMES[cmd]}')
                        return False
                elif cmd in (107, 108):
                    # op_toaltstack/op_fromaltstack require the altstack
                    if not operation(stack, altstack):
                        LOGGER.info(f'bad op: {OP_CODE_NAMES[cmd]}')
                        return False
                elif cmd in (172, 173, 174, 175):
                    # signing operations require sig_hash to check against
                    if not operation(stack, z):
                        LOGGER.info(f'bad op: {OP_CODE_NAMES[cmd]}')
                        return False
                else:
                    if not operation(stack):
                        LOGGER.info(f'bad op: {OP_CODE_NAMES[cmd]}')
                        return False
            else:
                # add bytes to stack as element
                stack.append(cmd)
        if len(stack) == 0:
            return False
        # TBD: why this check as well? Because OP_0 is not considered a no-op?
        if stack.pop() == b'':
            return False
        return True
