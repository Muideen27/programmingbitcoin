#!/usr/bin/python3
"""`op` - module for Script language opcodes.

Used in conjuction with `script` to implement the Bitcoin smart contract
language, Script.

Opcode documentation taken in part from https://en.bitcoin.it/wiki/Script.

Part of an educational mockup of Bitcoin Core; adapted from original
repository developed by Jimmy Song, et al:

    https://github.com/jimmysong/programmingbitcoin

for his book Programming Bitcoin, O'Reilly Media Inc, March 2019.

"""

import hashlib

from helper import (
    hash160,
    hash256,
)


def encode_num(num):
    """Encodes integers into modified little endian format for use in Script.

    Args:
        num (int): integer to encode

    Returns:
        bytes: Script-encoded value

    """
    if num == 0:
        return b''
    abs_num = abs(num)
    negative = num < 0
    result = bytearray()
    # equivalent to bytearray(abs_num.to_bytes(n, 'little'), without knowing n
    while abs_num:
        result.append(abs_num & 0xff)
        abs_num >>= 8
    # for negative numbers we ensure that the top bit is set; for positive not
    if result[-1] & 0x80:
        result.append(0x80 if negative else 0)
    elif negative:
        result[-1] |= 0x80
    return bytes(result)


def decode_num(element):
    """Decodes an integer from a Script element.

    Args:
        element (bytes): element to decode

    Returns:
        int: decoded integer

    """
    if element == b'':
        return 0
    # encoded in a modified little endian format, reverse for big endian
    big_endian = element[::-1]
    # top bit set means it's negative
    if big_endian[0] & 0x80:
        negative = True
        result = big_endian[0] & 0x7f
    else:
        negative = False
        result = big_endian[0]
    for c in big_endian[1:]:
        result <<= 8
        result += c
    return -result if negative else result


def op_0(stack):
    """Script opcode OP_0 / OP_FALSE: An empty array of bytes is pushed onto
    the stack.

    Note: This is not a no-op, as an item is added to the stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success

    """
    stack.append(encode_num(0))
    return True


def op_1negate(stack):
    """Script opcode OP_1NEGATE: The number -1 is pushed onto the stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success

    """
    stack.append(encode_num(-1))
    return True


def op_1(stack):
    """Script opcode OP_1 / OP_TRUE: The number 1 is pushed onto the stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success

    """
    stack.append(encode_num(1))
    return True


def op_2(stack):
    """Script opcode OP_2: The number 2 is pushed onto the stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success

    """
    stack.append(encode_num(2))
    return True


def op_3(stack):
    """Script opcode OP_3: The number 3 is pushed onto the stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success

    """
    stack.append(encode_num(3))
    return True


def op_4(stack):
    """Script opcode OP_4: The number 4 is pushed onto the stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success

    """
    stack.append(encode_num(4))
    return True


def op_5(stack):
    """Script opcode OP_5: The number 5 is pushed onto the stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success

    """
    stack.append(encode_num(5))
    return True


def op_6(stack):
    """Script opcode OP_6: The number 6 is pushed onto the stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success

    """
    stack.append(encode_num(6))
    return True


def op_7(stack):
    """Script opcode OP_7: The number 7 is pushed onto the stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success

    """
    stack.append(encode_num(7))
    return True


def op_8(stack):
    """Script opcode OP_8: The number 8 is pushed onto the stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success

    """
    stack.append(encode_num(8))
    return True


def op_9(stack):
    """Script opcode OP_9: The number 9 is pushed onto the stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success

    """
    stack.append(encode_num(9))
    return True


def op_10(stack):
    """Script opcode OP_10: The number 10 is pushed onto the stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success

    """
    stack.append(encode_num(10))
    return True


def op_11(stack):
    """Script opcode OP_11: The number 11 is pushed onto the stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success

    """
    stack.append(encode_num(11))
    return True


def op_12(stack):
    """Script opcode OP_12: The number 12 is pushed onto the stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success

    """
    stack.append(encode_num(12))
    return True


def op_13(stack):
    """Script opcode OP_13: The number 13 is pushed onto the stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success

    """
    stack.append(encode_num(13))
    return True


def op_14(stack):
    """Script opcode OP_14: The number 14 is pushed onto the stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success

    """
    stack.append(encode_num(14))
    return True


def op_15(stack):
    """Script opcode OP_15: The number 15 is pushed onto the stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success

    """
    stack.append(encode_num(15))
    return True


def op_16(stack):
    """Script opcode OP_16: The number 16 is pushed onto the stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success

    """
    stack.append(encode_num(16))
    return True


def op_nop(stack):
    """Script opcodes OP_NOP, OP_NOP1, OP_NOP4-OP_NOP10: Does nothing.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success

    """
    return True


def op_if(stack, items, notif=False):
    """Script opcode OP_IF: If the top stack value is not False, the following
    statements are executed. The top stack value is removed.

    Uses the pattern: <expression> if [statements] [else [statements]]* endif

    Note: Song elected to implement op_if and op_notif as two mostly redundant
    functions, each with inbuilt handling of OP_ELSE and OP_ENDIF to process
    nested loops. The only difference was the final test for 0, so they were
    consolidated.

    Args:
        stack (deque): Script execution stack
        items (list): Script command list at point of OP_IF call
        notif (bool): reverses behavior based on top stack value at end

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 1:
        return False
    # go through and re-make the items array based on the top stack element
    true_items = []
    false_items = []
    current_array = true_items
    found = False
    num_endifs_needed = 1
    while len(items) > 0:
        item = items.pop(0)
        if item in (99, 100):                         # (OP_IF, OP_NOTIF)
            # nested if, we have to go another endif
            num_endifs_needed += 1
            current_array.append(item)
        elif num_endifs_needed == 1 and item == 103:  # OP_ELSE
            current_array = false_items
        elif item == 104:                             # OP_ENDIF
            if num_endifs_needed == 1:
                found = True
                break
            else:
                num_endifs_needed -= 1
                current_array.append(item)
        else:
            current_array.append(item)
    if not found:
        return False
    element = stack.pop()
    if (decode_num(element) == 0) == notif:
        items[:0] = true_items
    else:
        items[:0] = false_items
    return True


def op_notif(stack, items):
    """Script opcode OP_NOTIF: If the top stack value is False, the statements
    are executed. The top stack value is removed.

    Uses the pattern: <expression> notif [statements] [else [statements]]* endif

    Args:
        stack (deque): Script execution stack
        items (list): Script command list at point of OP_NOTIF call

    Returns:
        bool: True on success, False on failure

    """
    return op_if(stack, items, notif=True)


# TBD: OP_ELSE docstring info (if later broken out into separate method):
#   <expression> if [statements] [else [statements]]* endif
#   If the preceding OP_IF or OP_NOTIF or OP_ELSE was not executed then these
#   statements are and if the preceding OP_IF or OP_NOTIF or OP_ELSE was
#   executed then these statements are not.


# TBD: OP_ENDIF docstring info (if later broken out into separate method):
#   <expression> if [statements] [else [statements]]* endif Ends an if/else
#   block. All blocks must end, or the transaction is invalid. An OP_ENDIF
#   without OP_IF earlier is also invalid.


def op_verify(stack):
    """Script opcode OP_VERIFY: Marks transaction as invalid if top stack value
    is not true (is 0.) The top stack value is removed.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 1:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        return False
    return True


def op_return(stack):
    """Script opcode OP_RETURN: Marks transaction as invalid.

    Notes: Since bitcoin 0.9, a standard way of attaching extra data to
    transactions is to add a zero-value output with a scriptPubKey consisting
    of OP_RETURN followed by data. Such outputs are provably unspendable and
    specially discarded from storage in the UTXO set, reducing their cost to
    the network. Since 0.12, standard relay rules allow a single output with
    OP_RETURN, that contains any sequence of push statements (or
    OP_RESERVED[1]) after the OP_RETURN provided the total scriptPubKey length
    is at most 83 bytes.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    return False


def op_toaltstack(stack, altstack):
    """Script opcode OP_TOALTSTACK: Puts the input onto the top of the alt
    stack. Removes it from the main stack.

    Args:
        stack (deque): Script execution stack
        altstack (deque): alternate Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 1:
        return False
    altstack.append(stack.pop())
    return True


def op_fromaltstack(stack, altstack):
    """Script opcode OP_FROMALTSTACK: Puts the input onto the top of the main
    stack. Removes it from the alt stack.

    Args:
        stack (deque): Script execution stack
        altstack (deque): alternate Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(altstack) < 1:
        return False
    stack.append(altstack.pop())
    return True


def op_2drop(stack):
    """Script opcode OP_2DROP: Removes the top two stack items.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 2:
        return False
    stack.pop()
    stack.pop()
    return True


def op_2dup(stack):
    """Script opcode OP_2DUP: Duplicates the top two stack items.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 2:
        return False
    stack.extend(stack[-2:])
    return True


def op_3dup(stack):
    """Script opcode OP_3DUP: Duplicates the top three stack items.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 3:
        return False
    stack.extend(stack[-3:])
    return True


def op_2over(stack):
    """Script opcode OP_2OVER: Copies the pair of items two spaces back in the
    stack to the front.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 4:
        return False
    stack.extend(stack[-4:-2])
    return True


def op_2rot(stack):
    """Script opcode OP_2ROT: The fifth and sixth items back are moved to the
    top of the stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 6:
        return False
    stack.extend(stack[-6:-4])
    return True


def op_2swap(stack):
    """Script opcode OP_2SWAP: Swaps the top two pairs of items.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 4:
        return False
    stack[-4:] = stack[-2:] + stack[-4:-2]
    return True


def op_ifdup(stack):
    """Script opcode OP_IFDUP: If the top stack value is not 0, duplicate it.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 1:
        return False
    if decode_num(stack[-1]) != 0:
        stack.append(stack[-1])
    return True


def op_depth(stack):
    """Script opcode OP_DEPTH: Puts the number of stack items onto the stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    stack.append(encode_num(len(stack)))
    return True


def op_drop(stack):
    """Script opcode OP_DROP: Removes the top stack item.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 1:
        return False
    stack.pop()
    return True


def op_dup(stack):
    """Script opcode OP_DUP: Duplicates the top stack item.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 1:
        return False
    stack.append(stack[-1])
    return True


def op_nip(stack):
    """Script opcode OP_NIP: Removes the second-to-top stack item.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 2:
        return False
    stack[-2:] = stack[-1:]
    return True


def op_over(stack):
    """Script opcode OP_OVER: Copies the second-to-top stack item to the top.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 2:
        return False
    stack.append(stack[-2])
    return True


def op_pick(stack):
    """Script opcode OP_PICK: Pop top of stack to get value n; the item n back
    in the stack is copied to the top.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 1:
        return False
    n = decode_num(stack.pop())
    if len(stack) < n + 1:
        return False
    stack.append(stack[-n - 1])
    return True


def op_roll(stack):
    """Script opcode OP_ROLL: Pop top of stack to get value n; the item n back
    in the stack is moved to the top.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 1:
        return False
    n = decode_num(stack.pop())
    if len(stack) < n + 1:
        return False
    if n == 0:
        return True
    stack.append(stack.pop(-n - 1))
    return True


def op_rot(stack):
    """Script opcode OP_ROT: The 3rd item down the stack is moved to the top.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 3:
        return False
    stack.append(stack.pop(-3))
    return True


def op_swap(stack):
    """Script opcode OP_SWAP: The top two items on the stack are swapped.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 2:
        return False
    stack.append(stack.pop(-2))
    return True


def op_tuck(stack):
    """Script opcode OP_TUCK: The item at the top of the stack is copied and
    inserted before the second-to-top item.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 2:
        return False
    stack.insert(-2, stack[-1])
    return True


def op_size(stack):
    """Script opcode OP_SIZE: Pushes the string length of the top element of
    the stack (without popping it).

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 1:
        return False
    stack.append(encode_num(len(stack[-1])))
    return True


def op_equal(stack):
    """Script opcode OP_EQUAL: Pops top two stack items, pushes 1 if inputs
    are exactly equal, 0 otherwise.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 2:
        return False
    element1 = stack.pop()
    element2 = stack.pop()
    if element1 == element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_equalverify(stack):
    """Script opcode OP_EQUALVERIFY: Same as OP_EQUAL, but runs OP_VERIFY
    afterward.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    return op_equal(stack) and op_verify(stack)


def op_1add(stack):
    """Script opcode OP_1ADD: 1 is added to the value at top of stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 1:
        return False
    element = decode_num(stack.pop())
    stack.append(encode_num(element + 1))
    return True


def op_1sub(stack):
    """Script opcode OP_1SUB: 1 is subtracted from the value at top of stack.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 1:
        return False
    element = decode_num(stack.pop())
    stack.append(encode_num(element - 1))
    return True


def op_negate(stack):
    """Script opcode OP_NEGATE: The sign of the value at top of stack is flipped.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 1:
        return False
    element = decode_num(stack.pop())
    stack.append(encode_num(-element))
    return True


def op_abs(stack):
    """Script opcode OP_ABS: The value at top of stack is made positive.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 1:
        return False
    element = decode_num(stack.pop())
    if element < 0:
        stack.append(encode_num(-element))
    else:
        stack.append(encode_num(element))
    return True


def op_not(stack):
    """Script opcode OP_NOT: If the value at top of stack is 0 or 1, it is
    flipped. Otherwise it will be replaced with 0.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 1:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_0notequal(stack):
    """Script opcode OP_0NOTEQUAL: Top of stack becomes 0 if it already is 0.
    1 otherwise.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 1:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        stack.append(encode_num(0))
    else:
        stack.append(encode_num(1))
    return True


def op_add(stack):
    """Script opcode OP_ADD: Pops top two stack items a and b, pushes sum.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    stack.append(encode_num(element1 + element2))
    return True


def op_sub(stack):
    """Script opcode OP_SUB: Pops top two stack items a and b, pushes b
    subtracted from a.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    stack.append(encode_num(element2 - element1))
    return True


def op_booland(stack):
    """Script opcode OP_BOOLAND: Pops top two stack items a and b. If both a
    and b are not 0, pushes 1; otherwise 0.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 and element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_boolor(stack):
    """Script opcode OP_BOOLOR: Pops top two stack items a and b. If a or b is
    not 0, pushes 1; otherwise 0.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 or element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_numequal(stack):
    """Script opcode OP_NUMEQUAL: Pops top two stack items a and b. If a equals
    b, pushes 1; otherwise 0.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 == element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_numequalverify(stack):
    """Script opcode OP_NUMEQUALVERIFY: Same as OP_NUMEQUAL, but runs OP_VERIFY
    afterward.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    return op_numequal(stack) and op_verify(stack)


def op_numnotequal(stack):
    """Script opcode OP_NUMNOTEQUAL: Pops top two stack items a and b. If a does
    not equal b, pushes 1; otherwise 0.


    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 == element2:
        stack.append(encode_num(0))
    else:
        stack.append(encode_num(1))
    return True


def op_lessthan(stack):
    """Script opcode OP_LESSTHAN: Pops top two stack items a and b. If a is
    less than b, pushes 1; otherwise 0.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element2 < element1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_greaterthan(stack):
    """Script opcode OP_GREATERTHAN: Pops top two stack items a and b. If a is
    greater than b, pushes 1; otherwise 0.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element2 > element1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_lessthanorequal(stack):
    """Script opcode OP_LESSTHANOREQUAL: Pops top two stack items a and b. If a
    is less than or equal b, pushes 1; otherwise 0.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element2 <= element1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_greaterthanorequal(stack):
    """Script opcode OP_GREATERTHANOREQUAL: Pops top two stack items a and b.
    If a is greater than or equal to b, pushes 1; otherwise 0.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element2 >= element1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_min(stack):
    """Script opcode OP_MIN: Pops top two stack items a and b, pushes the
    smaller of a and b.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 < element2:
        stack.append(encode_num(element1))
    else:
        stack.append(encode_num(element2))
    return True


def op_max(stack):
    """Script opcode OP_MAX: Pops top two stack items a and b, pushes the
    larger of a and b.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 > element2:
        stack.append(encode_num(element1))
    else:
        stack.append(encode_num(element2))
    return True


def op_within(stack):
    """Script opcode OP_WITHIN: Pops top three stack items a, b and c; pushes
    1 if c is within the specified range [a:b) (left-inclusive), 0 otherwise.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 3:
        return False
    maximum = decode_num(stack.pop())
    minimum = decode_num(stack.pop())
    element = decode_num(stack.pop())
    if element >= minimum and element < maximum:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_ripemd160(stack):
    """Script opcode OP_RIPEMD160: Pops top stack element, pushes element
    hashed using RIPEMD-160.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.new('ripemd160', element).digest())
    return True


def op_sha1(stack):
    """Script opcode OP_SHA1: Pops top stack element, pushes element hashed
    using SHA-1.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.sha1(element).digest())
    return True


def op_sha256(stack):
    """Script opcode OP_SHA256: Pops top stack element, pushes element hashed
    using SHA-256.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.sha256(element).digest())
    return True


def op_hash160(stack):
    """Script opcode OP_HASH160: The input is hashed twice: first with SHA-256
    and then with RIPEMD-160.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hash160(element))
    return True


def op_hash256(stack):
    """Script opcode OP_HASH256: Pops top stack element, pushes element hashed
    two times with SHA-256.

    Args:
        stack (deque): Script execution stack

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hash256(element))
    return True


def op_checksig(stack, z):
    """Script opcode OP_CHECKSIG: Verifies signature with public key, pushes 1
    if valid, 0 otherwise.

    TBD: Does not hash transaction, relies on signature hash passed in to
    Script.evaluate. Song's version does not use Script code separator.

    Bitcoin Core OP_CHECKSIG: The entire transaction's outputs, inputs, and
    script (from the most recently-executed OP_CODESEPARATOR to the end) are
    hashed. The signature used by OP_CHECKSIG must be a valid signature for
    this hash and public key. If it is, 1 is returned, 0 otherwise.

    Bitoin Core OP_CODESEPARATOR: All of the signature checking words will
    only match signatures to the data after the most recently-executed
    OP_CODESEPARATOR.

    Args:
        stack (deque): Script execution stack
            z (int):  32-byte sha256 hash of the message that was signed

    Returns:
        bool: True on success, False on failure

    """
    if len(stack) < 2:
        return False
    sec = stack.pop()
    # take off the last byte of the signature as that's the hash_type
    # TBD: why remove last byte? Not mentioned in DER format
    der = stack.pop()[:-1]
    try:
        pubkey = S256Point.parse(sec)
        sig = Signature.parse(der)
    except (ValueError, SyntaxError) as e:
        LOGGER.info(e)
        return False
    # TBD: establish when and where the signature hash is converted to int
    stack.append(encode_num(1 if pubkey.verify(z, sig) else 0))
    return True


def op_checksigverify(stack, z):
    """Script opcode OP_CHECKSIGVERIFY: Same as OP_CHECKSIG, but OP_VERIFY is
    executed afterward.

    Args:
        stack (deque): Script execution stack
            z (int):  32-byte sha256 hash of the message that was signed

    Returns:
        bool: True on success, False on failure

    """
    return op_checksig(stack, z) and op_verify(stack)


def op_checkmultisig(stack, z):
    """Script opcode OP_CHECKMULTISIG: TBD: update description after ch13 SegWit

    Bitcoin Core OP_CHECKMULTISIG description: Compares the first signature
    against each public key until it finds an ECDSA match. Starting with the
    subsequent public key, it compares the second signature against each
    remaining public key until it finds an ECDSA match. The process is repeated
    until all signatures have been checked or not enough public keys remain to
    produce a successful result. All signatures need to match a public key.
    Because public keys are not checked again if they fail any signature
    comparison, signatures must be placed in the scriptSig using the same
    order as their corresponding public keys were placed in the scriptPubKey
    or redeemScript. If all signatures are valid, 1 is returned, 0 otherwise.
    Due to a bug, one extra unused value is removed from the stack.

    Args:
        stack (deque): Script execution stack
            z (int):  32-byte sha256 hash of the message that was signed

    Returns:
        bool: True on success, False on failure

    """
    # TBD: ch13 SegWit
    raise NotImplementedError


def op_checkmultisigverify(stack, z):
    """Script opcode OP_CHECKMULTISIGVERIFY: Same as OP_CHECKMULTISIG,
    but OP_VERIFY is executed afterward.

    Args:
        stack (deque): Script execution stack
            z (int):  32-byte sha256 hash of the message that was signed

    Returns:
        bool: True on success, False on failure

    """
    return op_checkmultisig(stack, z) and op_verify(stack)


def op_checklocktimeverify(stack, locktime, sequence):
    """Script opcode OP_CHECKLOCKTIMEVERIFY (previously OP_NOP2): Checks top
    stack item against locktime and sequence.

    Notes: Marks transaction as invalid if the top stack item is greater than
    the transaction's nLockTime field, otherwise script evaluation continues
    as though an OP_NOP was executed. Transaction is also invalid if:
        1. the stack is empty
        2. the top stack item is negative
        3. the top stack item is greater than or equal to 500000000 while the
            transaction's nLockTime field is less than 500000000, or vice
            versa;
        4. the input's nSequence field is equal to 0xffffffff. The precise
            semantics are described in BIP0065.

    Args:
        stack (deque): Script execution stack
        locktime (int): time delay on when transaction enters the blockchain:
            locktimes of less than 500,000,000 are a block number, higher are
            a UNIX timestamp
        sequence (int): value associated with a transaction when referenced as
            an input to another transaction, originally meant for duties now
            covered by Lightning Network payment channels, repurposed for use
            by OP_CHECKCLOCKTIMEVERIFY and OP_CHECKSEQUENCEVERIFY

    Returns:
        bool: True on success, False on failure

    """
    # TBD: reconcile code with BIP0065 instructions in docstring
    if sequence == 0xffffffff:
        return False
    if len(stack) < 1:
        return False
    element = decode_num(stack[-1])
    if element < 0:
        return False
    if element < 500000000 and locktime > 500000000:
        return False
    if locktime < element:
        return False
    return True


def op_checksequenceverify(stack, version, sequence):
    """Script opcode OP_CHECKSEQUENCEVERIFY (previously OP_NOP3): Validates
    transaction based on certain requirements of the sequence value.

    Marks transaction as invalid if the relative lock time of the input
    (enforced by BIP0068 with nSequence) is not equal to or longer than the
    value of the top stack item. The precise semantics are described in
    BIP0112.

    Args:
        stack (deque): Script execution stack
        version (int): must be 2 or above to validate transaction with this op
        sequence (int): value associated with a transaction when referenced as
            an input to another transaction, originally meant for duties now
            covered by Lightning Network payment channels, repurposed for use
            by OP_CHECKCLOCKTIMEVERIFY and OP_CHECKSEQUENCEVERIFY

    Returns:
        bool: True on success, False on failure

    """
    if sequence & (1 << 31) == (1 << 31):
        return False
    if len(stack) < 1:
        return False
    element = decode_num(stack[-1])
    if element < 0:
        return False
    if element & (1 << 31) == (1 << 31):
        if version < 2:
            return False
        elif sequence & (1 << 31) == (1 << 31):
            return False
        elif element & (1 << 22) != sequence & (1 << 22):
            return False
        elif element & 0xffff > sequence & 0xffff:
            return False
    return True


OP_CODE_FUNCTIONS = {
    0: op_0,
    # 1-75: <no name>    # indicates following n bytes are data element
    # 76: op_pushdata1,  # implemented in Script.parse/.serialize
    # 77: op_pushdata2,  # implemented in Script.parse/.serialize
    # 78: op_pushdata4,  # can be ignored; current max element byte length 520
    79: op_1negate,
    81: op_1,
    82: op_2,
    83: op_3,
    84: op_4,
    85: op_5,
    86: op_6,
    87: op_7,
    88: op_8,
    89: op_9,
    90: op_10,
    91: op_11,
    92: op_12,
    93: op_13,
    94: op_14,
    95: op_15,
    96: op_16,
    97: op_nop,
    99: op_if,
    100: op_notif,
    # 103: op_else,   # implemented in op_if and op_notif
    # 104: op_endif,  # implemented in op_if and op_notif
    105: op_verify,
    106: op_return,
    107: op_toaltstack,
    108: op_fromaltstack,
    109: op_2drop,
    110: op_2dup,
    111: op_3dup,
    112: op_2over,
    113: op_2rot,
    114: op_2swap,
    115: op_ifdup,
    116: op_depth,
    117: op_drop,
    118: op_dup,
    119: op_nip,
    120: op_over,
    121: op_pick,
    122: op_roll,
    123: op_rot,
    124: op_swap,
    125: op_tuck,
    # 126: op_cat,     # disabled
    # 127: op_substr,  # disabled
    # 128: op_left,    # disabled
    # 129: op_right,   # disabled
    130: op_size,
    # 131: op_invert,  # disabled
    # 132: op_and,     # disabled
    # 133: op_or,      # disabled
    # 134: op_xor,     # disabled
    135: op_equal,
    136: op_equalverify,
    139: op_1add,
    140: op_1sub,
    # 141: op_2mul,    # disabled
    # 142: op_2div,    # disabled
    143: op_negate,
    144: op_abs,
    145: op_not,
    146: op_0notequal,
    147: op_add,
    148: op_sub,
    # 149: op_mul,     # disabled
    # 150: op_div,     # disabled
    # 151: op_mod,     # disabled
    # 152: op_lshift,  # disabled
    # 153: op_rshift,  # disabled
    154: op_booland,
    155: op_boolor,
    156: op_numequal,
    157: op_numequalverify,
    158: op_numnotequal,
    159: op_lessthan,
    160: op_greaterthan,
    161: op_lessthanorequal,
    162: op_greaterthanorequal,
    163: op_min,
    164: op_max,
    165: op_within,
    166: op_ripemd160,
    167: op_sha1,
    168: op_sha256,
    169: op_hash160,
    170: op_hash256,
    # 171: op_codeseparator,  # TBD: skipped by Song, build into op_checksig?
    172: op_checksig,
    173: op_checksigverify,
    174: op_checkmultisig,
    175: op_checkmultisigverify,
    176: op_nop,
    177: op_checklocktimeverify,
    178: op_checksequenceverify,
    179: op_nop,
    180: op_nop,
    181: op_nop,
    182: op_nop,
    183: op_nop,
    184: op_nop,
    185: op_nop,
}

OP_CODE_NAMES = {
    #
    # Constant opcodes: 0-96
    #
    0: 'OP_0',           # aka OP_FALSE
    # 1-75: <no name>    # indicates following n bytes are data element
    76: 'OP_PUSHDATA1',  # implemented in Script.parse/.serialize
    77: 'OP_PUSHDATA2',  # implemented in Script.parse/.serialize
    78: 'OP_PUSHDATA4',  # unimplemented, as current max element length is 520B
    79: 'OP_1NEGATE',
    80: 'OP_RESERVED',   # reserved
    81: 'OP_1',          # aka OP_TRUE
    82: 'OP_2',
    83: 'OP_3',
    84: 'OP_4',
    85: 'OP_5',
    86: 'OP_6',
    87: 'OP_7',
    88: 'OP_8',
    89: 'OP_9',
    90: 'OP_10',
    91: 'OP_11',
    92: 'OP_12',
    93: 'OP_13',
    94: 'OP_14',
    95: 'OP_15',
    96: 'OP_16',
    #
    # Flow control opcodes: 97-106
    #
    97: 'OP_NOP',
    98: 'OP_VER',         # reserved
    99: 'OP_IF',
    100: 'OP_NOTIF',
    101: 'OP_VERIF',      # reserved
    102: 'OP_VERNOTIF',   # reserved
    103: 'OP_ELSE',       # implemented in op_if and op_notif
    104: 'OP_ENDIF',      # implemented in op_if and op_notif
    105: 'OP_VERIFY',
    106: 'OP_RETURN',
    #
    # Stack manipulation opcodes: 107-125
    #
    107: 'OP_TOALTSTACK',
    108: 'OP_FROMALTSTACK',
    109: 'OP_2DROP',
    110: 'OP_2DUP',
    111: 'OP_3DUP',
    112: 'OP_2OVER',
    113: 'OP_2ROT',
    114: 'OP_2SWAP',
    115: 'OP_IFDUP',
    116: 'OP_DEPTH',
    117: 'OP_DROP',
    118: 'OP_DUP',
    119: 'OP_NIP',
    120: 'OP_OVER',
    121: 'OP_PICK',
    122: 'OP_ROLL',
    123: 'OP_ROT',
    124: 'OP_SWAP',
    125: 'OP_TUCK',
    #
    # Splice opcodes: 126-130
    #
    126: 'OP_CAT',       # disabled
    127: 'OP_SUBSTR',    # disabled
    128: 'OP_LEFT',      # disabled
    129: 'OP_RIGHT',     # disabled
    130: 'OP_SIZE',
    #
    # Bitwse logic opcodes: 131-136
    #
    131: 'OP_INVERT',    # disabled
    132: 'OP_AND',       # disabled
    133: 'OP_OR',        # disabled
    134: 'OP_XOR',       # disabled
    135: 'OP_EQUAL',
    136: 'OP_EQUALVERIFY',
    137: 'OP_RESERVED1', # reserved
    138: 'OP_RESERVED2', # reserved
    #
    # Arithmetic opcodes: 139-165
    #     Note: In the real Bitcoin Core, Script arithmetic inputs larger than
    #     4 bytes (signed int) cause the script to abort and fail. Given
    #     Python's implementation of ints, this limitation is removed here.
    #     TBD: Should it be simulated with a caps at INT_MIN and INT_MAX?
    #
    139: 'OP_1ADD',
    140: 'OP_1SUB',
    141: 'OP_2MUL',      # disabled
    142: 'OP_2DIV',      # disabled
    143: 'OP_NEGATE',
    144: 'OP_ABS',
    145: 'OP_NOT',
    146: 'OP_0NOTEQUAL',
    147: 'OP_ADD',
    148: 'OP_SUB',
    149: 'OP_MUL',       # disabled
    150: 'OP_DIV',       # disabled
    151: 'OP_MOD',       # disabled
    152: 'OP_LSHIFT',    # disabled
    153: 'OP_RHIFT',     # disabled
    154: 'OP_BOOLAND',
    155: 'OP_BOOLOR',
    156: 'OP_NUMEQUAL',
    157: 'OP_NUMEQUALVERIFY',
    158: 'OP_NUMNOTEQUAL',
    159: 'OP_LESSTHAN',
    160: 'OP_GREATERTHAN',
    161: 'OP_LESSTHANOREQUAL',
    162: 'OP_GREATERTHANOREQUAL',
    163: 'OP_MIN',
    164: 'OP_MAX',
    165: 'OP_WITHIN',
    #
    # Crypto opcodes: 166-175
    #
    166: 'OP_RIPEMD160',
    167: 'OP_SHA1',
    168: 'OP_SHA256',
    169: 'OP_HASH160',
    170: 'OP_HASH256',
    171: 'OP_CODESEPARATOR',  # TBD: skipped by Song, build into op_checksig?
    172: 'OP_CHECKSIG',
    173: 'OP_CHECKSIGVERIFY',
    174: 'OP_CHECKMULTISIG',
    175: 'OP_CHECKMULTISIGVERIFY',
    #
    176: 'OP_NOP1',
    #
    # Locktime opcodes: 177-178
    #
    177: 'OP_CHECKLOCKTIMEVERIFY',
    178: 'OP_CHECKSEQUENCEVERIFY',
    #
    179: 'OP_NOP4',
    180: 'OP_NOP5',
    181: 'OP_NOP6',
    182: 'OP_NOP7',
    183: 'OP_NOP8',
    184: 'OP_NOP9',
    185: 'OP_NOP10',
}
