#!/usr/bin/env python3
# -*- coding: utf-8 -*-

SHUFFLE = [
    0x02, 0x06, 0x07, 0x01, 0x05, 0x0b, 0x09, 0x0e,
    0x03, 0x0f, 0x04, 0x08, 0x0a, 0x0c, 0x0d, 0x00,
]

ADD32 = [
    0xef, 0xbe, 0xad, 0xde, 0xad, 0xde, 0xe1, 0xfe,
    0x37, 0x13, 0x37, 0x13, 0x66, 0x74, 0x63, 0x67,
]

XOR = [
    0x76, 0x58, 0xb4, 0x49, 0x8d, 0x1a, 0x5f, 0x38,
    0xd4, 0x23, 0xf8, 0x34, 0xeb, 0x86, 0xf9, 0xaa,
]

EXPECTED_PREFIX = b"CTF{"
PLACEHOLDER = -1


def simd_op(flag: list, i: int) -> (bool, bytes):
    # This is essentially the pxor(paddd(pshufb(flag))) operation from the original program.
    # See reimpl.py for details, although keep in mind that this operates on single bytes
    # rather than the full 32 bits. This means, an additional fixup step will be necessary
    # to produce correct data in the end whenever a byte crosses the 8-bit boundary.
    # The boolean value returned by the function indicates whenever that happens.
    if flag[i] == PLACEHOLDER and flag[SHUFFLE[i]] != PLACEHOLDER:
        sum = flag[SHUFFLE[i]] + ADD32[i]
        return (sum > 0xFF, (sum & 0xFF) ^ XOR[i])
    else:
        return (False, flag[i])


def build_flag(flag: list) -> bytes:
    # We start with 4 known characters, 16 characters are expected.
    # 4 repetitions of the algorithm are sufficient to cover all of them.
    for _ in range(4):

        for i in range(16):
            fixup_needed, result = simd_op(flag, i)

            # If a fixup is needed, increment the next value in the ADD32 table so that
            # the arithmetic carry is evened out.
            if fixup_needed:
                ADD32[i + 1] += 1

            # Overwrite the byte at the current position with the computed SIMD result.
            flag[i] = result

    return flag


# Build the flag starting with the "CTF{" prefix, followed by -1 values as
# unique placeholders for all empty values (since bytes are always unsigned).
flag = build_flag([i for i in EXPECTED_PREFIX] + [PLACEHOLDER] * (16 - len(EXPECTED_PREFIX)))
print("Flag:", "".join(map(chr, flag)))
