#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from struct import pack, unpack

SHUFFLE = [
    0x02, 0x06, 0x07, 0x01, 0x05, 0x0b, 0x09, 0x0e,
    0x03, 0x0f, 0x04, 0x08, 0x0a, 0x0c, 0x0d, 0x00,
]

ADD32 = bytearray([
    0xef, 0xbe, 0xad, 0xde, 0xad, 0xde, 0xe1, 0xfe,
    0x37, 0x13, 0x37, 0x13, 0x66, 0x74, 0x63, 0x67,
])

XOR = bytearray([
    0x76, 0x58, 0xb4, 0x49, 0x8d, 0x1a, 0x5f, 0x38,
    0xd4, 0x23, 0xf8, 0x34, 0xeb, 0x86, 0xf9, 0xaa,
])

def pshufb(data: bytes) -> bytes:
    assert len(data) == 16 and len(SHUFFLE) == 16
    return bytearray(data[SHUFFLE[i]] for i in range(16))

def paddd(data: bytes) -> bytes:
    assert len(data) == 16 and len(ADD32) == 16

    result = bytearray()
    for i in range(0, 16, 4):
        # The instruction processes data in 32-bit chunks.
        x = unpack("<I", data[i:i + 4])[0]
        y = unpack("<I", ADD32[i:i + 4])[0]

        result.extend(pack("<I", (x + y) & 0xFFFF_FFFF))

    return result

def pxor(data: bytes) -> bytes:
    assert len(data) == 16 and len(ADD32) == 16

    result = bytearray()
    for i in range(0, 16, 4):
        # The instruction processes data in 32-bit chunks.
        x = unpack("<I", data[i:i + 4])[0]
        y = unpack("<I", XOR[i:i + 4])[0]

        result.extend(pack("<I", x ^ y))

    return result


# Read the user input and sanitize it to 15 bytes + a null byte.
user_input_str = input("Flag: ")
user_input = user_input_str[:15].encode() + b"\x00"

# Apply the SIMD algorithm from the binary to it.
simd_result = pxor(paddd(pshufb(user_input)))

print(f"pxor(paddd(pshufb({user_input_str[:15]}))):")
print([i for i in simd_result])
