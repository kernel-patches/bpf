#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Script that generates known-good data used in the KUnit tests for
# length-preserving symmetric ciphers.
#
# Requires that python-cryptography be installed.
#
# Copyright 2026 Google LLC

import hashlib
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_BLOCK_SIZE = 16


# Linear congruential generator matching rand32() in
# lib/crypto/tests/test-utils.h
class Rng:
    def __init__(self, seed):
        self.seed = seed

    def rand_bytes(self, length):
        out = []
        for _ in range(length):
            self.seed = (self.seed * 25214903917 + 11) % 2**48
            out.append((self.seed >> 16) % 256)
        return bytes(out)


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def aes_encrypt_with_mode(key, mode, data):
    encryptor = Cipher(algorithms.AES(key), mode).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def aes_ecb_encrypt(key, ptext):
    return aes_encrypt_with_mode(key, modes.ECB(), ptext)


def aes_cbc_encrypt(key, iv, ptext):
    return aes_encrypt_with_mode(key, modes.CBC(iv), ptext)


# AES-CBC-CTS, CS3 variant (i.e., the last two blocks are always swapped)
def aes_cbc_cts_encrypt(key, iv, ptext):
    data_len = len(ptext)
    assert data_len >= AES_BLOCK_SIZE
    padded_len = -(-data_len // AES_BLOCK_SIZE) * AES_BLOCK_SIZE
    ctext = aes_cbc_encrypt(key, iv, ptext.ljust(padded_len, b"\0"))
    if padded_len == AES_BLOCK_SIZE:
        return ctext
    pn_len = data_len - (padded_len - AES_BLOCK_SIZE)
    return (
        ctext[: padded_len - 2 * AES_BLOCK_SIZE]
        + ctext[padded_len - AES_BLOCK_SIZE :]
        + ctext[padded_len - 2 * AES_BLOCK_SIZE :][:pn_len]
    )


# AES-CTR with a 128-bit big endian counter
def aes_ctr_crypt(key, ctr, data):
    return aes_encrypt_with_mode(key, modes.CTR(ctr), data)


# AES-XCTR.  For consistency with the kernel tests, 'state' is the 64-bit little
# endian block counter followed by the 16-byte IV.
def aes_xctr_crypt(key, state, data):
    ctr = int.from_bytes(state[:8], byteorder="little")
    iv = state[8:]
    out = b""
    for i in range(0, len(data), AES_BLOCK_SIZE):
        ctr_block = ctr.to_bytes(8, byteorder="little") + bytes(8)
        keystream = aes_ecb_encrypt(key, xor(iv, ctr_block))
        out += xor(data[i : i + AES_BLOCK_SIZE], keystream)
        ctr = (ctr + 1) % 2**64
    return out


# AES-XTS, implemented manually since python-cryptography doesn't support
# AES-192-XTS.  Includes ciphertext stealing.
def aes_xts_encrypt_manual(key, tweak, ptext):
    assert len(ptext) >= AES_BLOCK_SIZE
    key1, key2 = key[: len(key) // 2], key[len(key) // 2 :]
    t = int.from_bytes(aes_ecb_encrypt(key2, tweak), byteorder="little")
    num_full_blocks = len(ptext) // AES_BLOCK_SIZE
    partial_len = len(ptext) % AES_BLOCK_SIZE

    def encrypt_block(block, t):
        t_bytes = t.to_bytes(AES_BLOCK_SIZE, byteorder="little")
        return xor(aes_ecb_encrypt(key1, xor(block, t_bytes)), t_bytes)

    def mul_x(t):
        t <<= 1
        if t >> 128:
            t = (t & (2**128 - 1)) ^ 0x87
        return t

    out = b""
    for i in range(num_full_blocks):
        out += encrypt_block(ptext[i * AES_BLOCK_SIZE :][:AES_BLOCK_SIZE], t)
        t = mul_x(t)
    if partial_len:
        cc = out[-AES_BLOCK_SIZE:]
        pp = ptext[num_full_blocks * AES_BLOCK_SIZE :] + cc[partial_len:]
        out = out[:-AES_BLOCK_SIZE] + encrypt_block(pp, t) + cc[:partial_len]
    return out


def aes_xts_encrypt(key, tweak, ptext):
    ctext = aes_xts_encrypt_manual(key, tweak, ptext)
    # Cross-check against python-cryptography where possible.  It supports
    # neither AES-192-XTS nor keys whose two halves are the same.
    if len(key) != 48 and key[: len(key) // 2] != key[len(key) // 2 :]:
        assert ctext == aes_encrypt_with_mode(key, modes.XTS(tweak), ptext)
    return ctext


# For each mode: (encryption function, valid key lengths, IV state size,
# minimum data length, data length alignment).  These must match the values
# used by the corresponding test in lib/crypto/tests/.
MODES = {
    "aes-ecb": (lambda k, iv, p: aes_ecb_encrypt(k, p), [16, 24, 32], 0, 0, 16),
    "aes-cbc": (aes_cbc_encrypt, [16, 24, 32], 16, 0, 16),
    "aes-cbc-cts": (aes_cbc_cts_encrypt, [16, 24, 32], 16, 16, 1),
    "aes-ctr": (aes_ctr_crypt, [16, 24, 32], 16, 0, 1),
    "aes-xctr": (aes_xctr_crypt, [16, 24, 32], 24, 0, 1),
    "aes-xts": (aes_xts_encrypt, [32, 48, 64], 16, 16, 1),
}


# Deterministically generate many different inputs using exactly the same
# method that test_skcipher_monte_carlo() uses; encrypt them using an
# independent implementation of the algorithm; compute the checksum of all the
# resulting ciphertexts concatenated to each other; and print the checksum as a
# C array.
def gen_monte_carlo_checksum(alg):
    encrypt, key_lens, iv_size, min_data_len, data_len_align = MODES[alg]
    blake2s = hashlib.blake2s()
    for data_len in range(1025):
        if data_len < min_data_len or data_len % data_len_align != 0:
            continue
        rng = Rng(data_len)
        key_len = key_lens[(data_len // data_len_align) % len(key_lens)]
        key = rng.rand_bytes(key_len)
        iv = rng.rand_bytes(iv_size)
        ptext = rng.rand_bytes(data_len)
        blake2s.update(encrypt(key, iv, ptext))

    name = f"{alg.replace('-', '_')}_monte_carlo_checksum"
    value = blake2s.digest()
    print(f"static const u8 {name}[BLAKE2S_HASH_SIZE] = {{")
    for i in range(0, len(value), 11):
        line = "\t" + "".join(f"0x{b:02x}, " for b in value[i : i + 11])
        print(f"{line.rstrip()}")
    print("};")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in MODES:
        sys.stderr.write(f"Usage: gen-skcipher-testvecs.py [{'|'.join(MODES)}]\n")
        sys.exit(1)
    gen_monte_carlo_checksum(sys.argv[1])
