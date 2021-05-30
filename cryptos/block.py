"""
The Block object in Bitcoin
Reference:
- https://en.bitcoin.it/wiki/Block
- https://en.bitcoin.it/wiki/Block_hashing_algorithm
"""

from __future__ import annotations # PEP 563: Postponed Evaluation of Annotations
from dataclasses import dataclass
from typing import Dict, List, Tuple, Union

from .sha256 import sha256

# -----------------------------------------------------------------------------
# Block headers, 80 bytes
GENESIS_BLOCK = {
    'main': bytes.fromhex('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c'),
    'test': bytes.fromhex('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18'),
}
# -----------------------------------------------------------------------------
# helper functions

def decode_int(s, nbytes, encoding='little'):
    return int.from_bytes(s.read(nbytes), encoding)

def encode_int(i, nbytes, encoding='little'):
    return i.to_bytes(nbytes, encoding)

def bits_to_target(bits):
    exponent = bits[-1]
    coeff = int.from_bytes(bits[:-1], 'little')
    target = coeff * 256**(exponent - 3)
    return target

def target_to_bits(target):
    b = target.to_bytes(32, 'big')
    b = b.lstrip(b'\x00')
    if b[0] >= 128:
        # leading bit is a 1, which would interpret this as negative number
        # shift everything over by 1 byte because for us target is always positive
        exponent = len(b) + 1 # how long the number is in base 256
        coeff = b'\x00' + b[:2] # first three digits of the base 256 number
    else:
        exponent = len(b)
        coeff = b[:3]
    # encode coeff in little endian and exponent is at the end
    new_bits = coeff[::-1] + bytes([exponent])
    return new_bits

def calculate_new_bits(prev_bits, dt):
    two_weeks = 60*60*24*14 # number of seconds in two week period
    dt = max(min(dt, two_weeks*4), two_weeks//4)
    prev_target = bits_to_target(prev_bits)
    new_target = int(prev_target * dt / two_weeks)
    new_target = min(new_target, 0xffff * 256**(0x1d - 3)) # cap maximum target
    new_bits = target_to_bits(new_target)
    return new_bits

# -----------------------------------------------------------------------------

@dataclass
class Block:
    version: int        # 4 bytes little endian
    prev_block: bytes   # 32 bytes, little endian
    merkle_root: bytes  # 32 bytes, little endian
    timestamp: int      # uint32, seconds since 1970-01-01T00:00 UTC
    bits: bytes         # 4 bytes, current target in compact format
    nonce: bytes        # 4 bytes, searched over in pow

    @classmethod
    def decode(cls, s) -> Block:
        version = decode_int(s, 4)
        prev_block = s.read(32)[::-1]
        merkle_root = s.read(32)[::-1]
        timestamp = decode_int(s, 4)
        bits = s.read(4)
        nonce = s.read(4)
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)

    def encode(self) -> bytes:
        out = []
        out += [encode_int(self.version, 4)]
        out += [self.prev_block[::-1]]
        out += [self.merkle_root[::-1]]
        out += [encode_int(self.timestamp, 4)]
        out += [self.bits]
        out += [self.nonce]
        return b''.join(out)

    def id(self) -> str:
        return sha256(sha256(self.encode()))[::-1].hex()

    def target(self) -> int:
        return bits_to_target(self.bits)

    def difficulty(self) -> float:
        genesis_block_target = 0xffff * 256**(0x1d - 3)
        diff = genesis_block_target / self.target()
        return diff

    def validate(self) -> bool:
        """ validate this block """
        # 1) validate bits (target) field (todo)
        # 2) validate proof of work
        if int(self.id(), 16) >= self.target():
            return False
        # if everything passes the block is good
        return True
