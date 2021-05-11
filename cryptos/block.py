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
# helper functions

def decode_int(s, nbytes, encoding='little'):
    return int.from_bytes(s.read(nbytes), encoding)

def encode_int(i, nbytes, encoding='little'):
    return i.to_bytes(nbytes, encoding)
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
        exponent = self.bits[-1]
        coeff = int.from_bytes(self.bits[:-1], 'little')
        target = coeff * 256**(exponent - 3)
        return target

    def difficulty(self) -> float:
        genesis_block_target = 0xffff * 256**(0x1d - 3)
        diff = genesis_block_target / self.target()
        return diff
