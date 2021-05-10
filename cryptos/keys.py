"""
Utilities to generate secret/public key pairs and Bitcoin address
(note: using "secret" instead of "private" so that sk and pk are
easy consistent shortcuts of the two without collision)
"""

import os
import time

from .curves import Point
from .bitcoin import BITCOIN

# -----------------------------------------------------------------------------
# Secret key generation. We're going to leave secret key as just a super plain int

def gen_secret_key(n: int) -> int:
    """
    n is the upper bound on the key, typically the order of the elliptic curve
    we are using. The function will return a valid key, i.e. 1 <= key < n.
    """
    while True:
        key = int.from_bytes(os.urandom(32), 'big')
        if 1 <= key < n:
            break # the key is valid, break out
    return key

# -----------------------------------------------------------------------------
# Public key - specific functions, esp encoding / decoding

class PublicKey(Point):
    """
    The public key is just a Point on a Curve, but has some additional specific
    encoding / decoding functionality that this class implements.
    """

    @classmethod
    def from_point(cls, pt: Point):
        """ promote a Point to be a PublicKey """
        return cls(pt.curve, pt.x, pt.y)

    @classmethod
    def from_sk(cls, sk):
        """ sk can be an int or a hex string """
        assert isinstance(sk, (int, str))
        sk = int(sk, 16) if isinstance(sk, str) else sk
        pk = sk * BITCOIN.gen.G
        return cls.from_point(pk)

    @classmethod
    def decode(cls, b: bytes):
        """ decode from the SEC binary format """
        assert isinstance(b, bytes)

        # the uncompressed version is straight forward
        if b[0] == 4:
            x = int.from_bytes(b[1:33], 'big')
            y = int.from_bytes(b[33:65], 'big')
            return Point(BITCOIN.gen.G.curve, x, y)

        # for compressed version uncompress the full public key Point
        # first recover the y-evenness and the full x
        assert b[0] in [2, 3]
        is_even = b[0] == 2
        x = int.from_bytes(b[1:], 'big')

        # solve y^2 = x^3 + 7 for y, but mod p
        p = BITCOIN.gen.G.curve.p
        y2 = (pow(x, 3, p) + 7) % p
        y = pow(y2, (p + 1) // 4, p)
        y = y if ((y % 2 == 0) == is_even) else p - y # flip if needed to make the evenness agree
        return cls(BITCOIN.gen.G.curve, x, y)

    def encode(self, compressed=True):
        """ return the SEC bytes encoding of the public key Point """
        if compressed:
            prefix = b'\x02' if self.y % 2 == 0 else b'\x03'
            return prefix + self.x.to_bytes(32, 'big')
        else:
            return b'\x04' + self.x.to_bytes(32, 'big') + self.y.to_bytes(32, 'big')
