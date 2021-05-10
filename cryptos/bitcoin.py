"""
Bitcoin-specific functions, classes, utilities and parameters
"""

from dataclasses import dataclass
from .curves import Curve, Point, Generator

# -----------------------------------------------------------------------------
# public API
__all__ = ['BITCOIN']

# -----------------------------------------------------------------------------

@dataclass
class Coin:
    gen: Generator

# -----------------------------------------------------------------------------

def bitcoin_gen():
    # Bitcoin uses secp256k1: http://www.oid-info.com/get/1.3.132.0.10
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a = 0x0000000000000000000000000000000000000000000000000000000000000000
    b = 0x0000000000000000000000000000000000000000000000000000000000000007
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    curve = Curve(p, a, b)
    G = Point(curve, Gx, Gy)
    gen = Generator(G, n)
    return gen

# create an object that can be imported from other modules
BITCOIN = Coin(bitcoin_gen())
