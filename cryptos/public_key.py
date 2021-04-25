"""
Function to generate a public key from a private key
"""
from dataclasses import dataclass

# -----------------------------------------------------------------------------
def extended_euclidean_algorithm(a, b):
    """
    Returns (gcd, x, y) s.t. a * x + b * y == gcd
    This function implements the extended Euclidean
    algorithm and runs in O(log b) in the worst case,
    taken from Wikipedia.
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t

def inv(n, p):
    """ returns modular multiplicate inverse m s.t. (n * m) % p == 1 """
    gcd, x, y = extended_euclidean_algorithm(n, p)
    return x % p
# -----------------------------------------------------------------------------

@dataclass
class Curve:
    """
    Elliptic Curve over the field of integers modulo a prime.
    Points on the curve satisfy y^2 = x^3 + a*x + b (mod p).
    """
    p: int
    a: int
    b: int

@dataclass
class Point:
    """ An integer point (x,y) on a Curve """
    curve: Curve
    x: int
    y: int

    def __add__(self, other):
        # handle special case of P + 0 = 0 + P = 0
        if self == INF:
            return other
        if other == INF:
            return self
        # handle special case of P + (-P) = 0
        if self.x == other.x and self.y != other.y:
            return INF
        # compute the "slope"
        if self.x == other.x: # (self.y = other.y is guaranteed too per above check)
            m = (3 * self.x**2 + self.curve.a) * inv(2 * self.y, self.curve.p)
        else:
            m = (self.y - other.y) * inv(self.x - other.x, self.curve.p)
        # compute the new point
        rx = (m**2 - self.x - other.x) % self.curve.p
        ry = (-(m*(rx - self.x) + self.y)) % self.curve.p
        return Point(self.curve, rx, ry)

    def __rmul__(self, k):
        assert isinstance(k, int) and k >= 0
        result = INF
        append = self
        while k:
            if k&1 == 1:
                result = result + append
            append = append + append
            k >>= 1
        return result

INF = Point(None, None, None)

def gen_bitcoin_curve():
    # Return the elliptic curve used in Bitcoin and the generator point
    # secp256k1, http://www.oid-info.com/get/1.3.132.0.10
    _p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    _r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    _b = 0x0000000000000000000000000000000000000000000000000000000000000007
    _a = 0x0000000000000000000000000000000000000000000000000000000000000000
    _Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    _Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    curve = Curve(_p, _a, _b)
    G = Point(curve, _Gx, _Gy)
    return curve, G

# -----------------------------------------------------------------------------
if __name__ == '__main__':

    # read a private key from the user
    import sys
    if len(sys.argv) == 2:
        # read a private key from console
        private_key = int(sys.argv[1], 16)
    else:
        # take the private key example from Mastering Bitcoin, Chapter 4
        private_key = int('1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD', 16)

    # round the elliptic curve we go...
    curve, G = gen_bitcoin_curve()
    public_key = private_key * G

    # print the public key point on the curve
    print('x:', format(public_key.x, '064x').upper()) # (strip the 0x part denoting hex number)
    print('y:', format(public_key.y, '064x').upper())
