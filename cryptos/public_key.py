"""
Function to generate a public key from a private key
"""

INF = (None, None)

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

class EllipticCurveModP:

    def __init__(self, p, r, a, b):
        # note only p, a are actually used in the math we care about so far
        self.p = p
        self.r = r
        self.a = a
        self.b = b

    def add(self, P, Q):
        # unpack P,Q into its x,y components
        px, py = P
        qx, qy = Q
        # handle special case of P + 0 = 0 + P = 0
        if P == INF:
            return Q
        if Q == INF:
            return P
        # handle special case of P + (-P) = 0
        if qx == px and qy != py:
            return INF
        # compute the "slope"
        if qx == px: # we must also have qy == py since this was checked right above, so P=Q
            m = (3 * px**2 + self.a) * inv(2 * py, self.p)
        else:
            m = (py - qy) * inv(px - qx, self.p)
        # calculate the (reflected) intersection on the curve
        rx = (m**2 - px - qx) % self.p
        ry = (-(m*(rx - px) + py)) % self.p
        return (rx, ry)

    def mul(self, k, P):
        # return k*P for a scalar k
        assert isinstance(k, int) and k >= 0
        result = INF
        append = P
        while k:
            if k&1 == 1:
                result = self.add(result, append)
            append = self.add(append, append)
            k >>= 1
        return result

def gen_bitcoin_curve():

    # the elliptic curve used in Bitcoin
    # secp256k1, http://www.oid-info.com/get/1.3.132.0.10
    _p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    _r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    _b = 0x0000000000000000000000000000000000000000000000000000000000000007
    _a = 0x0000000000000000000000000000000000000000000000000000000000000000
    _Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    _Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

    curve = EllipticCurveModP(_p, _r, _a, _b)
    G = (_Gx, _Gy)
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
    public_key = curve.mul(private_key, G)

    # print the public key point on the curve
    x, y = public_key
    print('x:', format(x, '064x').upper()) # (strip the 0x part denoting hex number)
    print('y:', format(y, '064x').upper())
