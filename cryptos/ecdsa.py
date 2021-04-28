"""
Elliptic Curve Digital Signature Algorithm (ECDSA)
Functions that sign/verify digital signatures and related utilities
"""

from dataclasses import dataclass

from .sha256 import sha256
from cryptos.curves import bitcoin_gen, inv, Point
from cryptos.keys import gen_private_key, sk_to_pk
# -----------------------------------------------------------------------------

@dataclass
class Signature:
    r: int
    s: int

def sign(private_key: int, message: bytes) -> Signature:

    gen = bitcoin_gen()
    n = gen.n

    # hash the message and convert to integer
    # TODO: do we want to do this here? or outside? probably not here
    z = int.from_bytes(sha256(message), 'big')

    # generate a new private/public key pair at random
    # TODO: make deterministic
    # TODO: make take constant time to mitigate timing attacks
    k = gen_private_key(n, 'os')
    P = sk_to_pk(k)

    # calculate the signature
    r = P.x
    s = inv(k, n) * (z + private_key * r) % n

    sig = Signature(r, s)
    return sig

def verify(public_key: Point, message: bytes, sig: Signature) -> bool:

    gen = bitcoin_gen()
    n = gen.n

    # some super basic verification
    assert isinstance(sig.r, int) and 1 <= sig.r < n
    assert isinstance(sig.s, int) and 1 <= sig.s < n

    # hash the message and convert to integer
    z = int.from_bytes(sha256(message), 'big')

    # verify signature
    w = inv(sig.s, n)
    u1 = z * w % n
    u2 = sig.r * w % n
    P = (u1 * gen.G) + (u2 * public_key)
    match = P.x == sig.r

    return match
