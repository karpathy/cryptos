"""
Utilities to generate secret/public key pairs and Bitcoin address
(note: using "secret" instead of "private" so that sk and pk are
easy consistent shortcuts of the two without collision)
"""

import os
import time

from .curves import Point
from .bitcoin import BITCOIN
from .sha256 import sha256
from .ripemd160 import ripemd160

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

    def encode(self, compressed, hash160=False):
        """ return the SEC bytes encoding of the public key Point """
        # calculate the bytes
        if compressed:
            prefix = b'\x02' if self.y % 2 == 0 else b'\x03'
            pkb = prefix + self.x.to_bytes(32, 'big')
        else:
            pkb = b'\x04' + self.x.to_bytes(32, 'big') + self.y.to_bytes(32, 'big')
        # hash if desired
        return ripemd160(sha256(pkb)) if hash160 else pkb

    def address(self, net: str, compressed: bool) -> str:
        """ return the associated bitcoin address for this public key as string """
        # encode the public key into bytes and hash to get the payload
        pkb_hash = self.encode(compressed=compressed, hash160=True)
        # add version byte (0x00 for Main Network, or 0x6f for Test Network)
        version = {'main': b'\x00', 'test': b'\x6f'}
        ver_pkb_hash = version[net] + pkb_hash
        # calculate the checksum
        checksum = sha256(sha256(ver_pkb_hash))[:4]
        # append to form the full 25-byte binary Bitcoin Address
        byte_address = ver_pkb_hash + checksum
        # finally b58 encode the result
        b58check_address = b58encode(byte_address)
        return b58check_address

# -----------------------------------------------------------------------------
# convenience functions

def gen_key_pair():
    """ generate a (secret, public) key pair in one shot """
    sk = gen_secret_key(BITCOIN.gen.n)
    pk = PublicKey.from_sk(sk)
    return sk, pk

# -----------------------------------------------------------------------------
# base58 encoding / decoding utilities
# reference: https://en.bitcoin.it/wiki/Base58Check_encoding

alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
alphabet_inv = {c:i for i,c in enumerate(alphabet)}

def b58encode(b: bytes) -> str:
    assert len(b) == 25 # version is 1 byte, pkb_hash 20 bytes, checksum 4 bytes
    n = int.from_bytes(b, 'big')
    chars = []
    while n:
        n, i = divmod(n, 58)
        chars.append(alphabet[i])
    # special case handle the leading 0 bytes... ¯\_(ツ)_/¯
    num_leading_zeros = len(b) - len(b.lstrip(b'\x00'))
    res = num_leading_zeros * alphabet[0] + ''.join(reversed(chars))
    return res

def b58decode(res: str) -> bytes:
    n = sum(alphabet_inv[c] * 58**i for i, c in enumerate(reversed(res)))
    return n.to_bytes(25, 'big') # version, pkb_hash, checksum bytes

def address_to_pkb_hash(b58check_address: str) -> bytes:
    """ given an address in b58check recover the public key hash """
    byte_address = b58decode(b58check_address)
    # validate the checksum
    assert byte_address[-4:] == sha256(sha256(byte_address[:-4]))[:4]
    # strip the version in front and the checksum at tail
    pkb_hash = byte_address[1:-4]
    return pkb_hash
