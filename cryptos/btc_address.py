"""
Function that converts public key to (Compressed) Bitcoin address and related utilities
"""

from .sha256 import sha256
from .ripemd160 import ripemd160

# -----------------------------------------------------------------------------
# base58 encoding / decoding utilities
# reference: https://en.bitcoin.it/wiki/Base58Check_encoding

alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
alphabet_inv = {c:i for i,c in enumerate(alphabet)}

def chunk(n, base):
    ret = []
    while n:
        n, i = divmod(n, base)
        ret.append(i)
    return ret

def b58encode(b: bytes) -> str:
    assert len(b) == 25 # version is 1 byte, pkb_hash 20 bytes, checksum 4 bytes
    n = int.from_bytes(b, 'big')
    ix = chunk(n, 58)
    s = ''.join(alphabet[i] for i in reversed(ix))
    # special case handle the leading 0 bytes... ¯\_(ツ)_/¯
    num_leading_zeros = len(b) - len(b.lstrip(b'\x00'))
    res = num_leading_zeros * alphabet[0] + s
    return res

def b58decode(res: str) -> bytes:
    n = sum(alphabet_inv[c] * 58**i for i, c in enumerate(reversed(res)))
    return n.to_bytes(25, 'big') # version, pkb_hash, checksum bytes

# -----------------------------------------------------------------------------

def pk_to_address_bytes(public_key) -> bytes:

    # generate the compressed public key
    prefix = b'\x02' if public_key.y % 2 == 0 else b'\x03'
    pkb = prefix + public_key.x.to_bytes(32, 'big')

    # double hash to get the payload
    pkb_hash = ripemd160(sha256(pkb))

    # add version byte (0x00 for Main Network)
    ver_pkb_hash = b'\x00' + pkb_hash

    # calculate the checksum
    checksum = sha256(sha256(ver_pkb_hash))[:4]

    # append to form the full 25-byte binary Bitcoin Address
    byte_address = ver_pkb_hash + checksum

    return byte_address

def pk_to_address(public_key) -> str:
    byte_address = pk_to_address_bytes(public_key)
    b58check_address = b58encode(byte_address)
    return b58check_address

def address_to_pkb_hash(b58check_address: str) -> bytes:
    """ given an address in b58check recover the public key hash """
    byte_address = b58decode(b58check_address)
    # validate the checksum
    assert byte_address[-4:] == sha256(sha256(byte_address[:-4]))[:4]
    # strip the version in front and the checksum at tail
    pkb_hash = byte_address[1:-4]
    return pkb_hash
