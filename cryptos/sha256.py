"""
Follows the FIPS PUB 180-4 description for calculating SHA-256 hash function
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

Noone in their right mind should use this for any serious reason. This was written
purely for educational purposes.
"""

import math
from itertools import count, islice

# -----------------------------------------------------------------------------
# SHA-256 Functions, defined in Section 4

def rotr(x, n, size=32):
    return (x >> n) | (x << size - n) & (2**size - 1)

def shr(x, n):
    return x >> n

def sig0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)

def sig1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)

def capsig0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def capsig1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def ch(x, y, z):
    return (x & y)^ (~x & z)

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def b2i(b):
    return int.from_bytes(b, 'big')

def i2b(i):
    return i.to_bytes(4, 'big')

# -----------------------------------------------------------------------------
# SHA-256 Constants

def is_prime(n):
    return not any(f for f in range(2,int(math.sqrt(n))+1) if n%f == 0)

def first_n_primes(n):
    return islice(filter(is_prime, count(start=2)), n)

def frac_bin(f, n=32):
    """ return the first n bits of fractional part of float f """
    f -= math.floor(f) # get only the fractional part
    f *= 2**n # shift left
    f = int(f) # truncate the rest of the fractional content
    return f

def genK():
    """
    Follows Section 4.2.2 to generate K

    The first 32 bits of the fractional parts of the cube roots of the first
    64 prime numbers:

    428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
    d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
    e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
    983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967
    27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85
    a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070
    19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3
    748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2
    """
    return [frac_bin(p ** (1/3.0)) for p in first_n_primes(64)]

def genH():
    """
    Follows Section 5.3.3 to generate the initial hash value H^0

    The first 32 bits of the fractional parts of the square roots of
    the first 8 prime numbers.

    6a09e667 bb67ae85 3c6ef372 a54ff53a 9b05688c 510e527f 1f83d9ab 5be0cd19
    """
    return [frac_bin(p ** (1/2.0)) for p in first_n_primes(8)]

# -----------------------------------------------------------------------------

def pad(b):
    """ Follows Section 5.1: Padding the message """
    b = bytearray(b) # convert to a mutable equivalent
    l = len(b) * 8 # note: len returns number of bytes not bits

    # append but "1" to the end of the message
    b.append(0b10000000) # appending 10000000 in binary (=128 in decimal)

    # follow by k zero bits, where k is the smallest non-negative solution to
    # l + 1 + k = 448 mod 512
    # i.e. pad with zeros until we reach 448 (mod 512)
    while (len(b)*8) % 512 != 448:
        b.append(0x00)

    # the last 64-bit block is the length l of the original message
    # expressed in binary (big endian)
    b.extend(l.to_bytes(8, 'big'))

    return b

def sha256(b: bytes) -> bytes:

    # Section 4.2
    K = genK()

    # Section 5: Preprocessing
    # Section 5.1: Pad the message
    b = pad(b)
    # Section 5.2: Separate the message into blocks of 512 bits (64 bytes)
    blocks = [b[i:i+64] for i in range(0, len(b), 64)]

    # for each message block M^1 ... M^N
    H = genH() # Section 5.3

    # Section 6
    for M in blocks: # each block is a 64-entry array of 8-bit bytes

        # 1. Prepare the message schedule, a 64-entry array of 32-bit words
        W = []
        for t in range(64):
            if t <= 15:
                # the first 16 words are just a copy of the block
                W.append(bytes(M[t*4:t*4+4]))
            else:
                term1 = sig1(b2i(W[t-2]))
                term2 = b2i(W[t-7])
                term3 = sig0(b2i(W[t-15]))
                term4 = b2i(W[t-16])
                total = (term1 + term2 + term3 + term4) % 2**32
                W.append(i2b(total))

        # 2. Initialize the 8 working variables a,b,c,d,e,f,g,h with prev hash value
        a, b, c, d, e, f, g, h = H

        # 3.
        for t in range(64):
            T1 = (h + capsig1(e) + ch(e, f, g) + K[t] + b2i(W[t])) % 2**32
            T2 = (capsig0(a) + maj(a, b, c)) % 2**32
            h = g
            g = f
            f = e
            e = (d + T1) % 2**32
            d = c
            c = b
            b = a
            a = (T1 + T2) % 2**32

        # 4. Compute the i-th intermediate hash value H^i
        delta = [a, b, c, d, e, f, g, h]
        H = [(i1 + i2) % 2**32 for i1, i2 in zip(H, delta)]

    return b''.join(i2b(i) for i in H)

if __name__ == '__main__':
    import sys
    assert len(sys.argv) == 2, "Pass in exactly one filename to return checksum of"
    with open(sys.argv[1], 'rb') as f:
        print(sha256(f.read()).hex())
