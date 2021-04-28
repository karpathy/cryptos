"""
Utilities to generate private/public key pairs and Bitcoin address
"""

import os
import time

from .sha256 import sha256
from .curves import bitcoin_gen

# -----------------------------------------------------------------------------
# Private key generation utilities

def random_bytes_os():
    """
    Use os provided entropy, e.g. on macs sourced from /dev/urandom, eg available as:
    $ head -c 32 /dev/urandom

    According to Apple Platform Security docs
    https://support.apple.com/en-ie/guide/security/seca0c73a75b/web
    the kernel CPRNG is a Fortuna-derived design targeting a 256-bit security level
    where the entropy is sourced from:
    - The Secure Enclave’s hardware RNG
    - Timing-based jitter collected during boot
    - Entropy collected from hardware interrupts
    - A seed file used to persist entropy across boots
    - Intel random instructions, i.e. RDSEED and RDRAND (macOS only)
    """
    return os.urandom(32)


def random_bytes_user():
    """
    Collect some entropy from time and user and generate a key with SHA-256
    """
    entropy = ''
    for i in range(5):
        s = input("Enter some word #%d/5: " % (i+1,))
        entropy += s + '|' + str(int(time.time() * 1000000)) + '|'
    return sha256(entropy.encode('ascii'))


def mastering_bitcoin_bytes():
    """
    The example from Mastering Bitcoin, Chapter 4
    https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc
    """
    sk = '3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6'
    return bytes.fromhex(sk)


def gen_private_key(n: int, source: str = 'os') -> int:
    """
    n is the upper bound on the key, typically the order of the elliptic curve
    we are using. The function will return a valid key, i.e. 1 <= key < n.
    """

    assert source in ['os', 'user', 'mastering'], "The source must be one of 'os' or 'user' or 'mastering'"
    bytes_fn = {
        'os': random_bytes_os,
        'user': random_bytes_user,
        'mastering': mastering_bitcoin_bytes,
    }[source]

    while True:
        key = int.from_bytes(bytes_fn(), 'big')
        if 1 <= key < n:
            break # the key is valid, break out

    return key

# -----------------------------------------------------------------------------
# Public key generation

def sk_to_pk(sk):
    # convenience function that takes the private (secret) key
    # and returns the public key. sk can be passed in as integer or hex string
    if isinstance(sk, int):
        private_key = sk
    elif isinstance(sk, str):
        private_key = int(sk, 16) # assume it is given as hex
    else:
        raise ValueError("private key sk should be an int or a hex string")

    gen = bitcoin_gen()
    public_key = private_key * gen.G
    return public_key

def gen_key_pair(source: str = 'os'):
    """ convenience function to quickly generate a private/public keypair """
    gen = bitcoin_gen()
    sk = gen_private_key(gen.n, source)
    pk = sk_to_pk(sk)
    return sk, pk


