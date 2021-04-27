import hashlib
from cryptos.sha256 import sha256
from cryptos.ripemd160 import ripemd160

def test_sha256():

    test_bytes = [
        b'',
        b'abc', # as seen in NIST docs
        b'hello',
        b'a longer message to make sure that a larger number of blocks works okay too'*15
    ]

    for b in test_bytes:
        gt = hashlib.sha256(b).hexdigest()
        yolo = sha256(b).hex()
        assert gt == yolo

def test_ripemd160():

    # taken from the ripemd160 docs
    # https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
    test_pairs = [
        ('', '9c1185a5c5e9fc54612808977ee8f548b2258d31'),
        ('a', '0bdc9d2d256b3ee9daae347be6f4dc835a467ffe'),
        ('abc', '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'),
        ('message digest', '5d0689ef49d2fae572b881b123a85ffa21595f36'),
        ('1234567890'*8, '9b752e45573d4b39f4dbd3323cab82bf63326bfb'),
        # ('a'*1000000, '52783243c1697bdbe16d37f97f68f08325dc1528'), # can take a while to compute
        ('a'*1000, 'aa69deee9a8922e92f8105e007f76110f381e9cf'), # I made this shorter one up instead
    ]

    for b, gt in test_pairs:
        yolo = ripemd160(b.encode('ascii')).hex()
        assert gt == yolo
