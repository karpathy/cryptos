"""
A cli tool that generates and prints a new Bitcoin address.
Specifically, the tool prints:
- a new secret key
- the associated public key
- the bitcoin address
"""

from cryptos.keys import gen_secret_key, PublicKey
from cryptos.bitcoin import BITCOIN

if __name__ == '__main__':

    # generate a secret/public key pair
    secret_key = gen_secret_key(BITCOIN.gen.n)
    public_key = PublicKey.from_sk(secret_key)
    print('generated secret key:')
    print(hex(secret_key))
    print('corresponding public key:')
    print('x:', format(public_key.x, '064x').upper())
    print('y:', format(public_key.y, '064x').upper())

    # get the associated bitcoin address
    addr = public_key.address(net='main', compressed=True)
    print('compressed bitcoin address (b58check format):')
    print(addr)
