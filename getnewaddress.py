"""
A cli tool that generates and prints a new Bitcoin address.
Specifically, the tool prints:
- a new private key
- the associated public key
- the bitcoin address
"""

import sys

from cryptos.keys import gen_key_pair
from cryptos.btc_address import pk_to_address

if __name__ == '__main__':

    # generate a private/public key pair
    source = sys.argv[1] if len(sys.argv) == 2 else 'os' # can also be 'user' | 'mastering'
    private_key, public_key = gen_key_pair(source) # represented as int
    print('generated private key:')
    print(hex(private_key))
    print('corresponding public key:')
    print('x:', format(public_key.x, '064x').upper()) # (strip the 0x part denoting hex number)
    print('y:', format(public_key.y, '064x').upper())

    # calculate the bitcoin address
    addr = pk_to_address(public_key) # is a string in b58check format
    print('compressed bitcoin address (b58check format):')
    print(addr)
