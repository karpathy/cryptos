"""
Test the generation of private/public keypairs and bitcoin addreses
"""

from cryptos.public_key import sk_to_pk
from cryptos.btc_address import pk_to_address

def test_public_key_gen():

    # Example taken from Chapter 4 of Mastering Bitcoin
    # https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc
    public_key = sk_to_pk('1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD')
    assert format(public_key.x, '064x').upper() == 'F028892BAD7ED57D2FB57BF33081D5CFCF6F9ED3D3D7F159C2E2FFF579DC341A'
    assert format(public_key.y, '064x').upper() == '07CF33DA18BD734C600B96A72BBC4749D5141C90EC8AC328AE52DDFE2E505BDB'


def test_btc_addresses():

    # tuples of (private key in hex, expected compressed bitcoin address string in b58check)
    tests = [
        # Mastering Bitcoin Chapter 4 example
        # https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc
        ('3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6', '14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3'),
        # Bitcoin wiki page reference
        # https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses#How_to_create_Bitcoin_Address
        ('18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725', '1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs'),
    ]

    for private_key, expected_address in tests:
        pk = sk_to_pk(private_key)
        addr = pk_to_address(pk)
        assert addr == expected_address
