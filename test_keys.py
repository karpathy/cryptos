"""
Test the generation of private/public keypairs and bitcoin addreses
"""

from cryptos.public_key import gen_bitcoin_curve

def test_public_key_gen():

    # Example taken from Chapter 4 of Mastering Bitcoin
    # https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc
    private_key = int('1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD', 16)
    curve, G = gen_bitcoin_curve()
    public_key = curve.mul(private_key, G)
    assert format(public_key[0], '064x').upper() == 'F028892BAD7ED57D2FB57BF33081D5CFCF6F9ED3D3D7F159C2E2FFF579DC341A'
    assert format(public_key[1], '064x').upper() == '07CF33DA18BD734C600B96A72BBC4749D5141C90EC8AC328AE52DDFE2E505BDB'
