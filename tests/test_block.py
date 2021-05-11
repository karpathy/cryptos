"""
Test Block
"""

from io import BytesIO

from cryptos.block import Block

def test_encode_decode_id():
    # Exercise 3, 4, 5 in Chapter 9 (Blocks) of programming bitcoin
    raw = bytes.fromhex('020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d')

    block = Block.decode(BytesIO(raw))
    assert block.version == 0x20000002
    assert block.prev_block == bytes.fromhex('000000000000000000fd0c220a0a8c3bc5a7b487e8c8de0dfa2373b12894c38e')
    assert block.merkle_root == bytes.fromhex('be258bfd38db61f957315c3f9e9c5e15216857398d50402d5089a8e0fc50075b')
    assert block.timestamp == 0x59a7771e
    assert block.bits == bytes.fromhex('e93c0118')
    assert block.nonce == bytes.fromhex('a4ffd71d')

    raw2 = block.encode()
    assert raw == raw2

    assert block.id() == '0000000000000000007e9e4c586439b0cdbe13b1370bdd9435d76a644d047523'
