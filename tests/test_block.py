"""
Test Block
"""

from io import BytesIO

from cryptos.block import Block, calculate_new_bits, bits_to_target, target_to_bits

def test_block():

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
    assert block.target() == 0x0000000000000000013ce9000000000000000000000000000000000000000000
    assert int(block.difficulty()) == 888171856257 # difficulty of genesis block was 1 :|

def test_validate():

    raw = bytes.fromhex('04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec1')
    block = Block.decode(BytesIO(raw))
    assert block.validate()

    raw = bytes.fromhex('04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec0')
    block = Block.decode(BytesIO(raw))
    assert not block.validate()

def test_calculate_bits():

    dt = 302400
    prev_bits = bytes.fromhex('54d80118')
    next_bits = calculate_new_bits(prev_bits, dt)
    assert next_bits == bytes.fromhex('00157617')

    # make sure encoding/decidng of bits <-> target works
    for bits in [prev_bits, next_bits]:
        target = bits_to_target(bits)
        bits2 = target_to_bits(target)
        assert bits == bits2
