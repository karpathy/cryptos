"""
Test node network protocol comms handling classes / utils
"""

from io import BytesIO
from cryptos.network import NetworkEnvelope, VersionMessage, SimpleNode

def test_encode_decode_network_envelope():

    msg = bytes.fromhex('f9beb4d976657261636b000000000000000000005df6e0e2')
    stream = BytesIO(msg)
    envelope = NetworkEnvelope.decode(stream, 'main')
    assert envelope.command == b'verack'
    assert envelope.payload == b''
    assert envelope.encode() == msg

    msg = bytes.fromhex('f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001')
    stream = BytesIO(msg)
    envelope = NetworkEnvelope.decode(stream, 'main')
    assert envelope.command == b'version'
    assert envelope.payload == msg[24:]
    assert envelope.encode() == msg

def test_encode_version_payload():

    v = VersionMessage(
        timestamp=0,
        nonce=b'\x00'*8,
        user_agent=b'/programmingbitcoin:0.1/',
    )

    assert v.encode().hex() == '7f11010000000000000000000000000000000000000000000000000000000000000000000000ffff00000000208d000000000000000000000000000000000000ffff00000000208d0000000000000000182f70726f6772616d6d696e67626974636f696e3a302e312f0000000000'

def test_handshake():

    node = SimpleNode(
        host='testnet.programmingbitcoin.com',
        net='test',
    )
    node.handshake()
    node.close()
