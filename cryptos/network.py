"""
Classes/utils for connecting to Bitcoin nodes

Protocol Documentation: https://en.bitcoin.it/wiki/Protocol_documentation
"""

from dataclasses import dataclass
from io import BytesIO
from .sha256 import sha256
from .transaction import encode_varint

MAGICS = {
    'main': b'\xf9\xbe\xb4\xd9',
    'test': b'\x0b\x11\x09\x07',
}

@dataclass
class NetworkEnvelope:
    command: bytes
    payload: bytes
    net: str

    def __repr__(self):
        return "[NetworkEnvelope] Command: %s, Payload: %s" % \
               (self.command.decode('ascii'), self.payload.hex())

    @classmethod
    def decode(cls, s, net):
        """ Construct a NetworkEnvelope from BytesIO stream s on a given net """

        # validate magic bytes
        magic = s.read(4)
        assert magic != b'', "No magic bytes; Connection was reset?"
        assert magic == MAGICS[net]
        # decode the command
        command = s.read(12)
        command = command.strip(b'\x00')
        # decode and validate the payload
        payload_length = int.from_bytes(s.read(4), 'little')
        checksum = s.read(4)
        payload = s.read(payload_length)
        assert checksum == sha256(sha256(payload))[:4]

        return cls(command, payload, net)

    def encode(self):
        """ Encode this network message as bytes """
        out = []

        out += [MAGICS[self.net]]
        # encode the command
        assert len(self.command) <= 12
        out += [self.command]
        out += [b'\x00' * (12 - len(self.command))] # command padding
        # encode the payload
        assert len(self.payload) <= 2**32 # in practice reference client nodes will reject >= 32MB...
        out += [len(self.payload).to_bytes(4, 'little')] # payload length
        out += [sha256(sha256(self.payload))[:4]] # checksum
        out += [self.payload]

        return b''.join(out)

    def stream(self):
        return BytesIO(self.payload)

"""
-------------------------------------------------------------------------------
Specific types of commands and their payload encoder/decords follow
-------------------------------------------------------------------------------
"""

@dataclass
class VersionMessage:
    """ reference: https://en.bitcoin.it/wiki/Protocol_documentation#version """

    # header information
    version: int = 70015 # specifies what messages may be communicated
    services: int = 0 # info about what capabilities are available
    timestamp: int = None # 8 bytes Unix timestamp in little-endian
    # receiver information (explicit) net_addr
    receiver_services: int = 0
    receiver_ip: bytes = b'\x00\x00\x00\x00' # assumed to be IPv4 here
    receiver_port: int = 8333
    # sender information (explicit) net_addr
    sender_services: int = 0
    sender_ip: bytes = b'\x00\x00\x00\x00' # assumed to be IPv4 here
    sender_port: int = 8333
    # additional metadata
    """
    uint64_t Node random nonce, randomly generated every time a version
    packet is sent. This nonce is used to detect connections to self.
    """
    nonce: bytes = None # 8 bytes of nonce
    user_agent: bytes = None # var_str: User Agent
    latest_block: int = 0 # "The last block received by the emitting node"
    relay: bool = False # Whether the remote peer should announce relayed transactions or not, see BIP 0037

    def encode(self):
        out = []

        # version is 4 bytes little endian
        out += [self.version.to_bytes(4, 'little')]
        # services is 8 bytes little endian
        out += [self.services.to_bytes(8, 'little')]
        # timestamp is 8 bytes little endian
        out += [self.timestamp.to_bytes(8, 'little')]

        # receiver services is 8 bytes little endian
        out += [self.receiver_services.to_bytes(8, 'little')]
        # IPV4 is 10 00 bytes and 2 ff bytes then receiver ip
        assert isinstance(self.receiver_ip, bytes) and len(self.receiver_ip) == 4
        out += [b'\x00' * 10 + b'\xff\xff' + self.receiver_ip]
        # receiver port is 2 bytes, big endian
        out += [self.receiver_port.to_bytes(2, 'big')]

        # sender services is 8 bytes little endian
        out += [self.sender_services.to_bytes(8, 'little')]
        # IPV4 is 10 00 bytes and 2 ff bytes then sender ip
        assert isinstance(self.sender_ip, bytes) and len(self.sender_ip) == 4
        out += [b'\x00' * 10 + b'\xff\xff' + self.sender_ip]
        # sender port is 2 bytes, big endian
        out += [self.sender_port.to_bytes(2, 'big')]

        # nonce should be 8 bytes
        assert isinstance(self.nonce, bytes) and len(self.nonce) == 8
        out += [self.nonce]
        # useragent is a variable string, so varint first
        assert isinstance(self.user_agent, bytes)
        out += [encode_varint(len(self.user_agent))]
        out += [self.user_agent]

        # latest block is 4 bytes little endian
        out += [self.latest_block.to_bytes(4, 'little')]
        # relay is 00 if false, 01 if true
        out += [b'\x01' if self.relay else b'\x00']

        return b''.join(out)
