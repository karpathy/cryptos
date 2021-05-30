"""
Classes/utils for connecting to Bitcoin nodes

Protocol Documentation: https://en.bitcoin.it/wiki/Protocol_documentation
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Union

import socket
from io import BytesIO

from .sha256 import sha256
from .transaction import encode_varint, decode_varint
from .block import Block

# -----------------------------------------------------------------------------

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
        """ Stream the payload of this envelope """
        return BytesIO(self.payload)

# -----------------------------------------------------------------------------
# Specific types of commands and their payload encoder/decords follow
# -----------------------------------------------------------------------------

@dataclass
class NetAddrStruct:
    """
    reference: https://en.bitcoin.it/wiki/Protocol_documentation#Network_address
    currently assumes IPv4 address
    """
    services: int = 0
    ip: bytes = b'\x00\x00\x00\x00' # IPv4 address
    port: int = 8333

    def encode(self):
        out = []
        # receiver services is 8 bytes little endian
        out += [self.services.to_bytes(8, 'little')]
        # IPV4 is 10 00 bytes and 2 ff bytes then receiver ip
        assert isinstance(self.ip, bytes) and len(self.ip) == 4
        out += [b'\x00' * 10 + b'\xff\xff' + self.ip]
        # receiver port is 2 bytes, big endian
        out += [self.port.to_bytes(2, 'big')]
        return b''.join(out)


@dataclass
class VersionMessage:
    """
    reference: https://en.bitcoin.it/wiki/Protocol_documentation#version
    When a node creates an outgoing connection, it will immediately advertise
    its version. The remote node will respond with its version. No further
    communication is possible until both peers have exchanged their version.
    """

    # header information
    version: int = 70015 # specifies what messages may be communicated
    services: int = 0 # info about what capabilities are available
    timestamp: int = None # 8 bytes Unix timestamp in little-endian
    # receiver net_addr
    receiver: NetAddrStruct = field(default_factory=NetAddrStruct)
    # sender net_addr
    sender: NetAddrStruct = field(default_factory=NetAddrStruct)
    # additional metadata
    """
    uint64_t Node random nonce, randomly generated every time a version
    packet is sent. This nonce is used to detect connections to self.
    """
    nonce: bytes = None # 8 bytes of nonce
    user_agent: bytes = None # var_str: User Agent
    latest_block: int = 0 # "The last block received by the emitting node"
    relay: bool = False # Whether the remote peer should announce relayed transactions or not, see BIP 0037
    command: str = field(init=False, default=b'version')

    @classmethod
    def decode(cls, s):
        # TODO. For now return a fixed default stub
        return cls()

    def encode(self):
        out = []

        # version is 4 bytes little endian
        out += [self.version.to_bytes(4, 'little')]
        # services is 8 bytes little endian
        out += [self.services.to_bytes(8, 'little')]
        # timestamp is 8 bytes little endian
        out += [self.timestamp.to_bytes(8, 'little')]
        # receiver
        out += [self.receiver.encode()]
        # sender
        out += [self.sender.encode()]
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

@dataclass
class VerAckMessage:
    """
    https://en.bitcoin.it/wiki/Protocol_documentation#verack
    The verack message is sent in reply to version. This message
    consists of only a message header with the command string "verack".
    """
    command: str = field(init=False, default=b'verack')

    @classmethod
    def decode(cls, s):
        return cls()

    def encode(self):
        return b''

@dataclass
class PingMessage:
    """
    https://en.bitcoin.it/wiki/Protocol_documentation#ping
    The ping message is sent primarily to confirm that the TCP/IP
    connection is still valid. An error in transmission is presumed
    to be a closed connection and the address is removed as a current peer.
    """
    nonce: bytes
    command: str = field(init=False, default=b'ping')

    @classmethod
    def decode(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def encode(self):
        return self.nonce

@dataclass
class PongMessage:
    """
    https://en.bitcoin.it/wiki/Protocol_documentation#pong
    The pong message is sent in response to a ping message.
    In modern protocol versions, a pong response is generated
    using a nonce included in the ping.
    """
    nonce: bytes
    command: str = field(init=False, default=b'pong')

    @classmethod
    def decode(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def encode(self):
        return self.nonce

@dataclass
class GetHeadersMessage:
    """
    https://en.bitcoin.it/wiki/Protocol_documentation#getheaders
    """
    version: int = 70015 # uint32_t protocol version
    num_hashes: int = 1 # var_int, number of block locator hash entries; can be >1 if there is a chain split
    start_block: bytes = None # char[32] block locator object
    end_block: bytes = None # char[32] hash of the last desired block header; set to zero to get as many blocks as possible
    command: str = field(init=False, default=b'getheaders')

    def __post_init__(self):
        assert isinstance(self.start_block, bytes) and len(self.start_block) == 32
        self.end_block = self.end_block if self.end_block is not None else b'\x00' * 32
        assert isinstance(self.end_block, bytes) and len(self.end_block) == 32

    def encode(self):
        out = []
        out += [self.version.to_bytes(4, 'little')]
        out += [encode_varint(self.num_hashes)]
        out += [self.start_block[::-1]] # little-endian
        out += [self.end_block[::-1]] # little-endian
        return b''.join(out)

@dataclass
class HeadersMessage:
    """
    https://en.bitcoin.it/wiki/Protocol_documentation#headers
    """
    blocks: List[Block] = None
    command: str = field(init=False, default=b'headers')

    @classmethod
    def decode(cls, s):
        count = decode_varint(s)
        blocks = []
        for _ in range(count):
            b = Block.decode(s)
            blocks.append(b)
            """
            the number of transactions is also given and is always zero if we
            only request the headers. This is done so that the same code can be
            used to decode the "block" message, which contains the full block
            information with all the transactions attached. Here we just make
            sure it is zero.
            """
            num_transactions = decode_varint(s)
            assert num_transactions == 0
        return cls(blocks)

# -----------------------------------------------------------------------------
# A super lightweight baby node follows
# -----------------------------------------------------------------------------

class SimpleNode:

    def __init__(self, host: str, net: str, verbose: int = 0):
        self.net = net
        self.verbose = verbose

        port = {'main': 8333, 'test': 18333}[net]
        self.socket = socket.socket()
        self.socket.connect((host, port))
        self.stream = self.socket.makefile('rb', None)

    def send(self, message):
        env = NetworkEnvelope(message.command, message.encode(), net=self.net)
        if self.verbose:
            print(f"sending: {env}")
        self.socket.sendall(env.encode())

    def read(self):
        env = NetworkEnvelope.decode(self.stream, net=self.net)
        if self.verbose:
            print(f"receiving: {env}")
        return env

    def wait_for(self, *message_classes):
        command = None
        command_to_class = { m.command: m for m in message_classes }

        # loop until one of the desired commands is encountered
        while command not in command_to_class:
            env = self.read()
            command = env.command

            # respond to Version with VerAck
            if command == VersionMessage.command:
                self.send(VerAckMessage())

            # respond to Ping with Pong
            elif command == PingMessage.command:
                self.send(PongMessage(env.payload))

        # return the parsed message
        return command_to_class[command].decode(env.stream())

    def handshake(self):
        """
        Version Handshake
        ref: https://en.bitcoin.it/wiki/Version_Handshake

        Local peer (L) connects to a remote peer (R):
        L -> R: Send version message with the local peer's version
        R -> L: Send version message back
        R -> L: Send verack message
        R:      Sets version to the minimum of the 2 versions
        L -> R: Send verack message after receiving version message from R
        L:      Sets version to the minimum of the 2 versions
        """
        version = VersionMessage(
            timestamp=0,
            nonce=b'\x00'*8,
            user_agent=b'/programmingbitcoin:0.1/',
        )
        self.send(version)
        self.wait_for(VersionMessage)
        self.wait_for(VerAckMessage)
        self.send(VerAckMessage())

    def close(self):
        self.socket.close()
