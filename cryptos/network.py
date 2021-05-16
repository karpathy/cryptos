"""
Classes/utils for connecting to Bitcoin nodes
"""

from dataclasses import dataclass
from io import BytesIO
from .sha256 import sha256

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
