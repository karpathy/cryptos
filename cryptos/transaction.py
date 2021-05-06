"""
The Transaction object in Bitcoin
Reference: https://en.bitcoin.it/wiki/Transaction
"""

from __future__ import annotations # PEP 563: Postponed Evaluation of Annotations
from dataclasses import dataclass
from typing import Dict, List, Tuple, Union

import os
import requests
import string
from io import BytesIO

from .sha256 import sha256
# -----------------------------------------------------------------------------
# helper functions

def decode_int(s, nbytes, encoding='little'):
    return int.from_bytes(s.read(nbytes), encoding)

def encode_int(i, nbytes, encoding='little'):
    return i.to_bytes(nbytes, encoding)

def decode_varint(s):
    i = decode_int(s, 1)
    if i == 0xfd:
        return decode_int(s, 2)
    elif i == 0xfe:
        return decode_int(s, 4)
    elif i == 0xff:
        return decode_int(s, 8)
    else:
        return i

def encode_varint(i):
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + encode_int(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + encode_int(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + encode_int(i, 8)
    else:
        raise ValueError("integer too large: %d" % (i, ))

# -----------------------------------------------------------------------------

class TxFetcher:
    """ lazily fetches transactions using an api on demand """

    @staticmethod
    def fetch(tx_id: str):
        assert isinstance(tx_id, str)
        assert all(c in string.hexdigits for c in tx_id)
        tx_id = tx_id.lower() # normalize just in case we get caps
        txdb_dir = 'txdb'
        cache_file = os.path.join(txdb_dir, tx_id)

        # cache transactions on disk so we're not stressing the generous API provider
        if os.path.isfile(cache_file):
            # fetch bytes from local disk store
            print("reading transaction %s from disk cache" % (tx_id, ))
            with open(cache_file, 'rb') as f:
                raw = f.read()
        else:
            # fetch bytes from api
            print("fetching transaction %s from API" % (tx_id, ))
            url = 'https://blockstream.info/api/tx/%s/hex' % (tx_id, )
            response = requests.get(url)
            raw = bytes.fromhex(response.text.strip())
            # cache on disk
            if not os.path.isdir(txdb_dir):
                os.makedirs(txdb_dir, exist_ok=True)
            with open(cache_file, 'wb') as f:
                f.write(raw)

        tx = Tx.decode(BytesIO(raw))
        return tx


@dataclass
class Tx:
    version: int
    tx_ins: List[TxIn]
    tx_outs: List[TxOut]
    locktime: int
    segwit: bool

    @classmethod
    def decode(cls, s):
        """ s is a stream of bytes, e.g. BytesIO(b'...') """
        # decode version
        version = decode_int(s, 4)
        # decode inputs + detect segwit transactions
        segwit = False
        num_inputs = decode_varint(s)
        if num_inputs == 0: # detect segwit marker b'\x00'
            assert s.read(1) == b'\x01' # assert segwit flag
            num_inputs = decode_varint(s) # override num_inputs
            segwit = True
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.decode(s))
        # decode outputs
        num_outputs = decode_varint(s)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.decode(s))
        # decode witness in the case of segwit
        if segwit:
            for tx_in in inputs:
                num_items = decode_varint(s)
                items = []
                for _ in range(num_items):
                    item_len = decode_varint(s)
                    if item_len == 0:
                        items.append(0)
                    else:
                        items.append(s.read(item_len))
                tx_in.witness = items
        # decode locktime
        locktime = decode_int(s, 4)
        return cls(version, inputs, outputs, locktime, segwit)

    def encode(self, force_legacy=False) -> bytes:
        out = []
        out += [encode_int(self.version, 4)]
        if self.segwit and not force_legacy:
            out += [b'\x00\x01'] # segwit marker + flag bytes
        out += [encode_varint(len(self.tx_ins))]
        out += [tx_in.encode() for tx_in in self.tx_ins]
        out += [encode_varint(len(self.tx_outs))]
        out += [tx_out.encode() for tx_out in self.tx_outs]
        if self.segwit and not force_legacy:
            for tx_in in self.tx_ins:
                out += [encode_varint(len(tx_in.witness))] # num_items
                for item in tx_in.witness:
                    if isinstance(item, int):
                        out += [encode_varint(item)]
                    else: # bytes
                        out += [encode_varint(len(item)), item]
        out += [encode_int(self.locktime, 4)]
        return b''.join(out)

    def id(self) -> str:
        return sha256(sha256(self.encode(force_legacy=True)))[::-1].hex()

    def fee(self) -> int:
        input_total = sum(tx_in.value() for tx_in in self.tx_ins)
        output_total = sum(tx_out.amount for tx_out in self.tx_outs)
        return input_total - output_total


@dataclass
class TxIn:
    prev_tx: bytes # prev transaction ID: hash256 of prev tx contents
    prev_index: int # UTXO output index in the transaction
    script_sig: Script # unlocking script
    sequence: int # originally intended for "high frequency trades", with locktime
    witness: List[bytes] = None

    @classmethod
    def decode(cls, s):
        prev_tx = s.read(32)[::-1] # 32 bytes little endian
        prev_index = decode_int(s, 4)
        script_sig = Script.decode(s)
        sequence = decode_int(s, 4)
        return cls(prev_tx, prev_index, script_sig, sequence)

    def encode(self):
        out = []
        out += [self.prev_tx[::-1]]
        out += [encode_int(self.prev_index, 4)]
        out += [self.script_sig.encode()]
        out += [encode_int(self.sequence, 4)]
        return b''.join(out)

    def value(self):
        tx = TxFetcher.fetch(self.prev_tx.hex())
        amount = tx.tx_outs[self.prev_index].amount
        return amount


@dataclass
class TxOut:
    amount: int # in units of satoshi (1e-8 of a bitcoin)
    script_pubkey: Script # locking script

    @classmethod
    def decode(cls, s):
        amount = decode_int(s, 8)
        script_pubkey = Script.decode(s)
        return cls(amount, script_pubkey)

    def encode(self):
        out = []
        out += [encode_int(self.amount, 8)]
        out += [self.script_pubkey.encode()]
        return b''.join(out)


@dataclass
class Script:
    cmds: List[Union[int, bytes]]

    def __repr__(self):
        repr_int = lambda cmd: OP_CODE_NAMES.get(cmd, 'OP_[{}]'.format(cmd))
        repr_bytes = lambda cmd: cmd.hex()
        repr_cmd = lambda cmd: repr_int(cmd) if isinstance(cmd, int) else repr_bytes(cmd)
        return ' '.join(map(repr_cmd, self.cmds))

    @classmethod
    def decode(cls, s):
        length = decode_varint(s)
        cmds = []
        count = 0 # number of bytes read
        while count < length:
            current = s.read(1)[0] # read current byte as integer
            count += 1
            # push commands onto stack, elements as bytes or ops as integers
            if 1 <= current <= 75:
                # elements of size [1, 75] bytes
                cmds.append(s.read(current))
                count += current
            elif current == 76:
                # op_pushdata1: elements of size [76, 255] bytes
                data_length = decode_int(s, 1)
                cmds.append(s.read(data_length))
                count += data_length + 1
            elif current == 77:
                # op_pushdata2: elements of size [256-520] bytes
                data_length = decode_int(s, 2)
                cmds.append(s.read(data_length))
                count += data_length + 2
            else:
                # represents an op_code, add it (as int)
                cmds.append(current)
        if count != length:
            raise SyntaxError('parsing script failed')
        return cls(cmds)

    def encode(self):
        out = []
        for cmd in self.cmds:
            if isinstance(cmd, int):
                # an int is just an opcode, encode as a single byte
                out += [encode_int(cmd, 1)]
            else:
                # bytes represent an element, encode its length and then content
                length = len(cmd) # in bytes
                if length < 75:
                    out += [encode_int(length, 1)]
                elif 76 <= length <= 255:
                    out += [encode_int(76, 1), encode_int(length, 1)] # pushdata1
                elif 256 <= length <= 520:
                    out += [encode_int(77, 1), encode_int(length, 2)] # pushdata2
                else:
                    raise ValueError("cmd of length %d bytes is too long?" % (length, ))
                out += [cmd]
        ret = b''.join(out)
        return encode_varint(len(ret)) + ret


OP_CODE_NAMES = {
    0: 'OP_0',
    # values 1..75 are not opcodes but indicate elements
    76: 'OP_PUSHDATA1',
    77: 'OP_PUSHDATA2',
    78: 'OP_PUSHDATA4',
    79: 'OP_1NEGATE',
    81: 'OP_1',
    82: 'OP_2',
    83: 'OP_3',
    84: 'OP_4',
    85: 'OP_5',
    86: 'OP_6',
    87: 'OP_7',
    88: 'OP_8',
    89: 'OP_9',
    90: 'OP_10',
    91: 'OP_11',
    92: 'OP_12',
    93: 'OP_13',
    94: 'OP_14',
    95: 'OP_15',
    96: 'OP_16',
    97: 'OP_NOP',
    99: 'OP_IF',
    100: 'OP_NOTIF',
    103: 'OP_ELSE',
    104: 'OP_ENDIF',
    105: 'OP_VERIFY',
    106: 'OP_RETURN',
    107: 'OP_TOALTSTACK',
    108: 'OP_FROMALTSTACK',
    109: 'OP_2DROP',
    110: 'OP_2DUP',
    111: 'OP_3DUP',
    112: 'OP_2OVER',
    113: 'OP_2ROT',
    114: 'OP_2SWAP',
    115: 'OP_IFDUP',
    116: 'OP_DEPTH',
    117: 'OP_DROP',
    118: 'OP_DUP',
    119: 'OP_NIP',
    120: 'OP_OVER',
    121: 'OP_PICK',
    122: 'OP_ROLL',
    123: 'OP_ROT',
    124: 'OP_SWAP',
    125: 'OP_TUCK',
    130: 'OP_SIZE',
    135: 'OP_EQUAL',
    136: 'OP_EQUALVERIFY',
    139: 'OP_1ADD',
    140: 'OP_1SUB',
    143: 'OP_NEGATE',
    144: 'OP_ABS',
    145: 'OP_NOT',
    146: 'OP_0NOTEQUAL',
    147: 'OP_ADD',
    148: 'OP_SUB',
    154: 'OP_BOOLAND',
    155: 'OP_BOOLOR',
    156: 'OP_NUMEQUAL',
    157: 'OP_NUMEQUALVERIFY',
    158: 'OP_NUMNOTEQUAL',
    159: 'OP_LESSTHAN',
    160: 'OP_GREATERTHAN',
    161: 'OP_LESSTHANOREQUAL',
    162: 'OP_GREATERTHANOREQUAL',
    163: 'OP_MIN',
    164: 'OP_MAX',
    165: 'OP_WITHIN',
    166: 'OP_RIPEMD160',
    167: 'OP_SHA1',
    168: 'OP_SHA256',
    169: 'OP_HASH160',
    170: 'OP_HASH256',
    171: 'OP_CODESEPARATOR',
    172: 'OP_CHECKSIG',
    173: 'OP_CHECKSIGVERIFY',
    174: 'OP_CHECKMULTISIG',
    175: 'OP_CHECKMULTISIGVERIFY',
    176: 'OP_NOP1',
    177: 'OP_CHECKLOCKTIMEVERIFY',
    178: 'OP_CHECKSEQUENCEVERIFY',
    179: 'OP_NOP4',
    180: 'OP_NOP5',
    181: 'OP_NOP6',
    182: 'OP_NOP7',
    183: 'OP_NOP8',
    184: 'OP_NOP9',
    185: 'OP_NOP10',
}
