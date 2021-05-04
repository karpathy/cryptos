"""
The Transaction object in Bitcoin
Reference: https://en.bitcoin.it/wiki/Transaction
"""

from __future__ import annotations # PEP 563: Postponed Evaluation of Annotations
from dataclasses import dataclass
from typing import Dict, List, Tuple, Union

# -----------------------------------------------------------------------------
# helper functions

def read_varint(s):
    i = s.read(1)[0]
    if i == 0xfd:
        return int.from_bytes(s.read(2), 'little')
    elif i == 0xfe:
        return int.from_bytes(s.read(4), 'little')
    elif i == 0xff:
        return int.from_bytes(s.read(8), 'little')
    else:
        return i

# -----------------------------------------------------------------------------

@dataclass
class Tx:
    version: int
    tx_ins: List[TxIn]
    tx_outs: List[TxOut]
    locktime: int
    segwit: bool

    @classmethod
    def parse(cls, s):
        """ s is a stream of bytes, e.g. BytesIO(b'...') """
        # parse version
        version = int.from_bytes(s.read(4), 'little')
        # parse inputs + detect segwit transactions
        segwit = False
        num_inputs = read_varint(s)
        if num_inputs == 0: # detect segwit marker b'\x00'
            assert s.read(1) == b'\x01' # assert segwit flag
            num_inputs = read_varint(s) # override num_inputs
            segwit = True
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        # parse outputs
        num_outputs = read_varint(s)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        # parse witness in the case of segwit
        if segwit:
            for tx_in in inputs:
                num_items = read_varint(s)
                items = []
                for _ in range(num_items):
                    item_len = read_varint(s)
                    if item_len == 0:
                        items.append(0)
                    else:
                        items.append(s.read(item_len))
                tx_in.witness = items
        # parse locktime
        locktime = int.from_bytes(s.read(4), 'little')
        return cls(version, inputs, outputs, locktime, segwit)


@dataclass
class TxIn:
    prev_tx: bytes # prev transaction ID: hash256 of prev tx contents
    prev_index: int # UTXO output index in the transaction
    script_sig: Script # unlocking script
    sequence: int # originally intended for "high frequency trades", with locktime
    witness: List[bytes] = None

    @classmethod
    def parse(cls, s):
        prev_tx = s.read(32)[::-1] # 32 bytes little endian
        prev_index = int.from_bytes(s.read(4), 'little')
        script_sig = Script.parse(s)
        sequence = int.from_bytes(s.read(4), 'little')
        return cls(prev_tx, prev_index, script_sig, sequence)


@dataclass
class TxOut:
    amount: int # in units of satoshi (1e-8 of a bitcoin)
    script_pubkey: Script # locking script

    @classmethod
    def parse(cls, s):
        amount = int.from_bytes(s.read(8), 'little')
        script_pubkey = Script.parse(s)
        return cls(amount, script_pubkey)


@dataclass
class Script:
    cmds: List[Union[int, bytes]]

    def __repr__(self):
        repr_int = lambda cmd: OP_CODE_NAMES.get(cmd, 'OP_[{}]'.format(cmd))
        repr_bytes = lambda cmd: cmd.hex()
        repr_cmd = lambda cmd: repr_int(cmd) if isinstance(cmd, int) else repr_bytes(cmd)
        return ' '.join(map(repr_cmd, self.cmds))

    @classmethod
    def parse(cls, s):
        length = read_varint(s)
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
                data_length = int.from_bytes(s.read(1), 'little')
                cmds.append(s.read(data_length))
                count += data_length + 1
            elif current == 77:
                # op_pushdata2: elements of size [256-520] bytes
                data_length = int.from_bytes(s.read(2), 'little')
                cmds.append(s.read(data_length))
                count += data_length + 2
            else:
                # represents an op_code, add it (as int)
                cmds.append(current)
        if count != length:
            raise SyntaxError('parsing script failed')
        return cls(cmds)


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
