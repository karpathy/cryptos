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
from .ripemd160 import ripemd160
from .ecdsa import verify, Signature
from .keys import PublicKey

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
    def fetch(tx_id: str, net: str):
        assert isinstance(tx_id, str)
        assert all(c in string.hexdigits for c in tx_id)
        tx_id = tx_id.lower() # normalize just in case we get caps
        txdb_dir = 'txdb'
        cache_file = os.path.join(txdb_dir, tx_id)

        # cache transactions on disk so we're not stressing the generous API provider
        if os.path.isfile(cache_file):
            # fetch bytes from local disk store
            # print("reading transaction %s from disk cache" % (tx_id, ))
            with open(cache_file, 'rb') as f:
                raw = f.read()
        else:
            # fetch bytes from api
            # print("fetching transaction %s from API" % (tx_id, ))
            assert net is not None, "can't fetch a transaction without knowing which net to look at, e.g. main|test"
            if net == 'main':
                url = 'https://blockstream.info/api/tx/%s/hex' % (tx_id, )
            elif net == 'test':
                url = 'https://blockstream.info/testnet/api/tx/%s/hex' % (tx_id, )
            else:
                raise ValueError("%s is not a valid net type, should be main|test" % (net, ))
            response = requests.get(url)
            assert response.status_code == 200, "transaction id %s was not found on blockstream" % (tx_id, )
            raw = bytes.fromhex(response.text.strip())
            # cache on disk
            if not os.path.isdir(txdb_dir):
                os.makedirs(txdb_dir, exist_ok=True)
            with open(cache_file, 'wb') as f:
                f.write(raw)

        tx = Tx.decode(BytesIO(raw))
        assert tx.id() == tx_id # ensure that the calculated id matches the request id
        return tx


@dataclass
class Tx:
    version: int
    tx_ins: List[TxIn]
    tx_outs: List[TxOut]
    locktime: int = 0
    segwit: bool = False

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

    def encode(self, force_legacy=False, sig_index=-1) -> bytes:
        """
        encode this transaction as bytes.
        If sig_index is given then return the modified transaction
        encoding of this tx with respect to the single input index.
        This result then constitutes the "message" that gets signed
        by the aspiring transactor of this input.
        """
        out = []
        # encode metadata
        out += [encode_int(self.version, 4)]
        if self.segwit and not force_legacy:
            out += [b'\x00\x01'] # segwit marker + flag bytes
        # encode inputs
        out += [encode_varint(len(self.tx_ins))]
        if sig_index == -1:
            out += [tx_in.encode() for tx_in in self.tx_ins]
        else:
            out += [tx_in.encode(script_override=(sig_index == i))
                    for i, tx_in in enumerate(self.tx_ins)]
        # encode outputs
        out += [encode_varint(len(self.tx_outs))]
        out += [tx_out.encode() for tx_out in self.tx_outs]
        # encode witnesses
        if self.segwit and not force_legacy:
            for tx_in in self.tx_ins:
                out += [encode_varint(len(tx_in.witness))] # num_items
                for item in tx_in.witness:
                    if isinstance(item, int):
                        out += [encode_varint(item)]
                    else: # bytes
                        out += [encode_varint(len(item)), item]
        # encode... other metadata I guess
        out += [encode_int(self.locktime, 4)]
        out += [encode_int(1, 4) if sig_index != -1 else b''] # 1 = SIGHASH_ALL
        return b''.join(out)

    def id(self) -> str:
        return sha256(sha256(self.encode(force_legacy=True)))[::-1].hex()

    def fee(self) -> int:
        input_total = sum(tx_in.value() for tx_in in self.tx_ins)
        output_total = sum(tx_out.amount for tx_out in self.tx_outs)
        return input_total - output_total

    def validate(self):
        assert not self.segwit # todo for segwits

        # validate that this transaction is not minting coins
        if self.fee() < 0:
            return False

        # validate the digital signatures of all inputs
        for i, tx in enumerate(self.tx_ins):
            """
            note: here we should be decoding the sighash-type, which is the
            last byte appended on top of the DER signature in the script_sig,
            and encoding the signing bytes accordingly. For now we assume the
            most common type of signature, which is 1 = SIGHASH_ALL
            """
            mod_tx_enc = self.encode(sig_index=i)
            combined = tx.script_sig + tx.script_pubkey() # Script addition
            valid = combined.evaluate(mod_tx_enc)
            if not valid:
                return False

        return True

    def is_coinbase(self) -> bool:
        return (len(self.tx_ins) == 1) and \
               (self.tx_ins[0].prev_tx == b'\x00'*32) and \
               (self.tx_ins[0].prev_index == 0xffffffff)

    def coinbase_height(self) -> int:
        """ returns the block number of a given transaction, following BIP0034 """
        return int.from_bytes(self.tx_ins[0].script_sig.cmds[0], 'little') if self.is_coinbase() else None


@dataclass
class TxIn:
    prev_tx: bytes # prev transaction ID: hash256 of prev tx contents
    prev_index: int # UTXO output index in the transaction
    script_sig: Script = None # unlocking script
    sequence: int = 0xffffffff # originally intended for "high frequency trades", with locktime
    witness: List[bytes] = None
    net: str = None # which net are we on? eg 'main'|'test'

    @classmethod
    def decode(cls, s):
        prev_tx = s.read(32)[::-1] # 32 bytes little endian
        prev_index = decode_int(s, 4)
        script_sig = Script.decode(s)
        sequence = decode_int(s, 4)
        return cls(prev_tx, prev_index, script_sig, sequence)

    def encode(self, script_override=None):
        out = []
        out += [self.prev_tx[::-1]]
        out += [encode_int(self.prev_index, 4)]

        if script_override is None:
            # None = just use the actual script
            out += [self.script_sig.encode()]
        elif script_override is True:
            # True = override the script with the script_pubkey of the associated input
            tx = TxFetcher.fetch(self.prev_tx.hex(), net=self.net)
            out += [tx.tx_outs[self.prev_index].script_pubkey.encode()]
        elif script_override is False:
            # False = override with an empty script
            out += [Script([]).encode()]
        else:
            raise ValueError("script_override must be one of None|True|False")

        out += [encode_int(self.sequence, 4)]
        return b''.join(out)

    def value(self):
        # look the amount up on the previous transaction
        tx = TxFetcher.fetch(self.prev_tx.hex(), net=self.net)
        amount = tx.tx_outs[self.prev_index].amount
        return amount

    def script_pubkey(self):
        # look the script_pubkey up on the previous transaction
        tx = TxFetcher.fetch(self.prev_tx.hex(), net=self.net)
        script = tx.tx_outs[self.prev_index].script_pubkey
        return script


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

    def evaluate(self, mod_tx_enc):

        # for now let's just support a standard p2pkh transaction
        assert len(self.cmds) == 7
        assert isinstance(self.cmds[0], bytes) # signature
        assert isinstance(self.cmds[1], bytes) # pubkey
        assert isinstance(self.cmds[2], int) and (OP_CODE_NAMES[self.cmds[2]] == 'OP_DUP')
        assert isinstance(self.cmds[3], int) and (OP_CODE_NAMES[self.cmds[3]] == 'OP_HASH160')
        assert isinstance(self.cmds[4], bytes) # hash
        assert isinstance(self.cmds[5], int) and (OP_CODE_NAMES[self.cmds[5]] == 'OP_EQUALVERIFY')
        assert isinstance(self.cmds[6], int) and (OP_CODE_NAMES[self.cmds[6]] == 'OP_CHECKSIG')

        # verify the public key hash, answering the OP_EQUALVERIFY challenge
        pubkey, pubkey_hash = self.cmds[1], self.cmds[4]
        if pubkey_hash != ripemd160(sha256(pubkey)):
            return False

        # verify the digital signature of the transaction, answering the OP_CHECKSIG challenge
        sighash_type = self.cmds[0][-1] # the last byte is the sighash type
        assert sighash_type == 1 # 1 is SIGHASH_ALL, most commonly used and only one supported right now
        der = self.cmds[0][:-1] # DER encoded signature, but crop out the last byte
        sec = self.cmds[1] # SEC encoded public key
        sig = Signature.decode(der)
        pk = PublicKey.decode(sec)
        valid = verify(pk, mod_tx_enc, sig)

        return valid

    def __add__(self, other):
        return Script(self.cmds + other.cmds)


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
