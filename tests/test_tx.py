"""
Test Transaction
"""

from cryptos.transaction import Tx
from io import BytesIO

def test_legacy_parse():

    # Example taken from Programming Bitcoin, Chapter 5
    raw = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
    tx = Tx.parse(BytesIO(raw))

    # metadata parsing
    assert tx.version == 1
    assert tx.segwit is False
    # input parsing
    assert len(tx.tx_ins) == 1
    assert tx.tx_ins[0].prev_tx == bytes.fromhex('d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81')
    assert tx.tx_ins[0].prev_index == 0
    assert tx.tx_ins[0].sequence == 0xfffffffe
    assert tx.tx_ins[0].witness is None
    # output parsing
    assert len(tx.tx_outs) == 2
    assert tx.tx_outs[0].amount == 32454049
    assert tx.tx_outs[1].amount == 10011545
    # locktime parsing
    assert tx.locktime == 410393

    # todo: check scripts were parsed correctly

def test_segwit_parse():
    pass # todo
