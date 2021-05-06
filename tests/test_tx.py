"""
Test Transaction
"""

from cryptos.transaction import Tx
from io import BytesIO

def test_legacy_decode():

    # Example taken from Programming Bitcoin, Chapter 5
    raw = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
    tx = Tx.decode(BytesIO(raw))

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
    # id calculation
    assert tx.id() == '452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03'
    # fee calculation
    assert tx.fee() == 40000

    # check correct decoding/encoding
    raw2 = tx.encode()
    assert raw == raw2

def test_segwit_decode():

    # I snatched this transaction at random from the stream of transactions
    raw = bytes.fromhex('010000000001026c4224e4d6bab0cfdfd67870e084cda34e42d3544b3c77d310df40831fa4f5061700000023220020fb24ee0fec024ff3ff03c44d16ca523b78fd33ebaab99176e98b3f5e0e78da9dffffffffe8faf73aee5a09b1b678277fc63150dff639c97521e9088d6721a2b995f33664010000002322002083e1adc1eb82945fa99500bcd9df963b0e731524fd8eb25ef205e88d3bd7ab77ffffffff03a0370a00000000001976a914b00ff32bbc990acde3e5ac022e6d4120fb168f1e88ac7f791300000000001976a914128afed7e8d4e6f3a9d2d38ad560c307ebf392ba88ac54115c00000000001976a914c65d16caa1d8c1c46cc1bfac92eff06b02d8afcc88ac04004830450221009d93dc766b4a3417d7daccffe39719cd0344779c19d589d3a078625139a7dcd50220267c1b9b365d0eaa3b036771cbfc994c2b1c5b29e5107f023f036360cb60c8b50147304402206346b5c2bfa243c9cd0c5056abedfadc79e4a2b67b918315fc3faf79dfd12d7602203f729a665afd02ceb4b07898c06c81f0dfc378f66409ed828a4b5fe84f9287550169522102b951c91d97118489d1980ec472d89b5bc98fb98d0bafa17aca238d18a758b8642103d45b78e2a683330c62878e44610a5d1c8d40bd1f261b1110940b1b8a5aecd3e82103796ecd1667be6e20af571c46517e4ecf5e83052df864266658dd7f88e63efa6153ae0400483045022100e396deff2fe6dd6081e35f9dced6e09ea1b8b4830ae322b5d58986596996893d0220485420653c118c1a13b48941166b242077530d2b3cab908abe67af6b96ef2850014730440220171e11f4d6a106464a94e29f46750803a7deb214e6fbe2140ec5d80577dded0e02203483ab0c685f66e17b4afa86ba053732b43ff1ca7654796e72b69bd224bf26c4016952210375e42f77749f92a6b54c8e85fab2209e6807e15a3768c024a5cab01dc301c0282103fd4969521bd2d0f8e147c16655ae9c29dc48cb4f124b7a6398db78b1cbc878a221036bc18f387d1e4ba80492854cee639bd4ab6e3a310d9faa6f17350bbdc4c029d053ae25680a00')
    tx = Tx.decode(BytesIO(raw))

    # metadata parsing
    assert tx.version == 1
    assert tx.segwit is True
    # input parsing
    assert len(tx.tx_ins) == 2
    assert tx.tx_ins[0].witness is not None
    assert tx.tx_ins[1].witness is not None
    # output parsing
    assert len(tx.tx_outs) == 3
    assert tx.tx_outs[0].amount == 669600
    assert tx.tx_outs[1].amount == 1276287
    assert tx.tx_outs[2].amount == 6033748
    # id calculation
    assert tx.id() == '3ecf9b3d965cfaa2c472f09b5f487fbd838e4e1f861e3542c541d39c5cb7bc25'
    assert tx.fee() == 31922

    # check correct decoding/encoding
    raw2 = tx.encode()
    assert raw == raw2
