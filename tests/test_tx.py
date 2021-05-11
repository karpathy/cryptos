"""
Test Transaction
"""

from io import BytesIO

from cryptos.transaction import Tx, TxIn, TxOut, Script
from cryptos.keys import PublicKey, address_to_pkb_hash
from cryptos.ecdsa import sign

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

    # validate the transaction as Bitcoin law-abiding and cryptographically authentic
    assert tx.validate()

    # fudge the r in the (r,s) digital signature tuple, this should break validation because CHECKSIG will fail
    sigb = tx.tx_ins[0].script_sig.cmds[0]
    sigb2 = sigb[:6] + bytes([(sigb[6] + 1) % 255]) + sigb[7:]
    tx.tx_ins[0].script_sig.cmds[0] = sigb2
    assert not tx.validate()
    tx.tx_ins[0].script_sig.cmds[0] = sigb # revert to original
    assert tx.validate()

    # fudge the public key, should again break validation because pk hash won't match
    pkb = tx.tx_ins[0].script_sig.cmds[1]
    pkb2 = pkb[:6] + bytes([(pkb[6] + 1) % 255]) + pkb[7:]
    tx.tx_ins[0].script_sig.cmds[1] = pkb2
    assert not tx.validate()
    tx.tx_ins[0].script_sig.cmds[1] = pkb # revert to original
    assert tx.validate()

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

def test_create_tx():
    # this example follows Programming Bitcoin Chapter 7

    # define the inputs of our aspiring transaction
    prev_tx = bytes.fromhex('0d6fe5213c0b3291f208cba8bfb59b7476dffacc4e5cb66f6eb20a080843a299')
    prev_index = 13
    tx_in = TxIn(prev_tx, prev_index, net='test')

    # change output that goes back to us
    amount = int(0.33 * 1e8) # 0.33 tBTC in units of satoshi
    pkb_hash = address_to_pkb_hash('mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2')
    script = Script([118, 169, pkb_hash, 136, 172]) # OP_DUP, OP_HASH160, <hash>, OP_EQUALVERIFY, OP_CHECKSIG
    tx_out_change = TxOut(amount=amount, script_pubkey=script)

    # target output that goes to a lucky recepient
    amount = int(0.1 * 1e8) # 0.1 tBTC in units of satoshi
    pkb_hash = address_to_pkb_hash('mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf')
    script = Script([118, 169, pkb_hash, 136, 172]) # OP_DUP, OP_HASH160, <hash>, OP_EQUALVERIFY, OP_CHECKSIG
    tx_out_target = TxOut(amount=amount, script_pubkey=script)

    # create the desired transaction object
    tx = Tx(1, [tx_in], [tx_out_change, tx_out_target])

    # validate the intended fee of 0.01 tBTC
    assert tx.fee() == int(0.01 * 1e8)

    # produce the unlocking script for this p2pkh tx: [<signature>, <pubkey>]

    # first produce the <pubkey> that will satisfy OP_EQUALVERIFY on the locking script
    sk = 8675309 # the secret key that produced the public key that produced the hash that is on that input tx's locking script
    pk = PublicKey.from_sk(sk)
    sec = pk.encode(compressed=True) # sec encoded public key as bytes
    # okay but anyone with the knowledge of the public key could have done this part if this public
    # key was previously used (and hence revealed) somewhere on the blockchain

    # now produce the digital signature that will satisfy the OP_CHECKSIG on the locking script
    enc = tx.encode(sig_index=0)
    sig = sign(sk, enc) # only and uniquely the person with the secret key can do this
    der = sig.encode()
    der_and_type = der + b'\x01' # 1 = SIGHASH_ALL, indicating this der signature encoded "ALL" of the tx

    # set the unlocking script into the transaction
    tx_in.script_sig = Script([der_and_type, sec])

    # final check: ensure that our manually constructed transaction is all valid and ready to send out to the wild
    assert tx.validate()

    # peace of mind: fudge the signature and try again
    der = der[:6] + bytes([(der[6] + 1) % 255]) + der[7:]
    der_and_type = der + b'\x01'
    tx_in.script_sig = Script([der_and_type, sec])
    assert not tx.validate()

def test_is_coinbase():

    # not coinbase
    raw = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
    tx = Tx.decode(BytesIO(raw))
    assert not tx.is_coinbase()

    # is coinbase
    raw = bytes.fromhex('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000')
    tx = Tx.decode(BytesIO(raw))
    assert tx.is_coinbase()
    tx.tx_ins = [] # make not coinbase by deleting its inputs entirely
    assert not tx.is_coinbase()

def test_coinbase_height():

    raw = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
    tx = Tx.decode(BytesIO(raw))
    assert tx.coinbase_height() is None

    raw = bytes.fromhex('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000')
    tx = Tx.decode(BytesIO(raw))
    assert tx.coinbase_height() == 465879
