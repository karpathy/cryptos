"""
Test our ability to sign and verify digital signatures
"""

import os
from cryptos.curves import bitcoin_gen
from cryptos.keys import gen_key_pair
from cryptos.ecdsa import Signature, sign, verify

def test_ecdsa():

    gen = bitcoin_gen()

    # let's create two identities
    sk1, pk1 = gen_key_pair('os')
    sk2, pk2 = gen_key_pair('os')

    message = ('user pk1 would like to pay user pk2 1 BTC kkthx').encode('ascii')

    # an evil user2 attempts to submit the transaction to the network with some totally random signature
    sig = Signature(int.from_bytes(os.urandom(32), 'big'), int.from_bytes(os.urandom(32), 'big'))
    # a few seconds later a hero miner inspects the candidate transaction
    is_legit = verify(pk1, message, sig)
    assert not is_legit
    # unlike user2, hero miner is honest and discards the transaction, all is well

    # evil user2 does not give up and tries to sign with his key pair
    sig = sign(sk2, message)
    is_legit = verify(pk1, message, sig)
    assert not is_legit
    # denied, again!

    # lucky for user2, user1 feels sorry for them and the hardships they have been through recently
    sig = sign(sk1, message)
    is_legit = verify(pk1, message, sig)
    assert is_legit
    # hero miner validates the transaction and adds it to their block
    # user2 happy, buys a Tesla, and promises to turn things around

    # the end.
