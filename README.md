
# cryptos

Just me developing a pure Python from-scratch zero-dependency implementation of Bitcoin for educational purposes, including all of the under the hood crypto primitives such as SHA-256 and elliptic curves over finite fields math.

### SHA-256

My pure Python SHA-256 implementation closely following the [NIST FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) spec, in `cryptos/sha256.py`. Since this is a from scratch pure Python implementation it is slow and obviously not to be used anywhere except for educational purposes. Example usage:

```bash
$ echo "some test file lol" > testfile.txt
$ shasum -a 256 testfile.txt
4a79aed64097a0cd9e87f1e88e9ad771ddb5c5d762b3c3bbf02adf3112d5d375
$ python -m cryptos.sha256 testfile.txt
4a79aed64097a0cd9e87f1e88e9ad771ddb5c5d762b3c3bbf02adf3112d5d375
```

### Keys

`getnewaddress.py` is a cli entryway to generate a new Bitcoin secret/public key pair and the corresponding (base58check compressed) address:

```bash
$ python getnewaddress.py
generated secret key:
0xc322622e6a0033bb93ff666753f77cc8b819d274d9edea007b7e4b2af4caf025
corresponding public key:
x: 5B9D87FE091D52EA4CD49EA5CEFDD8C099DF7E6CCF510A9A94C763DE38C575D5
y: 6049637B3683076C5568EC723CF7D38FD603B88447180829BBB508C554EEA413
compressed bitcoin address (b58check format):
1DBGfUXnwTS2PRu8h3JefU9uYwYnyaTd2z
```

### Digital Signatures

Elliptic Curve Digital Signature Algorithm (ECDSA) implemented in `cryptos/ecdsa.py`, example usage:

```python
>>> from cryptos.keys import gen_key_pair
>>> from cryptos.ecdsa import sign, verify
>>> sk1, pk1 = gen_key_pair()
>>> sk2, pk2 = gen_key_pair()
>>> message = ('pk1 wants to pay pk2 1 BTC').encode('ascii')
>>> sig = sign(sk1, message)
>>> verify(pk1, message, sig)
True
>>> verify(pk2, message, sig)
False
```

### Transactions

Bitcoin transaction objects (both legacy or segwit) can be instantiated and parsed from raw bytes. An example of parsing a legacy type transaction:

```python
>>> from cryptos.transaction import Tx
>>> from io import BytesIO

>>> # example transaction in Programming Bitcoing Chapter 5
>>> raw = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
>>> tx = Tx.parse(BytesIO(raw))
>>> # we get back a Transaction object with parsed fields
>>> tx

Tx(version=1, tx_ins=[TxIn(prev_tx=b'\xd1\xc7\x89\xa9\xc6\x03\x83\xbfq_?j\xd9\xd1K\x91\xfeU\xf3\xde\xb3i\xfe]\x92\x80\xcb\x1a\x01y?\x81', prev_index=0, script_sig=3045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01 0349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a, sequence=4294967294, witness=None)], tx_outs=[TxOut(amount=32454049, script_pubkey=OP_DUP OP_HASH160 bc3b654dca7e56b04dca18f2566cdaf02e8d9ada OP_EQUALVERIFY OP_CHECKSIG), TxOut(amount=10011545, script_pubkey=OP_DUP OP_HASH160 1c4bc762dd5423e332166702cb75f40df79fea12 OP_EQUALVERIFY OP_CHECKSIG)], locktime=410393, segwit=False)
```

And we can verify that the transaction is Bitcoin law-abiding and cryptographically authentic:

```python
>>> tx.validate()
True
```

This isn't exactly a complete verification as a Bitcoin full node would do and e.g. skips verification of double spends, script sizing limits, etc., and also it only supports the (simpler) p2pkh transactions. Notably, this does not include the "modern" segwit versions used predominantly in today's Bitcoin traffic since the soft fork of BIP141 around July 2017.

### Blocks

See `cryptos/block.py` for Block class, functions and utilities.

### Lightweight Node

A lightweight Bitcoin Node that speaks a subset of the [Bitcoin protocol](https://en.bitcoin.it/wiki/Protocol_documentation) is in `cryptos/network.py`. This node connects to other nodes using Python's `socket`, performs version handshake and then can request block headers. E.g. we can walk the first 40,000 blocks (in batches of 2,000) and partially validate them. A Bitcoin full node would fetch the full block (not just headers) with all transactions and also validate those, etc. But a partial validation would look like:

```python

from io import BytesIO
from cryptos.block import Block, GENESIS_BLOCK, calculate_new_bits
from cryptos.network import SimpleNode
from cryptos.network import (
    GetHeadersMessage,
    HeadersMessage,
)

# connect to a node and pretty please ask for
# 20 block headers starting with the genesis block

# Start with the genesis block
# https://en.bitcoin.it/wiki/Genesis_block
# class Block:
#     version: int        # 4 bytes little endian
#     prev_block: bytes   # 32 bytes, little endian
#     merkle_root: bytes  # 32 bytes, little endian
#     timestamp: int      # uint32, seconds since 1970-01-01T00:00 UTC
#     bits: bytes         # 4 bytes, current target in compact format
#     nonce: bytes        # 4 bytes, searched over in pow
previous = Block.decode(BytesIO(GENESIS_BLOCK['main']))

# okay now let's crawl the blockchain block headers
node = SimpleNode(
    host='mainnet.programmingbitcoin.com',
    net='main',
)
node.handshake()

blocks = [previous]
for _ in range(20):

    # request next batch of 2,000 headers
    getheaders = GetHeadersMessage(start_block=bytes.fromhex(previous.id()))
    node.send(getheaders)
    headers = node.wait_for(HeadersMessage)

    # extend our chain of block headers
    blocks.extend(headers.blocks)

    previous = headers.blocks[-1]
    print(f"received another batch of blocks, now have {len(blocks)}")

node.close()
# we now have 40,001 blocks total, 80 bytes each in raw, so total of ~3.2MB of data

# now (partially) validate blockchain integrity
for i, block in enumerate(blocks):

    # validate proof of work on this block
    assert block.validate()

    # validate pointer to the previous node matches
    prev = blocks[i - 1]
    expected_prev_block = b'\x00'*32 if i == 0 else bytes.fromhex(prev.id())
    assert block.prev_block == expected_prev_block

    # validate the proof of work target calculation on the block was correct
    if i % 2016 == 0:
        if i == 0:
            # genesis block had hardcoded value for bits
            expected_bits = bytes.fromhex('ffff001d')
        else:
            # recalculate the target at every epoch (2016 blocks), approx 2 week period
            # note that Satoshi had an off-by-one bug in this calculation because we are
            # looking at timestamp difference between first and last block in an epoch,
            # so these are only 2015 blocks apart instead of 2016 blocks apart ¯\_(ツ)_/¯
            prev_epoch = blocks[i - 2016]
            time_diff = prev.timestamp - prev_epoch.timestamp
            expected_bits = calculate_new_bits(prev.bits, time_diff)
    assert block.bits == expected_bits

    if i % 1000 == 0:
        print(f"on block {i+1}/{len(blocks)}")
```

It feels very nice to independently at least partially verify the integrity of the block chain :)

### Unit tests

```bash
$ pytest
```

### License
MIT
