
# cryptos

Just me developing a pure Python from-scratch zero-dependency implementation of Bitcoin for educational purposes. This includes a lot of the core crypto math primitives such as SHA-256 and elliptic curves over finite fields math (but with the exception of RIPEMD160 hash function, which I imported).

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

`getnewaddress.py` is a cli entryway to the code that generates a new Bitcoin private/public key pair and the corresponding (base58 compressed) address:

```bash
$ python getnewaddress.py
generated private key:
0xc322622e6a0033bb93ff666753f77cc8b819d274d9edea007b7e4b2af4caf025
corresponding public key:
x: 5B9D87FE091D52EA4CD49EA5CEFDD8C099DF7E6CCF510A9A94C763DE38C575D5
y: 6049637B3683076C5568EC723CF7D38FD603B88447180829BBB508C554EEA413
compressed bitcoin address (b58check format):
1DBGfUXnwTS2PRu8h3JefU9uYwYnyaTd2z
```

You can also generate your own entropy from keyboard timings if you call the cli as `$ python getnewaddress.py user`, or you can verify that the implementation is not broken by reproducing the [Mastering Bitcoin Chapter 4](https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc) example:

```bash
$ python getnewaddress.py mastering
generated private key:
0x3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6
corresponding public key:
x: 5C0DE3B9C8AB18DD04E3511243EC2952002DBFADC864B9628910169D9B9B00EC
y: 243BCEFDD4347074D44BD7356D6A53C495737DD96295E2A9374BF5F02EBFC176
compressed bitcoin address (b58check format):
14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3
```

Where we see that after the all crazy hashing and elliptic curve over finite fields gymnastics the bitcoin address `14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3` matches, phew :)

### Digital Signatures

Elliptic Curve Digital Signature Algorithm (ECDSA) implemented in `cryptos/ecdsa.py`, example usage:

```python
>>> from cryptos.ecdsa import sign, verify
>>> from cryptos.keys import gen_key_pair
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

### Unit tests

```bash
$ pytest
```

### License
MIT
