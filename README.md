
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

### Unit tests

```bash
$ pytest
```

### License
MIT
