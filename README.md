
# cryptos

Just having fun

#### SHA-256

SHA-256 implementation following [NIST FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) spec in `cryptos/sha256.py`. Pure Python, slow, trying to closely follow the document spec, obviously not to be used anywhere except for educational purposes.

```bash
$ echo "some test file lol" > testfile.txt
$ shasum -a 256 testfile.txt
4a79aed64097a0cd9e87f1e88e9ad771ddb5c5d762b3c3bbf02adf3112d5d375
$ python -m cryptos.sha256 testfile.txt
4a79aed64097a0cd9e87f1e88e9ad771ddb5c5d762b3c3bbf02adf3112d5d375
```

#### Keys

Bitcoin elliptic curve - compatible private keys can be generated using default system entropy with:

```bash
$ python -m cryptos.private_key
0x5748d05ca380dbebea56e135c7671dd4221b204271a9a87bb4d3f24afa64f0e0
```

Or to seed entropy directly from the user for generating the key:

```bash
$ python -m cryptos.private_key user
Enter some word #1/5: hi
Enter some word #2/5: there
Enter some word #3/5: lol
Enter some word #4/5: entropy!
Enter some word #5/5: cool
0xd2e21be9bdc05304b7dd4347e73d1a14009732780125db39a1eb7736d9be245
```

We can then generate the corresponding public key, which is a point on the elliptic curve:

```bash
$ python -m cryptos.public_key 0xd2e21be9bdc05304b7dd4347e73d1a14009732780125db39a1eb7736d9be245
x: B8B2C5DE9F39CAAB1819536285B8DE9A674C6929AAA80CF23F40715DA9A4D765
y: E716EE6D252C9F52D7138AA73E0C43EBA2F4722613CE3077A8EFA68E1BD64596
```

This point can be compressed and then converted into a Bitcoin address (coming soon).

#### License
MIT
