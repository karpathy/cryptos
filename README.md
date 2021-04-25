
# cryptos

Just having fun

#### SHA-256

SHA-256 implementation following [NIST FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) spec in `cryptos/sha256.py`. Pure Python, slow, trying to closely follow the document spec, obviously not to be used anywhere except for educational purposes.

```bash
$ echo "some test file lol" > testfile.txt
$ shasum -a 256 testfile.txt
4a79aed64097a0cd9e87f1e88e9ad771ddb5c5d762b3c3bbf02adf3112d5d375
$ python cryptos/sha256.py testfile.txt
4a79aed64097a0cd9e87f1e88e9ad771ddb5c5d762b3c3bbf02adf3112d5d375
```

#### License
MIT
