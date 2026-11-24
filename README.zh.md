# cryptos

[ [English](README.md) | **中文** ]

本项目是仅用于教学目的、纯 Python 从零手写（from-scratch）且零依赖的比特币实现，涵盖了包括 SHA-256 以及有限域上椭圆曲线数学等所有底层密码学基础原语。

### SHA-256

`cryptos/sha256.py` 中提供了严格遵循 [NIST FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) 规范的纯 Python SHA-256 实现。由于该实现从零手写且纯由 Python 编写，运行速度较慢，除教学研究外显然不应在任何生产环境中使用。使用示例：

```bash
$ echo "some test file lol" > testfile.txt
$ shasum -a 256 testfile.txt
4a79aed64097a0cd9e87f1e88e9ad771ddb5c5d762b3c3bbf02adf3112d5d375
$ python -m cryptos.sha256 testfile.txt
4a79aed64097a0cd9e87f1e88e9ad771ddb5c5d762b3c3bbf02adf3112d5d375
```

### 密钥与地址 (Keys)

`getnewaddress.py` 是用于生成全新比特币私钥/公钥对以及对应压缩地址（base58check 压缩格式）的 CLI 命令行入口：

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

### 数字签名 (Digital Signatures)

`cryptos/ecdsa.py` 中实现了椭圆曲线数字签名算法（ECDSA），使用示例：

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

### 交易 (Transactions)

比特币交易对象（包括传统 legacy 与隔离见证 segwit 两种格式）可直接由原始字节进行实例化与解析。以下是解析传统类型交易的示例：

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

同时我们可以验证该交易符合比特币共识规则且在密码学上真实有效：

```python
>>> tx.validate()
True
```

需要注意，这并不完全等同于比特币全节点所执行的完整校验，例如略过了双花检测、脚本大小上限等校验，并且仅支持（较为简单的）p2pkh 交易类型。值得一提的是，此处未包含自 2017 年 7 月左右 BIP141 软分叉以来在当今比特币网络流量中占据主导地位的“现代” segwit 版本。

### 区块 (Blocks)

请参阅 `cryptos/block.py` 了解 Block 类、相关函数与实用工具。

### 轻量级节点 (Lightweight Node)

`cryptos/network.py` 中实现了一个支持 [比特币网络协议（Bitcoin protocol）](https://en.bitcoin.it/wiki/Protocol_documentation) 子集的轻量级比特币节点。该节点使用 Python 原生 `socket` 连接到其他网络节点，执行版本握手协议，随后可请求区块头信息。例如，我们可以遍历前 40,000 个区块（以 2,000 个为一批次）并进行部分验证。比特币全节点会拉取包含所有交易的完整区块（而不仅是区块头）并进行全量校验。部分验证的代码如下所示：

```python
from io import BytesIO
from cryptos.block import Block, GENESIS_BLOCK, calculate_new_bits
from cryptos.network import SimpleNode
from cryptos.network import (
    GetHeadersMessage,
    HeadersMessage,
)

# 连接至网络节点并请求以创世区块为起点的 20 个区块头

# 从创世区块开始
# https://en.bitcoin.it/wiki/Genesis_block
# class Block:
#     version: int        # 4 字节，小端序
#     prev_block: bytes   # 32 字节，小端序
#     merkle_root: bytes  # 32 字节，小端序
#     timestamp: int      # uint32，自 1970-01-01T00:00 UTC 以来的秒数
#     bits: bytes         # 4 字节，紧凑格式的当前目标值
#     nonce: bytes        # 4 字节，工作量证明中搜索的随机数
previous = Block.decode(BytesIO(GENESIS_BLOCK['main']))

# 开始爬取区块链区块头
node = SimpleNode(
    host='mainnet.programmingbitcoin.com',
    net='main',
)
node.handshake()

blocks = [previous]
for _ in range(20):

    # 请求下一批 2,000 个区块头
    getheaders = GetHeadersMessage(start_block=bytes.fromhex(previous.id()))
    node.send(getheaders)
    headers = node.wait_for(HeadersMessage)

    # 扩展区块头链
    blocks.extend(headers.blocks)

    previous = headers.blocks[-1]
    print(f"received another batch of blocks, now have {len(blocks)}")

node.close()
# 目前总计获取了 40,001 个区块，每个原始区块头 80 字节，总计约 3.2MB 数据

# 现在对区块链完整性进行（部分）验证
for i, block in enumerate(blocks):

    # 验证该区块的工作量证明（PoW）
    assert block.validate()

    # 验证指向前一区块的哈希指针匹配
    prev = blocks[i - 1]
    expected_prev_block = b'\x00'*32 if i == 0 else bytes.fromhex(prev.id())
    assert block.prev_block == expected_prev_block

    # 验证区块上的工作量证明目标难度计算正确
    if i % 2016 == 0:
        if i == 0:
            # 创世区块的 bits 值为硬编码
            expected_bits = bytes.fromhex('ffff001d')
        else:
            # 在每个纪元（epoch，2016 个区块，约 2 周周期）重新计算难度目标
            # 注意中本聪在计算中存在一个差一错误（off-by-one bug），
            # 因为算法计算的是纪元中第一个与最后一个区块之间的时间戳差值，
            # 导致跨度仅为 2015 个区块而不是 2016 个区块 ¯\_(ツ)_/¯
            prev_epoch = blocks[i - 2016]
            time_diff = prev.timestamp - prev_epoch.timestamp
            expected_bits = calculate_new_bits(prev.bits, time_diff)
    assert block.bits == expected_bits

    if i % 1000 == 0:
        print(f"on block {i+1}/{len(blocks)}")
```

能够独立地对区块链完整性进行至少部分的自主验证，体验非常棒 :)

### 单元测试 (Unit tests)

```bash
$ pytest
```

### 许可证 (License)
MIT

---

> **免责声明**：本文档为开源社区提供的中文翻译版，仅供参考与学习交流。如翻译内容与英文原文存在出入，请以原版英文 [README.md](README.md) 为准。
