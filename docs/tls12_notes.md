# TLS 1.2 报文与密码学详解（RFC 5246）

> 配套实验: `bash scripts/run_tls12.sh`（ECDHE）与 `bash scripts/run_tls12.sh AES128-GCM-SHA256`（静态 RSA）
> 解析: `python3 scripts/parse_handshake.py captures/tls12_rsa_ks_msg.txt`
> 验证: `python3 scripts/verify_tls12_crypto.py`

## 1. 记录层 (Record Layer, RFC 5246 §6.2)

所有 TLS 数据都封装在记录里。一条记录的 5 字节头：

```
struct {
    uint8  type;        // 20=ChangeCipherSpec 21=Alert 22=Handshake 23=ApplicationData
    uint16 legacy_version;  // 0x0303 (TLS1.2); 握手首条可以是 0x0301 以兼容老服务器
    uint16 length;      // 载荷长度 (≤ 2^14 + 2048)
} TLSPlaintext;
```

要点：
- **未加密前** type=22 的载荷是若干条握手消息的拼接（一条记录可含多条消息，一条长消息也可跨多条记录）。
- **加密后** (GCM) 载荷 = explicit_nonce(8) + AES-GCM 密文 + tag(16)，type 不变。
- ChangeCipherSpec 只有一个字节 `01`，作用是"**从现在起我发的记录都是加密的**"。TLS 1.3 仅为兼容中间件才保留它。

## 2. TLS 1.2 握手流程（静态 RSA 与 ECDHE 两种）

```
ClientHello ────────────────────────────→
                        ←─ ServerHello, Certificate, [ServerKeyExchange]
                           [CertificateRequest], ServerHelloDone
[ClientCertificate], ClientKeyExchange, [CertificateVerify]
ChangeCipherSpec, Finished ─────────────→
                        ←─ [NewSessionTicket], ChangeCipherSpec, Finished
```

- **静态 RSA 套件**（如 `TLS_RSA_WITH_AES_128_GCM_SHA256` 0x009C）：
  没有 ServerKeyExchange / ServerHelloDone 之外的密钥交换报文，客户端直接生成 48 字节
  premaster，用**服务器证书里的 RSA 公钥**加密放进 ClientKeyExchange。
  → 谁拿到服务器私钥 + 抓包，谁就能解出所有历史会话（**无前向安全**）。
- **(EC)DHE 套件**（如 0xC02F）：多出 ServerKeyExchange（服务器临时 DH 公钥 + 签名）
  与 ClientKeyExchange（客户端临时 DH 公钥），共享密钥 = ECDH(双方临时密钥)。
  临时密钥用完即丢 → **前向安全**。

## 3. 逐报文逐字段解析（真实抓包值）

### 3.1 ClientHello (type=1)

```
01 00 00 80                  type=1, body 长度 0x0080=128
03 03                        legacy_version: 客户端最高支持 TLS1.2
[32 B]                       random: 32 字节随机 (RFC5246 保留前 4B 作 gmt_unix_time,
                             实际实现多为纯随机)。防重放 + 参与 master_secret 推导
00                           session_id 长度 = 0 (vector<0..32>：1 字节长度前缀!)
00 02 c0 2f                  cipher_suites: 2 字节长度 + 套件列表
                             0xC02F = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
01 00                        compression_methods: 1 字节长度 + [null]
00 55                        extensions 长度 = 0x55
  ff01 0001 00               renegotiation_info
  000b 0002 01 00            ec_point_formats: uncompressed
  000a 000c 000a 001d 0017.. supported_groups: x25519, secp256r1, secp384r1, ...
  0023 0000                  session_ticket (愿意收 session ticket)
  0016 0000                  encrypt_then_mac
  0017 0000                  extended_master_secret (RFC7627)
  000d 002a 0028 0403 ...    signature_algorithms: ecdsa_secp256r1_sha256, rsa_pss...
```

字段学习点：
| 字段 | 作用 |
|---|---|
| random | 与 server_random 一起作为密钥推导的种子，保证每次会话密钥不同 |
| session_id | 1 字节长度前缀（不是 2 字节!），用于 TLS1.2 会话缓存恢复 |
| cipher_suites | 每个套件 2 字节：密钥交换 | 签名 | 对称 | 哈希 四个组件的"菜单" |
| signature_algorithms | TLS1.2 起显式声明，服务器选一个用于证书/SKE 签名验证 |

### 3.2 ServerHello (type=2)

```
02 00 00 3b                  type=2, body=0x3b
03 03                        服务器选定 TLS1.2
[32 B]                       server_random
00                           session_id 长度=0
c0 2f                        选定套件（与 ClientHello 交集之一）
01                           compression = null
00 13                        extensions 长度
  ff01 0001 00               renegotiation_info (安全重协商)
  000b 0002 01 00            ec_point_formats
  0023 0000                  session_ticket (服务器接受)
  0017 0000                  extended_master_secret: 协商成功!
```

### 3.3 Certificate (type=11)

```
0b 00 03 93                  type=11, body=0x393
00 03 90                     certificate_list 总长 (3 字节前缀)
  00 03 8d                   第 1 张证书 DER 长度
  30 82 03 89 ...            X.509 DER (subject/issuer/公钥/签名)
```

握手里只有**证书链字节**；验证（签发链、有效期、域名、用途）是本地逻辑。

### 3.4 ServerKeyExchange (type=12, 仅 (EC)DHE)

```
0c 00 01 28                  type=12, body=0x128
03                           curve_type = named_curve
001d                         named_curve = x25519
20                           ECPoint 长度 (1 字节前缀): 32
[32 B] c7 51 ...             服务器临时 x25519 公钥
0804                         签名算法标识 = rsa_pss_rsae_sha256 (OpenSSL 3.x 附带)
0100                         签名长度 = 256
[256 B] 1c 44 ...            RSA-PSS 签名: 覆盖 client_random + server_random + 本报文参数
```

签名的作用：把"服务器身份"和"这次会话的临时公钥"绑定，防中间人替换 DH 参数。

### 3.5 ServerHelloDone (type=14) / ClientKeyExchange (type=16)

```
0e 00 00 00                  ServerHelloDone: 空 body，"我说完了，你发吧"

RSA 模式的 ClientKeyExchange:
10 00 01 02                  type=16, body=0x102
0102                         EncryptedPreMasterSecret 长度 = 258?? → 256 + 2字节长度前缀
```
准确结构：`u16 长度 + 密文`。密文 = RSA_PKCS1v15(服务器公钥, 0303 || 46B 随机)。

ECDHE 模式则是：`u8 长度 + 客户端临时公钥`。

### 3.6 ChangeCipherSpec / Finished (type=20)

```
14 03 03 00 01  01           CCS: 1 字节 "01"
16 03 03 00 28               加密记录头 (0x28=40 = 12 verify + 1 type + 16 GCM tag + …)
14 00 00 0c [12 B]           Finished: verify_data = PRF(master_secret,
                             "client finished", SHA256(所有握手消息)) 取 12 字节
```

Finished 是**第一个用协商密钥加密的报文**，作用是双向确认：
1. 对方推导出了相同密钥（能解密）；
2. 之前所有握手消息没被篡改（转录哈希进 PRF）。

## 4. 密钥推导链（RFC 5246 §6.3/§8.1）

```
premaster (48B)
   │  PRF(premaster, "master secret", client_random + server_random)      ← 经典
   │  PRF(premaster, "extended master secret", session_hash)              ← EMS(若协商)
   ▼
master_secret (48B)
   │  PRF(master, "key expansion", server_random + client_random)   ← 注意顺序反转!
   ▼
key_block = client_write_MAC_key(0 for AEAD) | server_write_MAC_key(0)
          | client_write_key(16) | server_write_key(16)
          | client_write_IV(4)    | server_write_IV(4)
```

GCM (AEAD) 套件：MAC key 长度为 0；fixed_iv 4 字节与每条记录 8 字节 explicit nonce
拼接成 12 字节 IV。`nonce = fixed_iv || explicit_nonce`。

verify_data：`PRF(master, "client finished"/"server finished", Hash(handshake_messages))`
截 12 字节。`handshake_messages` = 从 ClientHello 到（不含）本 Finished 的**全部握手消息字节**。

## 5. 已在本机验证的事实（scripts/verify_tls12_crypto.py）

1. 用服务器私钥解 ClientKeyExchange → 48B premaster，前 2 字节 `0303`，与 keylog 中
   OpenSSL 记录的 premaster 逐字节一致；
2. EMS 推导的 master_secret 与 keylog 一致（本握手协商了 RFC7627）;
3. key_block 切分出的 client/server write key 与 IV 进入 GCM；
4. 用 master_secret + 转录哈希复算的 client/server Finished.verify_data 与抓包值一致。

### 5.1 记录层密文解密（scripts/verify_tls12_records.py）

用 key_block 切出的 write key/fixed IV 对中继落盘的原始字节流逐条 AES-GCM 解密，
双向 Finished 与 3 条应用数据（"app data one/two/three"）全部解开。实测要点：

```
nonce = fixed_iv(4B) ‖ explicit_nonce(8B)   ← explicit nonce 是记录体前 8 字节
AAD   = seq(8B) ‖ type(1) ‖ version(2) ‖ 明文长度(2)   ← 13B, 含序号!
seq   = 每方向从 0 计数, 明文记录(CH/CKE/CCS)不递增 AEAD 序号 (实测 OpenSSL)
```

与 TLS 1.3 的差异: 1.3 的 nonce = static_iv XOR seq（隐式, 不占带宽）,
AAD 只有 5B 记录头, 密文尾部多 1B inner content type。

## 6. 与 TLS 1.3 的关键差异速览

| 维度 | TLS 1.2 | TLS 1.3 |
|---|---|---|
| 密钥交换 | RSA / (EC)DHE，premaster | 只有 (EC)DHE/PSK，直接进 HKDF |
| 密钥推导 | PRF(HMAC 双层) | HKDF (Extract/Expand) + 密钥链 |
| 握手轮数 | 2-RTT | 1-RTT（0-RTT 可选） |
| Finished 覆盖 | 转录哈希进 PRF | HMAC(finished_key, TH)，密钥分方向 |
| ServerHello 之后 | 全部明文（除 Finished） | EE/Cert/CV/Fin 全部加密 |
| 会话恢复 | session_id / session ticket | PSK + NewSessionTicket |
| 前向安全 | 仅 (EC)DHE 套件 | 强制（PSK-only 除外） |
