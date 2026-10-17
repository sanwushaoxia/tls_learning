# TLS 1.3 报文与密码学详解（RFC 8446）

> 配套实验: `bash scripts/run_tls13_all.sh`（-msg 视图 + keylog + 中继原始字节流）
> 解析: `python3 scripts/parse_handshake.py captures/tls13_msg.txt`
> 验证: `python3 scripts/verify_tls13_crypto.py`

## 1. 一条记录看懂 TLS 1.3 的"加密提前"

TLS 1.3 抓包中你会发现：ServerHello 之后**所有握手报文都变成了 ApplicationData 记录**
（type=23）。握手消息被重新设计为：

```
struct {
    opaque content[TLSPlaintext.length];   // 握手消息等
    uint8  inner_type = handshake;          // 真实类型放在密文末尾
    opaque padding[0..2^12];
} TLSInnerPlaintext;
```

- 外层 type 恒为 23（应用数据），真实类型在**密文最后一字节**；
- 每条记录都带 AEAD 认证标签（防篡改）；
- ChangeCipherSpec 只剩兼容哑元（type=20, 内容 01，**不加密也不占序号语义**）。

## 2. 握手流程（1-RTT）

```
ClientHello                                                  ─→
                        ←─ ServerHello, {EncryptedExtensions,
                           Certificate, CertificateVerify, Finished}   ← 密文!
{Finished}                                                   ─→
                        ←─ {NewSessionTicket}, {NewSessionTicket}      ← 密文!
```

`{}` 表示处于加密状态（server handshake traffic secret）。

### 2.1 ClientHello —— 一切能力的载体

```
01 00 00 ef                  type=1, body=239
03 03                        legacy_version (死字段, 兼容中间件)
[32 B]                       random (仍存在, 参与转录哈希)
20 [32 B]                    legacy_session_id: 兼容字段, 32B 随机 (1 字节长度前缀)
00 06 1302 1303 1301         cipher_suites: 只表达 AEAD+HKDF 组合
01 00                        compression: 强制 null
00 a0                        extensions:
  0000 ...                   server_name (SNI, 明文泄露访问域名!)
  000a ...                   supported_groups (椭圆曲线/FFDHE 菜单)
  000d ...                   signature_algorithms (证书签名验算)
  002b 0003 02 0304          supported_versions: 0x0304 = TLS1.3 ← 真正的版本协商
  0033 0047 0017 0041 04...  key_share: group=P-256, 65B 未压缩公钥 (与 CH 同时发出 → 省 1-RTT)
  002d 0002 01 01            psk_key_exchange_modes: psk_dhe_ke
  0029 ...                   pre_shared_key (PSK 恢复时; 必须是最后一个扩展)
```

学习点：**key_share 与 ClientHello 同发**是 1.3 快的根本原因——服务器收到即可算出
共享密钥，无需第二个来回。

### 2.2 ServerHello —— 极简

```
02 00 00 97
03 03                        永远 0303
[32 B]                       random (TLS1.3 随机不再有特殊语义)
20 [32 B]                    session_id: 逐字节回显客户端的 (兼容)
1302                         选定 TLS_AES_256_GCM_SHA384
01                           compression = null
00 2e                        extensions:
  002b 0002 0304             supported_versions: TLS1.3
  0033 0024 001d 0020 [32B]  key_share: x25519 服务器公钥
```

**ServerHello 里不再有证书！** 从 EncryptedExtensions 起全部加密。

### 2.3 加密握手四件套

| 报文 | type | 内容与作用 |
|---|---|---|
| EncryptedExtensions | 8 | 服务器扩展（ALPN、SNI 确认等）—— 1.2 中"服务器扩展"明文发送，1.3 全部加密 |
| Certificate | 11 | 证书链; 结构 = `request_context(u8, 空)` + `证书列表(3B 前缀)` |
| CertificateVerify | 15 | `signature_algorithm(2B, 如 0x0403=ecdsa_secp256r1_sha256)` + 签名; 签名内容 = 字符串"TLS 1.3, server CertificateVerify"(64B 重复) + 0x00 + **全部转录哈希** —— 把服务器身份绑定到整个握手 |
| Finished | 20 | verify_data = HMAC(finished_key, TH(transcript)); finished_key 由本方向 traffic secret 推出 |

NewSessionTicket (type=4) 在握手完成后由服务器发送（可多条）：

```
04 00 00 e5                  type=4, body=229
00 00 1c 20                  ticket_lifetime = 7200s
25 44 93 9d                  ticket_age_add (随机, 混淆客户端票据年龄)
08                           ticket_nonce 长度 (u8!): 8 字节
00 00 ... 00 01              nonce (恢复连接的计数)
00 d0 [208 B]                ticket (服务器加密自鉴权, 客户端不可读)
00 00                        extensions
```

PSK 恢复握手时，客户端把 ticket 放进 pre_shared_key 扩展回传 → 1-RTT 甚至 0-RTT。

## 3. 密钥调度 (Key Schedule, RFC 8446 §7.1) —— 一张图

```
             0
             │
             ▼  HKDF-Extract(salt=0, ikm=0)             (PSK 时 ikm=psk)
       early_secret ──────────────► ExpandLabel("c e traffic", TH0) ──► 0-RTT 密钥
             │
             ▼  ExpandLabel("derived", 0)   ——"换盐"
   ┌── salt ─┐
   │         ▼  HKDF-Extract(salt, ikm=ECDHE共享密钥)
   │     handshake_secret ──► ExpandLabel("c hs traffic", TH(CH..SH)) ─► client 握手密钥
   │         │             └► ExpandLabel("s hs traffic", TH(CH..SH)) ─► server 握手密钥
   │         │                     每个再 ExpandLabel("key"/"iv") → 写密钥 & IV
   │         ▼  ExpandLabel("derived", 0)
   │    ┌── salt ─┐
   │    │         ▼  HKDF-Extract(salt, ikm=0)
   │    │     master_secret ──► ExpandLabel("c ap traffic", TH(全握手)) ─► client 应用密钥
   │    │                    ├► ExpandLabel("s ap traffic", TH(全握手)) ─► server 应用密钥
   │    │                    └► ExpandLabel("exp master"/"res master") ─► exporter/恢复
```

三个记忆点：
1. **HKDF-Extract 只出现 3 次**（early/handshake/master），其余全是 Expand；
2. **每一层用"上一层派生的 derived"当新盐**，实现密码学分段（隔离各阶段）;
3. **traffic secret → 记录密钥**：`key = ExpandLabel(secret,"key","",len)`,
   `iv = ExpandLabel(secret,"iv","",12)`。

### 记录层 AEAD（AES-GCM）

```
key  (32B for AES-256)
iv   (12B, 静态)
nonce_i = iv XOR uint64_BE(record_seq, 左对齐到 12B)
AAD     = 记录头 5 字节 (type || version || length)   ← 必须认证!
seq     = 每方向独立从 0 计数; 每个密钥阶段(hs→ap)重新从 0 计
```

## 4. Finished 的精妙设计

```
finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", hash_len)
verify_data  = HMAC(finished_key, TranscriptHash(到此为止的全部握手消息))
```

- client 与 server 用**各自的 traffic secret**，互不相同;
- verify_data 本身又被**外层 AEAD 加密**（双重保护）;
- 转录哈希覆盖所有握手消息 → 篡改任何一条消息（哪怕只是改个套件字节）都会令
  Finished 校验失败 → 中间人无法悄悄降级。

## 5. 已在本机验证的事实（scripts/verify_tls13_crypto.py）

1. **RFC 8448 标准测试向量**：从 early secret 一路复算 handshake secret、c/s hs traffic、
   master、c/s ap traffic、exp master、finished_key、write key/iv —— 与 RFC 逐字节一致;
2. 本机 OpenSSL 会话：用 keylog 密钥复算两个 Finished.verify_data，与抓包一致;
3. 用 `ExpandLabel(SERVER_TRAFFIC_SECRET_0,"key"/"iv")` 得到的密钥，对中继落盘的
   **原始密文记录**逐条 AES-256-GCM 解密：7 条全部成功
   （4 条握手阶段：EE/Cert/CV/Finished；2 条 NewSessionTicket + 1 条 close_notify
   属应用阶段）；
4. x25519 共享密钥**无法**从抓包还原（前向安全），keylog 是唯一观察窗口 ——
   这正是 TLS 1.3 对被动攻击者的保证。

## 6. 学习检查清单

- [ ] 能徒手写出 ClientHello 每个 1 字节长度前缀的位置（session_id/nonce 是 u8！）
- [ ] 能解释 key_share 为什么必须在 ClientHello 里（1-RTT 的由来）
- [ ] 能默画密钥调度图的 3 次 Extract 与各 ExpandLabel 标签
- [ ] 能解释 CertificateVerify 与 Finished 的区别（身份认证 vs 密钥确认）
- [ ] 能解释为什么 TLS1.3 中间人无法降级到 1.2（转录哈希 + Finished）

## 7. PSK 会话恢复与 0-RTT（RFC 8446 §2.2）

> 实验: `bash scripts/run_tls13_psk.sh` → `python3 scripts/verify_tls13_psk.py`

### 7.1 两种握手的报文序列对比（真实抓包）

```
完整握手: CH → SH → EE → Certificate → CertificateVerify → Fin(S) → Fin(C) → NST×2
PSK 恢复: CH → SH → EE → Fin(S) → EndOfEarlyData → Fin(C) → NST
```

恢复握手**没有 Certificate/CertificateVerify** —— 服务器身份由 PSK 隐式认证
（能算出相同 binder/traffic secret 就证明对方持有 PSK）。

### 7.2 pre_shared_key 扩展（ClientHello 的最后一个扩展）

```
identities: u16 总长 | [ u16 identity_len | ticket(32B) | obfuscated_ticket_age(4B) ]
binders:    u16 总长 | [ u8 binder_len(48) | binder(SHA384) ]
```

identity 就是第一次握手里 NewSessionTicket 的 ticket + 混淆年龄。

### 7.3 binder 复算（防篡改/防重放的核心）

```
resumption_PSK ← session 文件 (openssl sess_id -text 可见 "Resumption PSK")
early_secret   = HKDF-Extract(0, PSK)
binder_secret  = HKDF-Expand-Label(early, "res binder", Hash(""), hash_len)
finished_key   = HKDF-Expand-Label(binder_secret, "finished", "", hash_len)
binder         = HMAC(finished_key, Transcript-Hash(TruncatedClientHello))
```

- `TruncatedClientHello` = ClientHello **截去 binders 向量**（u16 总长 + 各 binder），
  其余字节与长度字段保持原样；
- **易错点**：`Derive-Secret` 的 context 永远是 `Hash(transcript)`，空 transcript 时
  是 `Hash("")` 而不是空字节串 —— 用错会得到完全不同的 binder（本项目实测踩过）。

### 7.4 0-RTT early data

```
c e traffic = Derive-Secret(early_secret, "c e traffic", TH(ClientHello))
```

0-RTT 数据用 early traffic secret 加密，在 ServerHello 之前就发出（省 1-RTT）。
结束标记是 `EndOfEarlyData`（type=5）。**安全限制：0-RTT 无防重放保护** ——
攻击者可以原样重放整段 0-RTT 流量，所以应用层必须只在幂等请求上接受 0-RTT。

### 7.5 已验证事实

1. binder 复算与 ClientHello 中实际值逐字节一致；
2. `CLIENT_EARLY_TRAFFIC_SECRET` 从 PSK 出发复算与 keylog 一致；
3. 恢复握手报文序列确实省去证书与签名。

## 8. mTLS 双向认证（RFC 8446 §4.3.2）

> 实验: `bash scripts/run_mtls.sh` → `python3 scripts/verify_mtls.py`

### 8.1 报文序列（真实抓包）

```
CH → SH → EE → CertificateRequest → Certificate(S) → CertificateVerify(S) → Fin(S)
  → Certificate(C) → CertificateVerify(C) → Fin(C) → NST×2
```

- **CertificateRequest** (type=13): `certificate_request_context(u8 vector, 常 0)`
  + signature_algorithms 等扩展 —— 服务器在此声明接受哪些客户端签名算法；
- 客户端 Certificate 的 `certificate_request_context` 必须逐字节回显请求中的值。

### 8.2 CertificateVerify 签名（双方对称）

```
签名输入 = 0x20 重复 64 次 || "TLS 1.3, client CertificateVerify" || 0x00
           || Transcript-Hash(到本 CV 为止的全部握手消息)      ← 套件哈希 (SHA384)
签名算法 = CertificateVerify 里的 signature_algorithm 字段
           (如 0x0403=ecdsa_secp256r1_**sha256**)              ← 签名哈希可能是 SHA256!
```

**易错点**：Transcript-Hash 用套件哈希（SHA384），而 ECDSA 签名本身用
signature_algorithm 指定的哈希（0x0403 → SHA256）—— 两者是独立的。

### 8.3 已验证事实

1. 客户端证书确由实验用 Client-CA 签发（CA 公钥验签通过）；
2. 客户端 CertificateVerify 用**客户端证书公钥**真实验签通过 ——
   证明「持有私钥」与「这条握手」被密码学绑定；
3. 服务器 CV 是完全对称的流程。
