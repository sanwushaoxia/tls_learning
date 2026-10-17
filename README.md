# TLS 1.2 / 1.3 学习项目

用 OpenSSL 在本机扮演客户端与服务器，抓取**真实握手报文**，逐字段解析每类报文，
并用 Python 从密码学上**复算并验证**交互中的每一步计算。

## 环境要求

- OpenSSL ≥ 3.0（`openssl version`）
- Python 3.10+，`pip install -r requirements.txt`（cryptography、pytest）

## 快速开始（Makefile 一键化）

```bash
make help           # 查看全部目标
make all            # 跑全部实验 + 解析 + 验证 + 测试
make test           # pytest 单元测试
make clean          # 清理产物
```

或单独运行每个实验：

| 命令 | 实验内容 |
|---|---|
| `make tls12-ecdhe` | TLS 1.2 ECDHE 握手 + keylog |
| `make tls12-rsa` | TLS 1.2 静态 RSA 握手（premaster 可用服务器私钥解出） |
| `make tls13` | TLS 1.3 握手 (-msg + keylog) |
| `make tls13-relay` | TLS 1.3 中继抓包（原始字节流，含密文） |
| `make tls12-records` | TLS 1.2 记录层密文解密（GCM nonce/AAD 全对比） |
| `make tls13-psk` | PSK 会话恢复 + 0-RTT（binder 复算） |
| `make mtls` | mTLS 双向认证（客户端证书 + CertificateVerify 验签） |
| `make parse` | 解析三份抓包的报文字段 |
| `make verify` | TLS 1.2 + TLS 1.3 密码学全链路验证 |

## 目录

```
certs/                  服务器证书 (RSA/ECDSA 自签) + 客户端证书 (Client-CA 签发)
captures/               抓包产物 (msg/keylog/原始字节流/PSK session)
scripts/
  tlslib/               可复用库
    parse.py            报文解析 (Reader/extract/parse_*/字段字典)
    crypto.py           PRF/HKDF/keylog 解析/验证输出工具
    capture.py          s_server 上下文管理器 + TCP 中继
  run_tls12.sh          TLS1.2 抓包 (参数: 套件名)
  run_tls13.sh          TLS1.3 抓包
  run_tls13_relay.py    TLS1.3 中继抓包 (原始字节)
  run_tls13_all.sh      tls13 + relay 组合
  run_tls12_relay.py    TLS1.2 中继抓包 (记录解密实验用)
  run_tls13_psk.sh      PSK 恢复 + 0-RTT 实验
  run_mtls.sh           mTLS 实验
  parse_handshake.py    解析 CLI (薄入口 → tlslib.parse)
  verify_tls12_crypto.py    TLS1.2 PRF 全链路验证
  verify_tls12_records.py   TLS1.2 记录层密文解密
  verify_tls13_crypto.py    TLS1.3 HKDF 全链路验证 + 密文解密
  verify_tls13_psk.py       PSK binder 复算 + 0-RTT 密钥验证
  verify_mtls.py            mTLS CertificateVerify 真实验签
  Makefile / requirements.txt / .gitignore
docs/
  tls12_notes.md        TLS1.2 报文逐字段 + PRF + 记录层解密要点
  tls13_notes.md        TLS1.3 报文逐字段 + 密钥调度 + PSK/0-RTT + mTLS
tests/                  pytest 单元测试 (RFC 向量 + 解析回归)
```

## 学习路线（建议顺序）

### 第 1 步 · 记录层
先看 `parse_handshake.py` 输出的"记录层视图"：type/版本/长度三字段，明文与密文记录的差异。
知识点：TLS 是「记录层 + 上层协议」的分层设计。

### 第 2 步 · TLS 1.2 握手报文
逐字段读 `captures/tls12_ecdhe_msg.txt` 的解析输出，对照 `docs/tls12_notes.md` §3。
重点：random、session_id（1 字节长度前缀!）、cipher_suites、ServerKeyExchange 的签名。

### 第 3 步 · TLS 1.2 密码学验证
跑 `verify_tls12_crypto.py`：RSA 解出 premaster → PRF(EMS) → master_secret →
key_block → 复算双向 Finished.verify_data。
思考题：为什么 RSA 交换可以这样做而 ECDHE 不行？（前向安全）

### 第 4 步 · TLS 1.2 记录层解密
`make tls12-records`：用推导密钥真实解开密文记录。
对比 1.2/1.3 的 nonce 构造与 AAD 差异（见 docs/tls12_notes.md §5.1）。

### 第 5 步 · TLS 1.3 握手报文与密钥调度
对照 `docs/tls13_notes.md` §2-§4 读 `captures/tls13_msg.txt` 解析输出。
`verify_tls13_crypto.py` 先用 RFC 8448 向量自检实现，再真实解开 7 条密文记录。

### 第 6 步 · PSK 会话恢复与 0-RTT
`make tls13-psk`：对比恢复握手省去的报文，复算 binder（含 Derive-Secret 的
`Hash("")` 易错点），验证 0-RTT 密钥链。理解 0-RTT 的防重放缺陷。

### 第 7 步 · mTLS 双向认证
`make mtls`：解析 CertificateRequest，真实验证客户端 CertificateVerify 签名
（用客户端证书公钥）。注意签名哈希（SHA256）与转录哈希（SHA384）的区别。

### 第 8 步 · 自由实验
- 换曲线：`run_tls13.sh` 里 `-groups P-256` 改 `X25519`
- 换套件：`run_tls12.sh` 的 cipher 参数换成 `ECDHE-ECDSA-*`（需要 ecdsa 证书）
- TLS 1.2 session 恢复：`openssl s_client -reconnect` 观察 session ticket 复用
- 用 `openssl s_client -keymatexport` 导出 keying material 并自行 HKDF 验证

## 常见问题

- **keylog 是追加模式**：OpenSSL 向 `-keylogfile` 追加，多次抓包后旧会话会残留；
  脚本已在抓包前清理。解析时取最后一组即最新会话。
- **-msg 看不到密文字节**：`-msg` 只打印解密后的内容；要看原始密文用中继抓包
  （`run_tls13_relay.py` / `run_tls12_relay.py`）或 `tcpdump -i lo -w`（需 root）。
- **Finished/binder 验证失败的排查**：确认 msg/keylog/session 来自同一次连接。
- **PSK 实验的 PSK 来源**：`openssl sess_id -text` 可看到 session 文件里的
  "Resumption PSK"，binder 复算就以此为根。
