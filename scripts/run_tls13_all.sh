#!/usr/bin/env bash
# 抓取完整的 TLS 1.3 握手 + 应用数据:
#  1. run_tls13.sh         : -msg 报文解析视图 + keylog (captures/tls13_*)
#  2. run_tls13_relay.py   : Python TCP 中继记录**原始字节流**(含密文记录),
#                            供 verify_tls13_crypto.py 做真实 AEAD 解密
#                            (captures/tls13_relay_{c2s,s2c}.bin)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
bash "$ROOT/scripts/run_tls13.sh"
python3 "$ROOT/scripts/run_tls13_relay.py"
echo "=== TLS1.3 完整抓取完成 ==="
