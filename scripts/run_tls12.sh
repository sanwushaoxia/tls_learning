#!/usr/bin/env bash
# 抓取一次 TLS 1.2 握手（-msg + keylog）
# 用法: run_tls12.sh [cipher]
#   AES128-GCM-SHA256            静态 RSA 交换：premaster 可用服务器私钥解出，
#                                用于从零复算 master_secret（输出 *_rsa_ks_*）
#   ECDHE-RSA-AES128-GCM-SHA256  默认，ECDHE 交换（输出 *_ecdhe_*）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CAP="$ROOT/captures"
CIPHER="${1:-ECDHE-RSA-AES128-GCM-SHA256}"
case "$CIPHER" in
  AES*-GCM-*) TAG="rsa_ks"; PORT=8412 ;;
  *)          TAG="ecdhe";  PORT=8412 ;;
esac

openssl s_server -accept $PORT -tls1_2 -quiet \
  -cert "$ROOT/certs/rsa_server.crt" -key "$ROOT/certs/rsa_server.key" &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
sleep 0.6

# 用 (sleep; echo; sleep) 模拟应用数据再关闭，保证握手完整、keylog 被写出
rm -f "$CAP"/tls12_*_keylog.txt
KEYLOG="$CAP/tls12_${TAG}_keylog.txt"
openssl s_client -connect 127.0.0.1:$PORT -tls1_2 -cipher "$CIPHER" \
  -msg -brief -keylogfile "$KEYLOG" \
  < <(sleep 1.2; echo "hello tls1.2"; sleep 0.4) \
  | tee "$CAP/tls12_${TAG}_msg.txt"
echo "=== TLS1.2 [$CIPHER] capture done ==="
