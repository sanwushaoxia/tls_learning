#!/usr/bin/env bash
# 抓取一次完整的 TLS 1.3 握手（-msg + keylog）
# 默认组 P-256（key_share 可解析），套件 TLS_AES_128_GCM_SHA256
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CAP="$ROOT/captures"

openssl s_server -accept 8413 -tls1_3 -quiet \
  -cert "$ROOT/certs/ecdsa_server.crt" -key "$ROOT/certs/ecdsa_server.key" \
  -groups P-256 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
sleep 0.6

rm -f "$CAP/tls13_keylog.txt"
KEYLOG="$CAP/tls13_keylog.txt"
openssl s_client -connect 127.0.0.1:8413 -tls1_3 -groups P-256 \
  -msg -brief -keylogfile "$KEYLOG" \
  < <(sleep 1.2; echo "hello tls1.3"; sleep 0.4) \
  | tee "$CAP/tls13_msg.txt"
echo "=== TLS1.3 capture done ==="
