#!/usr/bin/env bash
# TLS 1.3 PSK 会话恢复 + 0-RTT 实验
# 两次连接:
#   第 1 次: 完整握手 (ECDHE + 证书), -sess_out 导出 resumption session
#   第 2 次: -sess_in PSK 恢复 + -early_data 发 0-RTT 数据
# 产物:
#   captures/tls13_psk_full_msg.txt   第一次握手 -msg
#   captures/tls13_psk_msg.txt        第二次 (PSK 恢复) 握手 -msg
#   captures/tls13_psk_session.pem    resumption session (含 Resumption PSK!)
#   captures/tls13_psk_keylog.txt     两次会话的密钥 (含 CLIENT_EARLY_TRAFFIC_SECRET)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CAP="$ROOT/captures"
TMP="$(mktemp -d)"

openssl s_server -accept 8413 -tls1_3 -quiet -www -early_data \
  -cert "$ROOT/certs/ecdsa_server.crt" -key "$ROOT/certs/ecdsa_server.key" \
  -groups P-256 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
sleep 0.6

echo "── 第 1 次连接: 完整握手, 导出 session ──"
(sleep 1.2; echo hello) | openssl s_client -connect 127.0.0.1:8413 -tls1_3 -groups P-256 \
  -sess_out "$CAP/tls13_psk_session.pem" \
  -msg -msgfile "$CAP/tls13_psk_full_msg.txt" \
  -keylogfile "$CAP/tls13_psk_keylog.txt" >/dev/null 2>&1

echo "── 第 2 次连接: PSK 恢复 + 0-RTT early data ──"
printf 'early secret payload (0-RTT)\n' > "$TMP/early.txt"
(sleep 1.5; echo late) | openssl s_client -connect 127.0.0.1:8413 -tls1_3 -groups P-256 \
  -sess_in "$CAP/tls13_psk_session.pem" -early_data "$TMP/early.txt" \
  -msg -msgfile "$CAP/tls13_psk_msg.txt" \
  -keylogfile "$CAP/tls13_psk_keylog.txt" 2>&1 | grep -iE "Reused|Early data" | head -3

rm -rf "$TMP"
echo "=== PSK 实验抓包完成 ==="
