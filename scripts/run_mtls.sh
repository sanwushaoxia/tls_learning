#!/usr/bin/env bash
# mTLS 双向认证实验 (TLS 1.3):
#   服务器要求客户端证书 (-Verify 1 + -verifyCA), 客户端出示 client.crt
# 产物:
#   captures/mtls_msg.txt       -msg 视图 (含 CertificateRequest → 客户端 Certificate/CV)
#   captures/mtls_keylog.txt    密钥
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CAP="$ROOT/captures"

openssl s_server -accept 8417 -tls1_3 -quiet -www \
  -cert "$ROOT/certs/ecdsa_server.crt" -key "$ROOT/certs/ecdsa_server.key" \
  -groups P-256 -Verify 1 -verifyCAfile "$ROOT/certs/client_ca.crt" &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
sleep 0.6

rm -f "$CAP/mtls_keylog.txt"
(sleep 1.2; echo hello mtls) | openssl s_client -connect 127.0.0.1:8417 -tls1_3 -groups P-256 \
  -cert "$ROOT/certs/client.crt" -key "$ROOT/certs/client.key" \
  -msg -msgfile "$CAP/mtls_msg.txt" \
  -keylogfile "$CAP/mtls_keylog.txt" 2>&1 | grep -iE "Acceptable client|Verification|Verify return" | head -5

echo "=== mTLS 抓包完成 ==="
