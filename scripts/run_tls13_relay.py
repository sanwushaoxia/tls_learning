#!/usr/bin/env python3
"""
TCP 中继抓包器: 在 127.0.0.1:8415 与 openssl s_server(8413) 之间双向转发,
同时把两个方向的原始字节落盘 —— 得到真实 TLS 记录流(含密文), 弥补
openssl -msg 只显示明文/不显示密文的不足。

输出: captures/tls13_relay_c2s.bin (客户端→服务器)
      captures/tls13_relay_s2c.bin (服务器→客户端)
同时复写 captures/tls13_msg.txt / tls13_keylog.txt (保证与字节流同一次会话)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tlslib.capture import tls_server, Relay, run_s_client  # noqa: E402

CAP = Path(__file__).resolve().parent.parent / "captures"
KEYLOG = CAP / "tls13_keylog.txt"

# openssl keylog 为追加模式, 先清空避免多会话混杂
if KEYLOG.exists():
    KEYLOG.unlink()

with tls_server(8413, "tls1_3", "ecdsa_server.crt", "ecdsa_server.key",
                extra_args=["-groups", "P-256"]):
    relay = Relay(8415, 8413, CAP / "tls13_relay_c2s.bin", CAP / "tls13_relay_s2c.bin")
    relay.start()
    try:
        run_s_client(
            ["-connect", "127.0.0.1:8415", "-tls1_3", "-groups", "P-256",
             "-msg", "-keylogfile", str(KEYLOG)],
            stdin=b"hello via relay\n",
            msg_out=CAP / "tls13_msg.txt")
    finally:
        relay.stop()

print(f"C2S {(CAP / 'tls13_relay_c2s.bin').stat().st_size} B, "
      f"S2C {(CAP / 'tls13_relay_s2c.bin').stat().st_size} B —— 原始流已保存")
