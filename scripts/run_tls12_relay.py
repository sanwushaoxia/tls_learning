#!/usr/bin/env python3
"""
TLS 1.2 中继抓包器: 复用 tlslib.capture, 抓取静态 RSA 套件 (AES128-GCM-SHA256)
会话的原始字节流, 供 verify_tls12_records.py 做记录层密文解密。

输出: captures/tls12_rsa_ks_msg.txt / tls12_rsa_ks_keylog.txt
      captures/tls12_relay_c2s.bin / tls12_relay_s2c.bin (原始流, 含密文)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tlslib.capture import tls_server, Relay, run_s_client  # noqa: E402

CAP = Path(__file__).resolve().parent.parent / "captures"
KEYLOG = CAP / "tls12_rsa_ks_keylog.txt"

for old in CAP.glob("tls12_rsa_ks_keylog.txt"):
    old.unlink()  # openssl keylog 为追加模式, 先清空

with tls_server(8412, "tls1_2", "rsa_server.crt", "rsa_server.key"):
    relay = Relay(8416, 8412, CAP / "tls12_relay_c2s.bin", CAP / "tls12_relay_s2c.bin")
    relay.start()
    try:
        # 用 sleep 分段喂 stdin, 让应用数据成为多条加密记录
        import subprocess, time as _t
        client = subprocess.Popen(
            ["openssl", "s_client", "-connect", "127.0.0.1:8416", "-tls1_2",
             "-cipher", "AES128-GCM-SHA256", "-msg", "-keylogfile", str(KEYLOG), "-ign_eof"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            for line in [b"app data one\n", b"app data two\n", b"app data three\n"]:
                client.stdin.write(line); client.stdin.flush()
                _t.sleep(0.4)
            client.stdin.close()
            client.wait(timeout=8)
        except subprocess.TimeoutExpired:
            client.kill()
        # s_client 的 -msg 输出无法经 Popen 拿到完整明文流时, 从 stdout 提取
        (CAP / "tls12_rsa_ks_msg.txt").write_bytes(client.stdout.read())
    finally:
        relay.stop()

print(f"C2S {(CAP / 'tls12_relay_c2s.bin').stat().st_size} B, "
      f"S2C {(CAP / 'tls12_relay_s2c.bin').stat().st_size} B —— 原始流已保存")
