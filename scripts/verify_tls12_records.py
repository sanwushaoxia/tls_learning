#!/usr/bin/env python3
"""
TLS 1.2 记录层密文解密验证（RFC 5246 §6.2.3.3, GCM）

用与 verify_tls12_crypto.py 相同推导的 write key / fixed IV，对中继落盘的
原始字节流 (captures/tls12_relay_{c2s,s2c}.bin) 中的加密记录逐条解密：

  TLS1.2 GCM (RSA 套件 0x009C) —— 实测与 OpenSSL 逐字节吻合:
    nonce = fixed_iv(4B, key_block) || explicit_nonce(8B, 记录体前 8 字节)
            —— 对比 TLS1.3: static_iv(12B) XOR uint64(seq)，无需传 nonce
    AAD   = seq(8B) || type(1) || version(2) || length(2, **明文长度**)
            —— 对比 TLS1.3: 仅 5B 记录头，无独立序号
    密文  = 明文 || GCM tag(16B)
    seq   = 每方向从 0 计数；**明文记录 (CH/CKE/CCS) 不递增 AEAD 序号**
            (实测 OpenSSL 行为; Finished 是该方向第一条加密记录 → seq=0)

先抓原始流: python3 scripts/run_tls12_relay.py
用法: python3 verify_tls12_records.py
"""
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as apad
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tlslib.crypto import prf, parse_keylog, ok, fail  # noqa: E402
from tlslib.parse import extract_handshakes  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CAP = ROOT / "captures"

TYPE_NAMES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData"}


def derive_keys():
    """从抓包复算 key_block (与 verify_tls12_crypto.py 相同推导)"""
    hs = extract_handshakes((CAP / "tls12_rsa_ks_msg.txt").read_text(errors="replace"))
    kl = parse_keylog(CAP / "tls12_rsa_ks_keylog.txt")
    ch = next(d for _, n, d in hs if n == "ClientHello")
    sh = next(d for _, n, d in hs if n == "ServerHello")
    cke = next(d for _, n, d in hs if n == "ClientKeyExchange")

    epms = cke[6:]  # type(1)+len(3) + u16 前缀(2) 之后是 256B 密文
    priv = serialization.load_pem_private_key((ROOT / "certs/rsa_server.key").read_bytes(), None)
    pms = priv.decrypt(epms, apad.PKCS1v15())
    tr = b""
    for _, name, data in hs:
        tr += data
        if name == "ClientKeyExchange":
            break
    ms = prf(pms, "extended master secret", hashlib.sha256(tr).digest(), 48)
    if ms != kl.get("CLIENT_RANDOM"):
        fail("master_secret 与 keylog 不一致 (msg/keylog 可能不是同一次会话)")

    key_block = prf(ms, "key expansion", sh[6:38] + ch[6:38], 40)
    return {
        "client_key": key_block[0:16], "server_key": key_block[16:32],
        "client_iv": key_block[32:36], "server_iv": key_block[36:40],
    }


def parse_records(raw: bytes):
    """把原始 TLS 流切为 [(type, version, body, header), ...]"""
    recs = []
    i = 0
    while i + 5 <= len(raw):
        rtype = raw[i]
        ver = raw[i+1:i+3]
        ln = int.from_bytes(raw[i+3:i+5], "big")
        recs.append((rtype, ver, raw[i+5:i+5+ln], raw[i:i+5]))
        i += 5 + ln
    return recs


def decrypt_tls12_gcm(key, fixed_iv, seq, rtype, ver, body):
    """解密一条 TLS1.2 GCM 记录, 返回明文"""
    explicit_nonce = body[:8]
    ct = body[8:]
    plaintext_len = len(body) - 8 - 16
    nonce = fixed_iv + explicit_nonce
    aad = (seq.to_bytes(8, "big") + bytes([rtype]) + ver
           + plaintext_len.to_bytes(2, "big"))
    return AESGCM(key).decrypt(nonce, ct, aad)


def main():
    print("=" * 78)
    print("TLS 1.2 记录层密文解密 —— AES-128-GCM (0x009C)")
    print("=" * 78)
    keys = derive_keys()
    ok(f"key_block 复算: client_write_key={keys['client_key'].hex()[:16]}… "
       f"client_fixed_iv={keys['client_iv'].hex()} server_fixed_iv={keys['server_iv'].hex()}")

    for direction, fname in [("C→S", "tls12_relay_c2s.bin"), ("S→C", "tls12_relay_s2c.bin")]:
        raw = (CAP / fname).read_bytes()
        print(f"\n── {direction} ({fname}, {len(raw)} B) ──")
        role = "client" if direction == "C→S" else "server"
        seq = 0  # 仅加密记录递增 (明文记录不占, 实测 OpenSSL 行为)
        ok_count = 0
        for rtype, ver, body, hdr in parse_records(raw):
            tname = TYPE_NAMES.get(rtype, f"type{rtype}")
            is_encrypted = rtype in (22, 23, 21) and len(body) > 17 and seq > 0 or rtype == 23
            # TLS1.2 中加密记录与明文记录 type 相同 (Finished 仍是 22)。
            # 判别: 尝试解密, 失败则视为明文/未协商完成。
            if rtype in (22, 23):
                try:
                    plain = decrypt_tls12_gcm(keys[f"{role}_key"], keys[f"{role}_iv"],
                                              seq, rtype, ver, body)
                except Exception:
                    print(f"    [i] seq={seq:<3} {tname:<16} (明文/未到加密阶段, len={len(body)})")
                    continue
                # TLS1.2 明文就是内容本身 (无 TLS1.3 的 inner type 尾字节)
                ok_count += 1
                hs_show = ""
                if plain[0] == 20 and plain[:1] == b"\x14":
                    hs_show = " (Finished.verify_data)"
                print(f"    [√] seq={seq:<3} {tname:<16} → {len(plain):>3}B {plain[:24].hex()}{'…' if len(plain) > 24 else ''}{hs_show}")
                seq += 1
            else:
                print(f"    [i] seq={seq:<3} {tname:<16} (明文, len={len(body)})")
        if ok_count == 0:
            fail(f"{direction} 方向未能解密任何记录")
        ok(f"{direction} 方向共解密 {ok_count} 条加密记录")

    print("\n" + "=" * 78)
    print("对比要点 (TLS1.2 vs TLS1.3 记录层):")
    print("  nonce:  1.2 = fixed_iv(4B) ‖ explicit_nonce(8B, 随每条记录传输)")
    print("          1.3 = static_iv(12B) XOR uint64(record_seq) —— 隐式, 不占带宽")
    print("  AAD:    1.2 = seq(8B) + type(1) + ver(2) + 明文长度(2) = 13B (含序号!)")
    print("          1.3 = 记录头 5B (序号并入 nonce)")
    print("  明文:   1.2 = 内容 (Finished = 4B头+12B verify)")
    print("          1.3 = 内容 + 1B inner type (尾部)")
    print("=" * 78)


if __name__ == "__main__":
    main()
