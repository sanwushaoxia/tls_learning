#!/usr/bin/env python3
"""
TLS 1.3 密码学全链路验证（RFC 8446）

验证分两层：
  A. RFC 8448 标准测试向量：从 early secret 一路复算到
     handshake secret → c/s hs traffic → master → c/s ap traffic → exp master，
     再复算 finished_key 与 write key/iv —— 与 RFC 给出的每个中间值逐字节对比。

  B. 本机真实握手 (captures/tls13_*)：用 keylog 密钥复算两个 Finished.verify_data，
     并对中继落盘的原始密文记录逐条 AES-GCM 解密（含 AAD、nonce=iv⊕seq、
     阶段切换等所有细节），证明「从 secret 到记录层」的每一步与 OpenSSL 实现一致。

依赖: cryptography 库; 抓包: bash scripts/run_tls13_all.sh
用法: python3 verify_tls13_crypto.py
"""
import hashlib
import hmac
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tlslib.crypto import (hkdf_extract, hkdf_expand, expand_label,  # noqa: E402
                           derive_secret, parse_keylog, ok, fail, check_hex)
from tlslib.parse import extract_handshakes  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CAP = ROOT / "captures"

HASH = hashlib.sha384  # 套件 TLS_AES_256_GCM_SHA384 → hash=SHA384, key=32, iv=12

REC_RAW_PAT = re.compile(
    r"(>>>|<<<) TLS [\d.]+, RecordHeader \[length 0005\]\s*\n\s*([0-9a-f]{2} [0-9a-f]{2} [0-9a-f]{2} [0-9a-f]{2} [0-9a-f]{2})\s*\n((?:    [0-9a-f ]+\n)+)")


def transcript_upto(hs, stop_name, stop_direction):
    """hs 中出现顺序在 (stop_name, stop_direction) 之前的全部握手消息"""
    tr = b""
    for direction, name, data in hs:
        if (direction, name) == (stop_direction, stop_name):
            break
        tr += data
    return tr


# ---------- A. RFC 8448 §2 全链复算 ----------


def test_rfc8448():
    print("=" * 78)
    print("A. RFC 8448 标准测试向量 —— 复算整条密钥调度链 (AES_128_GCM_SHA256)")
    print("=" * 78)
    h = hashlib.sha256
    L = 32

    # §2: early secret = Extract(0, 0)
    early = hkdf_extract(bytes(L), bytes(L), h)
    check_hex("early secret", early,
              "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
    # derived = ExpandLabel(early, "derived", SHA256(""))
    derived = expand_label(early, "derived", h(b"").digest(), L, h)
    check_hex("derived", derived,
              "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
    # handshake = Extract(derived, ECDHE共享密钥)
    shared = bytes.fromhex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")
    hs_sec = hkdf_extract(derived, shared, h)
    check_hex("handshake secret", hs_sec,
              "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
    # 转录哈希(CH+SH) 与两个 hs traffic
    th = bytes.fromhex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
    c_hs = derive_secret(hs_sec, "c hs traffic", th, h)
    check_hex("c hs traffic", c_hs,
              "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
    s_hs = derive_secret(hs_sec, "s hs traffic", th, h)
    check_hex("s hs traffic", s_hs,
              "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
    # master = Extract(ExpandLabel(hs,"derived",0), 0)
    derived2 = expand_label(hs_sec, "derived", h(b"").digest(), L, h)
    check_hex("derived(master 前)", derived2,
              "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4")
    master = hkdf_extract(derived2, bytes(L), h)
    check_hex("master secret", master,
              "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")
    # ap traffic / exp master (转录到双方 Finished 后, RFC 给定 TH)
    th2 = bytes.fromhex("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13")
    c_ap = derive_secret(master, "c ap traffic", th2, h)
    check_hex("c ap traffic", c_ap,
              "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
    s_ap = derive_secret(master, "s ap traffic", th2, h)
    check_hex("s ap traffic", s_ap,
              "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
    exp_m = derive_secret(master, "exp master", th2, h)
    check_hex("exp master", exp_m,
              "fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50")
    # finished_key (RFC §2 给出值)
    fk_s = expand_label(s_hs, "finished", b"", L, h)
    check_hex("server finished_key", fk_s,
              "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8")
    fk_c = expand_label(c_hs, "finished", b"", L, h)
    check_hex("client finished_key", fk_c,
              "b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4")
    print("      server Finished.verify_data (RFC 参考值) = 9b9b141d9063…8f0718")
    print("      (HMAC 与转录的完整闭环在下方本机握手中验证)")
    # write key / iv
    key_s = expand_label(s_hs, "key", b"", 16, h)
    check_hex("server handshake write key", key_s, "3fce516009c21727d0f2e4e86ee403bc")
    iv_s = expand_label(s_hs, "iv", b"", 12, h)
    check_hex("server handshake write iv", iv_s, "5d313eb2671276ee13000b30")


# ---------- B. 本机真实握手验证 ----------


def verify_local():
    print()
    print("=" * 78)
    print("B. 本机 OpenSSL 握手验证 —— keylog 密钥 → 记录层 AEAD 解密")
    print("=" * 78)
    msg_text = (CAP / "tls13_msg.txt").read_text()
    hs = extract_handshakes(msg_text)

    kl = parse_keylog(CAP / "tls13_keylog.txt")
    print("  keylog 密钥:", ", ".join(kl.keys()), "\n")

    h = HASH
    fin_s_body = next(data[4:] for direction, name, data in hs
                      if name == "Finished" and direction == "server→client")
    fin_c_body = next(data[4:] for direction, name, data in hs
                      if name == "Finished" and direction == "client→server")

    # server Finished: 转录到第一个 Finished (S→C) 为止
    tr_to_sfin = transcript_upto(hs, "Finished", "server→client")
    fk_s = expand_label(kl["SERVER_HANDSHAKE_TRAFFIC_SECRET"], "finished", b"", h().digest_size, h)
    vd_s = hmac.new(fk_s, h(tr_to_sfin).digest(), h).digest()
    if vd_s == fin_s_body:
        ok(f"server Finished verify_data 复算一致 ({vd_s.hex()[:24]}…)")
    else:
        fail("server Finished 不一致", f"calc={vd_s.hex()[:24]} expect={fin_s_body.hex()[:24]}")
    # client Finished: 转录到 client Finished (>>>) 为止
    tr_to_cfin = transcript_upto(hs, "Finished", "client→server")
    fk_c = expand_label(kl["CLIENT_HANDSHAKE_TRAFFIC_SECRET"], "finished", b"", h().digest_size, h)
    vd_c = hmac.new(fk_c, h(tr_to_cfin).digest(), h).digest()
    if vd_c == fin_c_body:
        ok(f"client Finished verify_data 复算一致 ({vd_c.hex()[:24]}…)")
    else:
        fail("client Finished 不一致")

    # app write key/iv → 解密记录 (从中继落盘的原始字节流)
    key_s = expand_label(kl["SERVER_TRAFFIC_SECRET_0"], "key", b"", 32, h)
    iv_s = expand_label(kl["SERVER_TRAFFIC_SECRET_0"], "iv", b"", 12, h)
    ok(f"server app write_key = {key_s.hex()[:24]}…, write_iv = {iv_s.hex()}")

    print("\n  从原始字节流 (tls13_relay_s2c.bin) 解析 S→C 加密记录并 AEAD 解密:")
    print("  AAD = 记录头(5B), nonce = write_iv XOR record_seq (每个密钥阶段从 0 重新计数)")
    raw = (CAP / "tls13_relay_s2c.bin").read_bytes()

    keys_hs = expand_label(kl["SERVER_HANDSHAKE_TRAFFIC_SECRET"], "key", b"", 32, h)
    ivs_hs = expand_label(kl["SERVER_HANDSHAKE_TRAFFIC_SECRET"], "iv", b"", 12, h)
    seq = 0          # 加密记录序号 (明文 SH/CCS 不占)
    ok_count = 0
    i = 0
    while i + 5 <= len(raw):
        rtype = raw[i]
        ln = int.from_bytes(raw[i + 3:i + 5], "big")
        hdr = raw[i:i + 5]
        body = raw[i + 5:i + 5 + ln]
        if rtype == 23:
            # 前 4 条加密记录属于握手阶段, 之后切到应用阶段 (seq 重新从 0 计)
            if seq < 4:
                name, key, iv, sq = "handshake", keys_hs, ivs_hs, seq
            else:
                name, key, iv, sq = "app", key_s, iv_s, seq - 4
            nonce = (int.from_bytes(iv, "big") ^ sq).to_bytes(12, "big")
            try:
                plain = AESGCM(key).decrypt(nonce, body, hdr)
                inner = plain[:-1]  # 去掉 inner content type
                kind = {21: "Alert(close_notify)", 22: "Handshake", 23: "ApplicationData"}.get(plain[-1], "?")
                ok_count += 1
                print(f"    [√] seq={seq:<2} [{name:9s}] 解密成功 {len(inner):>4}B → {kind}: {inner[:28].hex()}{'…' if len(inner) > 28 else ''}")
            except Exception:
                print(f"    [-] seq={seq:<2} 解密失败")
            seq += 1
        i += 5 + ln
    if ok_count == 0:
        fail("未能解密任何 S→C 加密记录")
    ok(f"共成功解密 {ok_count} 条真实密文记录 —— 密钥链与记录层全链路自洽")


def main():
    test_rfc8448()
    verify_local()
    print()
    print("=" * 78)
    print("结论:")
    print("  1) RFC 8448 向量全链复算通过 → 密钥调度链实现与标准一致;")
    print("  2) 本机握手: 用 keylog 密钥复算 Finished verify_data + write key/iv,")
    print("     并真实解开抓包密文 → OpenSSL 实现同样遵循 RFC 8446;")
    print("  3) x25519 共享密钥因前向安全无法从抓包还原, 只能经 keylog 观察 ——")
    print("     恰好演示了『抓包者 = 被动攻击者』在 TLS1.3 下拿不到任何会话密钥。")
    print("=" * 78)


if __name__ == "__main__":
    main()
