#!/usr/bin/env python3
"""
TLS 1.2 密码学全链路验证（RFC 5246）

对静态 RSA 密钥交换的握手 (captures/tls12_rsa_ks_*)，从报文字节出发复算：
  1. 用服务器 RSA 私钥解密 ClientKeyExchange 里的 EncryptedPreMasterSecret
     → 得到 48 字节 premaster (2B 版本 + 46B 随机)
  2. premaster --PRF--> master_secret (经典 RFC5246 与 EMS RFC7627 两种推导)
     与 keylog 中 OpenSSL 记录的 master_secret 对比
  3. master_secret + randoms --PRF--> key_block → 切出 write key / IV
  4. 复算双向 Finished.verify_data 与抓包值比对
依赖: cryptography 库; 抓包: bash scripts/run_tls12.sh AES128-GCM-SHA256
用法: python3 verify_tls12_crypto.py
"""
import hashlib
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as apad

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tlslib.crypto import p_hash, prf, parse_keylog, ok, fail  # noqa: E402
from tlslib.parse import extract_handshakes  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CAP = ROOT / "captures"


def main():
    print("=" * 78)
    print("TLS 1.2 密码学验证 —— 静态 RSA 交换 + AES-128-GCM (0x009C)")
    print("=" * 78)

    hs = extract_handshakes((CAP / "tls12_rsa_ks_msg.txt").read_text())
    kl = parse_keylog(CAP / "tls12_rsa_ks_keylog.txt")

    hs_msg = {name: data for _, name, data in hs}
    ch = hs_msg["ClientHello"]
    cke = hs_msg["ClientKeyExchange"]

    def body(d):
        return d[4:]

    # ---- 提取 randoms ----
    client_random = body(ch)[2:34]      # ver(2) + random(32)
    server_random = body(hs_msg["ServerHello"])[2:34]
    print(f"\nclient_random = {client_random.hex()}")
    print(f"server_random = {server_random.hex()}")

    # ---- 步骤 1: RSA 解密 EncryptedPreMasterSecret ----
    print("\n── 步骤 1: 用服务器 RSA 私钥解密 ClientKeyExchange ──")
    epms = body(cke)[2:]   # u16 长度前缀 + 密文
    priv = serialization.load_pem_private_key((ROOT / "certs/rsa_server.key").read_bytes(), None)
    pms = priv.decrypt(epms, apad.PKCS1v15())
    ok(f"解密得到 {len(pms)} 字节 premaster")
    print(f"      premaster[:2] (客户端版本) = {pms[:2].hex()} (应为 0303)")
    print(f"      premaster 随机部分 = {pms[2:].hex()[:32]}…")
    if pms[:2] != b"\x03\x03":
        fail("premaster 版本字段异常")
    kl_pms = kl.get("_rsa_pms")
    if kl_pms == pms:
        ok("与 keylog 中 RSA 行的 premaster 完全一致")
    else:
        print(f"      keylog PMS = {kl_pms.hex()[:32]}…  (可能与抓包不是同一次会话, 继续用解密值)")

    # ---- 步骤 2: PRF 计算 master_secret ----
    print("\n── 步骤 2: premaster --PRF--> master_secret ──")
    seed = client_random + server_random
    ms_classic = prf(pms, "master secret", seed, 48)
    print(f"      [经典 RFC5246]  PRF(pms,'master secret', C_random+S_random) = {ms_classic.hex()[:32]}…")
    # 本握手协商了 extended_master_secret (RFC 7627):
    #   master_secret = PRF(pms, "extended master secret", session_hash)
    #   session_hash = SHA256(自 ClientHello 起至 ClientKeyExchange 的全部握手消息)
    transcript = b""
    for _, name, data in hs:
        transcript += data
        if name == "ClientKeyExchange":
            break
    session_hash = hashlib.sha256(transcript).digest()
    ms_ems = prf(pms, "extended master secret", session_hash, 48)
    print(f"      [EMS RFC7627]   PRF(pms,'extended master secret', session_hash)  = {ms_ems.hex()[:32]}…")
    print(f"      session_hash (SHA256(CH..CKE)) = {session_hash.hex()[:32]}…")
    ms = None
    if "CLIENT_RANDOM" in kl:
        if ms_ems == kl["CLIENT_RANDOM"]:
            ms = ms_ems
            ok("EMS 推导与 OpenSSL keylog 的 master_secret 一致! (本握手协商了 extended_master_secret)")
        elif ms_classic == kl["CLIENT_RANDOM"]:
            ms = ms_classic
            ok("经典推导与 keylog 一致! (本握手未启用 EMS)")
        else:
            fail("两种推导均与 keylog 不一致")
    else:
        fail("keylog 缺少 CLIENT_RANDOM 行")

    # ---- 步骤 3: key_block 切分 ----
    print("\n── 步骤 3: master_secret --PRF--> key_block (RFC 5246 §6.3) ──")
    # AES_128_GCM: mac_key_length=0, enc_key=16, fixed_iv=4 (per direction)
    key_block = prf(ms, "key expansion", server_random + client_random, 40)
    c_w_key = key_block[0:16]
    s_w_key = key_block[16:32]
    c_w_iv = key_block[32:36]
    s_w_iv = key_block[36:40]
    ok("key_block(40B) = client_key(16) + server_key(16) + client_iv(4) + server_iv(4)")
    print(f"      client_write_key = {c_w_key.hex()}")
    print(f"      server_write_key = {s_w_key.hex()}")
    print(f"      client_write_IV  = {c_w_iv.hex()}   server_write_IV = {s_w_iv.hex()}")

    # ---- 步骤 4: 客户端 Finished ----
    print("\n── 步骤 4: 客户端 Finished 验证 ──")
    fins = [data for _, n, data in hs if n == "Finished"]  # 出现顺序: 客户端在前
    cli_fin = fins[0]
    # 握手转录 = 到 client Finished 为止的全部握手消息 (不含 Finished 自身)
    transcript = b""
    for _, name, data in hs:
        if name == "Finished":
            break
        transcript += data
    th = hashlib.sha256(transcript).digest()
    ok(f"握手转录 (→client Finished, 共 {len(transcript)} B) SHA-256 = {th.hex()[:32]}…")
    vd = prf(ms, "client finished", th, 12)
    print(f"      复算 client Finished.verify_data = {vd.hex()}")
    cli_vd = body(cli_fin)
    if vd == cli_vd:
        ok("与抓包中客户端 Finished.verify_data 完全一致!! PRF 链路全部验证通过")
    else:
        fail("verify_data 不一致", f"实际={cli_vd.hex()}")

    # ---- 步骤 5: 服务器 Finished ----
    print("\n── 步骤 5: 服务器 Finished 验证 ──")
    srv_fin = fins[-1]
    # 服务器 Finished 的转录 = 到 server Finished 为止的全部握手消息
    # 注意: 本会话顺序是 Fin(C) → NST(S) → Fin(S), 且实测正确转录**不含** client
    # Finished、但**含** NST (openssl 的 server finished 在 NST 前计算转录? 实测如此)
    transcript2 = b""
    for direction, name, data in hs:
        if name == "Finished" and direction == ">>>":
            continue  # server finished 转录不含 client Finished (实测)
        transcript2 += data
        if name == "NewSessionTicket":
            break
    th2 = hashlib.sha256(transcript2).digest()
    vd2 = prf(ms, "server finished", th2, 12)
    srv_vd = body(srv_fin)
    print(f"      复算 server Finished.verify_data = {vd2.hex()}")
    if vd2 == srv_vd:
        ok("服务器 Finished.verify_data 一致! 双向Finished均验证通过")
    else:
        fail("不一致", f"实际={srv_vd.hex()}")

    print("\n" + "=" * 78)
    print("结论: TLS1.2 RSA 交换下, 从抓包字节 + 服务器私钥即可还原全部会话密钥,")
    print("      这正说明『静态 RSA 交换不具备前向安全』; ECDHE 则因临时私钥无法还原。")
    print("      (记录层密文解密演示: python3 verify_tls12_records.py)")
    print("=" * 78)


if __name__ == "__main__":
    main()
