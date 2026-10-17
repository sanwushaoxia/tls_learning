#!/usr/bin/env python3
"""
TLS 1.3 PSK 会话恢复与 0-RTT 验证（RFC 8446 §2.2 / §4.2.11）

对 run_tls13_psk.sh 的产物验证:
  1. 报文序列对比: 完整握手 vs PSK 恢复握手
     (恢复时无 Certificate/CertificateVerify, 出现 pre_shared_key 扩展与 EndOfEarlyData)
  2. 复算 PSK binder:
       early_secret  = HKDF-Extract(0, resumption_PSK)          ← PSK 取自 session 文件
       binder_secret = ExpandLabel(early, "res binder", Hash(""))
       finished_key  = ExpandLabel(binder_secret, "finished", "")
       binder        = HMAC(finished_key, TH(TruncatedClientHello))
     注意 Derive-Secret 的 context 是 Hash(transcript)（空 transcript → SHA384("")），
     不是空字节串 —— 这是本实验最易踩的坑。
  3. 复算 CLIENT_EARLY_TRAFFIC_SECRET 与 keylog 对比 (证明 PSK 正确)
  4. EndOfEarlyData 的存在意义说明

先抓包: bash scripts/run_tls13_psk.sh
用法: python3 verify_tls13_psk.py
"""
import hashlib
import hmac
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tlslib.crypto import hkdf_extract, expand_label, parse_keylog, ok, fail  # noqa: E402
from tlslib.parse import extract_handshakes  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CAP = ROOT / "captures"
H = hashlib.sha384   # 套件 TLS_AES_256_GCM_SHA384
L = H().digest_size


def extract_resumption_psk(session_file):
    """openssl sess_id -text 提取 Resumption PSK"""
    out = subprocess.run(["openssl", "sess_id", "-in", str(session_file), "-text"],
                         capture_output=True, text=True).stdout
    m = re.search(r"Resumption PSK: ([0-9A-F]+)", out)
    if not m:
        fail("session 文件中无 Resumption PSK")
    return bytes.fromhex(m.group(1))


def main():
    print("=" * 78)
    print("TLS 1.3 PSK 会话恢复与 0-RTT 验证")
    print("=" * 78)

    full_hs = extract_handshakes((CAP / "tls13_psk_full_msg.txt").read_text(errors="replace"))
    psk_hs = extract_handshakes((CAP / "tls13_psk_msg.txt").read_text(errors="replace"))

    # ---- 1. 报文序列对比 ----
    print("\n── 步骤 1: 两次握手的报文序列对比 ──")
    print(f"  完整握手: {' → '.join(n for _, n, _ in full_hs)}")
    print(f"  PSK 恢复: {' → '.join(n for _, n, _ in psk_hs)}")
    psk_names = {n for _, n, _ in psk_hs}
    missing = {"Certificate", "CertificateVerify"} - psk_names
    if missing and "EndOfEarlyData" in psk_names:
        ok(f"恢复握手省去了 {sorted(missing)} (服务器身份由 PSK 隐式认证), 出现 EndOfEarlyData (0-RTT 结束标记)")
    else:
        fail("报文序列不符合 PSK 恢复预期")

    # ---- 2. binder 复算 ----
    print("\n── 步骤 2: PSK binder 复算 ──")
    psk = extract_resumption_psk(CAP / "tls13_psk_session.pem")
    ok(f"从 session 文件提取 Resumption PSK ({len(psk)}B): {psk.hex()[:24]}…")
    early = hkdf_extract(bytes(L), psk, H)
    # 关键: Derive-Secret 的 context = Hash(transcript); 空 transcript → Hash("") ≠ b""
    binder_secret = expand_label(early, "res binder", H(b"").digest(), L, H)
    finished_key = expand_label(binder_secret, "finished", b"", L, H)
    ok("binder_secret = ExpandLabel(early, 'res binder', Hash(''))  ← context 是 Hash('') 而非空串!")
    ok(f"finished_key  = ExpandLabel(binder_secret, 'finished', '')  = {finished_key.hex()[:24]}…")

    ch = next(d for _, n, d in psk_hs if n == "ClientHello")
    # CH 尾部: binders = u16 总长(2) + u8 binder_len(1) + 48B binder(SHA384)
    blen_pos = len(ch) - 1 - L   # u8 binder_len 紧贴 binder 数据之前
    assert ch[blen_pos] == L, "binder 长度字段异常"
    truncated = ch[:blen_pos - 2]   # 再去掉 binders 总长 u16
    binder = hmac.new(finished_key, H(truncated).digest(), H).digest()
    print(f"      TruncatedClientHello = CH 去掉 binders (截去 {len(ch) - len(truncated)}B)")
    print(f"      复算 binder = {binder.hex()}")
    print(f"      实际 binder = {ch[-L:].hex()}")
    if binder == ch[-L:]:
        ok("binder 复算与 ClientHello 中实际值一致!! 防篡改/防重放机制验证通过")
    else:
        fail("binder 不一致")

    # ---- 3. CLIENT_EARLY_TRAFFIC_SECRET (证明 PSK 与 early secret 链路) ----
    print("\n── 步骤 3: 0-RTT 密钥链验证 ──")
    kl = parse_keylog(CAP / "tls13_psk_keylog.txt")
    if "CLIENT_EARLY_TRAFFIC_SECRET" not in kl:
        fail("keylog 无 CLIENT_EARLY_TRAFFIC_SECRET (0-RTT 未发生)")
    th_ch = H(ch).digest()
    c_ets = expand_label(early, "c e traffic", th_ch, L, H)
    print(f"      c e traffic = ExpandLabel(early, 'c e traffic', TH(ClientHello))")
    print(f"      复算: {c_ets.hex()[:32]}…")
    print(f"      keylog: {kl['CLIENT_EARLY_TRAFFIC_SECRET'].hex()[:32]}…")
    if c_ets == kl["CLIENT_EARLY_TRAFFIC_SECRET"]:
        ok("CLIENT_EARLY_TRAFFIC_SECRET 复算一致 —— 0-RTT 加密密钥链验证通过")
    else:
        fail("c e traffic 不一致")

    # ---- 4. EndOfEarlyData ----
    print("\n── 步骤 4: EndOfEarlyData ──")
    eoe = next(d for _, n, d in psk_hs if n == "EndOfEarlyData")
    ok(f"EndOfEarlyData (type=5, len={int.from_bytes(eoe[1:4], 'big')}): "
       "0-RTT 数据发完的边界标记, 用 early traffic secret 加密; "
       "此后切换到 handshake traffic secret")

    print("\n" + "=" * 78)
    print("结论:")
    print("  1) PSK 恢复握手省去证书/签名 (1-RTT 更快), 服务器身份由 PSK 隐式认证;")
    print("  2) binder = HMAC(finished_key, TH(truncated CH)) 把 PSK 绑定到本次")
    print("     ClientHello —— 任何对 CH 的篡改都会使 binder 校验失败;")
    print("  3) 0-RTT 数据用 early traffic secret 加密, 但**无防重放保护**")
    print("     (攻击者可重放整个 0-RTT 流量) —— 这是 0-RTT 最重要的安全限制;")
    print("  4) 易错点: Derive-Secret 的 context 永远是 Hash(transcript),")
    print("     空 transcript 时是 Hash('') 而不是空字节串。")
    print("=" * 78)


if __name__ == "__main__":
    main()
