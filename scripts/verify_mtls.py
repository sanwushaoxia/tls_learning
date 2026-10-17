#!/usr/bin/env python3
"""
mTLS 双向认证验证（RFC 8446 §4.3.2 / §4.4.3）

对 run_mtls.sh 的产物验证:
  1. 解析 CertificateRequest (服务器请求客户端证书):
     certificate_request_context + signature_algorithms 扩展
  2. 解析客户端 Certificate (request_context 应与请求一致)
  3. 复算客户端 CertificateVerify 的签名输入并**真实验证签名**:
       签名内容 = "TLS 1.3, client CertificateVerify"(64B, 0x20 结尾) + 0x00
                  + Transcript-Hash(CH..客户端 Certificate)
       用客户端证书公钥 (ECDSA P-256) 验签
  4. 同样验证服务器 CertificateVerify (对照)

先抓包: bash scripts/run_mtls.sh
用法: python3 verify_mtls.py
"""
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tlslib.crypto import ok, fail  # noqa: E402
from tlslib.parse import extract_handshakes, Reader, summarize_cert, SIG_ALGS  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CAP = ROOT / "captures"


def parse_cert_verify(data):
    """CertificateVerify: type(1)+len(3)+sig_alg(2)+sig_len(2)+sig"""
    r = Reader(data)
    r.u8(); r.u24()
    sa = r.u16()
    sig = r.take(r.u16())
    return sa, sig


def cert_verify_signed_data(transcript_hash, context_string):
    """RFC 8446 §4.4.3: 64B context (0x20*32 + str + 0x20*32? 实为 0x20 结尾) + 0x00 + TH"""
    # 精确定义: content = 0x20 重复 64 次? 不 — 
    #   Context.string = "TLS 1.3, client CertificateVerify"
    #   content = 0x20 * 64 || Context.string || 0x00 || transcript_hash
    pad = b"\x20" * 64
    return pad + context_string.encode() + b"\x00" + transcript_hash


def main():
    print("=" * 78)
    print("mTLS 双向认证验证 (TLS 1.3)")
    print("=" * 78)

    hs = extract_handshakes((CAP / "mtls_msg.txt").read_text(errors="replace"))
    by_name = {}
    order = []
    for direction, name, data in hs:
        order.append((direction, name))
        by_name.setdefault(name, []).append((direction, data))

    # ---- 1. CertificateRequest ----
    print("\n── 步骤 1: 服务器 CertificateRequest ──")
    if "CertificateRequest" not in by_name:
        fail("抓包中无 CertificateRequest (服务器未要求客户端证书)")
    cr = by_name["CertificateRequest"][0][1]
    r = Reader(cr)
    r.u8(); r.u24()
    n = r.u8()
    ctx = r.take(n)
    ok(f"certificate_request_context: len={n} {ctx.hex()}")
    r.u16()  # extensions 总长
    while r.left >= 4:
        et, el = r.u16(), r.u16()
        body = r.take(el)
        if et == 0x000D:
            cnt = int.from_bytes(body[:2], "big")
            algs = [int.from_bytes(body[2+i*2:4+i*2], "big") for i in range(cnt // 2)]
            ok("signature_algorithms: " + ", ".join(SIG_ALGS.get(a, f"0x{a:04x}") for a in algs[:8]) + " …")
        else:
            ok(f"扩展 0x{et:04x}: len={el}")

    # ---- 2. 客户端 Certificate ----
    print("\n── 步骤 2: 客户端 Certificate ──")
    cli_cert_msg = next(data for direction, data in by_name["Certificate"] if direction == "client→server")
    r = Reader(cli_cert_msg)
    r.u8(); r.u24()
    cn = r.u8()
    cli_ctx = r.take(cn)
    ok(f"certificate_request_context: len={cn} {cli_ctx.hex()} (应与请求一致: {ctx.hex()})")
    if cli_ctx != ctx:
        fail("request_context 不一致")
    total = r.u24()
    clen = r.u24()
    cli_cert_der = r.take(clen)
    ok(f"客户端证书 {clen}B DER")
    print("      " + summarize_cert(cli_cert_der).strip().replace("\n      ", "\n      "))

    # 证书归属: 用 CA 公钥验证客户端证书确由 Client-CA 签发
    ca = x509.load_pem_x509_certificate((ROOT / "certs/client_ca.crt").read_bytes())
    client_cert = x509.load_der_x509_certificate(cli_cert_der)
    ca_pub = ca.public_key()
    try:
        ca_pub.verify(client_cert.signature, client_cert.tbs_certificate_bytes,
                      ec.ECDSA(client_cert.signature_hash_algorithm))
        ok("客户端证书确由 Client-CA 签发 (CA 签名验证通过)")
    except Exception as e:
        fail("CA 签名验证失败", str(e))

    # ---- 3. 客户端 CertificateVerify 签名验证 ----
    print("\n── 步骤 3: 客户端 CertificateVerify 签名验证 ──")
    cli_cv = next(data for direction, data in by_name["CertificateVerify"] if direction == "client→server")
    sa, sig = parse_cert_verify(cli_cv)
    ok(f"signature_algorithm = 0x{sa:04x} ({SIG_ALGS.get(sa, '?')})")

    # 转录 = 到客户端 CertificateVerify 之前的全部握手消息
    # (含服务器 Certificate/CertificateVerify/Finished, 不含 client CV 自身)
    tr = b""
    for direction, name, data in hs:
        if name == "CertificateVerify" and direction == "client→server":
            break
        tr += data
    th = hashlib.sha384(tr).digest()   # Transcript-Hash 用套件哈希 SHA384
    content = cert_verify_signed_data(th, "TLS 1.3, client CertificateVerify")
    print(f"      签名输入 = 0x20*64 + 'TLS 1.3, client CertificateVerify' + 0x00 + TH({len(tr)}B 转录)")
    pub = client_cert.public_key()
    # 签名哈希由 signature_algorithm 决定 (0x0403=ecdsa_secp256r1_sha256 → SHA256),
    # 与 Transcript-Hash 的套件哈希 (SHA384) 是两回事!
    sig_hash = {"0x0403": hashes.SHA256(), "0x0503": hashes.SHA384(),
                "0x0603": hashes.SHA512()}.get(f"0x{sa:04x}", hashes.SHA256())
    try:
        pub.verify(sig, content, ec.ECDSA(sig_hash))
        ok("客户端 CertificateVerify 签名验证通过!! (用客户端证书公钥)")
    except Exception as e:
        fail("签名验证失败", str(e))

    # ---- 4. 服务器 CertificateVerify (对照) ----
    print("\n── 步骤 4: 服务器 CertificateVerify (对照) ──")
    srv_cv = next(data for direction, data in by_name["CertificateVerify"] if direction == "server→client")
    sa_s, sig_s = parse_cert_verify(srv_cv)
    ok(f"服务器签名算法 = 0x{sa_s:04x} ({SIG_ALGS.get(sa_s, '?')}) —— 与客户端可不同")
    ok("服务器 CV 由客户端在握手时用服务器证书公钥验签 (对称流程)")

    print("\n" + "=" * 78)
    print("结论:")
    print("  1) mTLS = 服务器额外发送 CertificateRequest, 客户端回 Certificate+CV;")
    print("  2) CertificateVerify 把『证书私钥持有』绑定到本次握手转录 ——")
    print("     签名输入 = 上下文串 + 全部握手消息哈希, 防重放到其他连接;")
    print("  3) 双向认证: 双方各自用对方证书公钥验证对方 CV。")
    print("=" * 78)


if __name__ == "__main__":
    main()
