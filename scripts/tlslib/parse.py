"""
TLS 报文解析库：从 openssl s_client/s_server -msg 的输出中提取握手报文，
逐字段解析各类握手消息与扩展。供 parse_handshake.py (CLI) 与验证脚本复用。

注意几个容易踩坑的编码点（都已在真实抓包中验证）:
- session_id / ticket_nonce / ECPoint 等使用 1 字节长度前缀 (vector<0..32> 等)
- cipher_suites / EncryptedPreMasterSecret 等使用 2 字节长度前缀
- certificate_list 使用 3 字节长度前缀
- 扩展类型号: supported_versions=0x002B, psk_key_exchange_modes=0x002D,
  key_share=0x0033, pre_shared_key=0x0029
"""
import re
import subprocess
import tempfile
import os
from pathlib import Path

# ---------- 从 -msg 文本中提取报文 ----------

HS_PAT = re.compile(
    r"(>>>|<<<) TLS [\d.]+, Handshake \[length ([0-9a-f]+)\], (\w+)\s*\n((?:    [0-9a-f ]+\n?)+)",
    re.M,
)

REC_PAT = re.compile(
    r"(>>>|<<<) TLS [\d.]+, RecordHeader \[length 0005\]\s*\n\s*([0-9a-f]{2} [0-9a-f]{2} [0-9a-f]{2} [0-9a-f]{2} [0-9a-f]{2})",
)

RECORD_TYPES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData"}
LEGACY_VERSIONS = {"03 01": "TLS1.0(兼容/协商)", "03 03": "TLS1.2/1.3"}


def extract_handshakes(text: str):
    """返回 [(direction, name, bytes), ...]，direction 为 '>>>'(C→S) / '<<<'(S→C)"""
    out = []
    for m in HS_PAT.finditer(text):
        direction = "client→server" if m.group(1) == ">>>" else "server→client"
        name = m.group(3)
        data = bytes.fromhex(re.sub(r"\s+", "", m.group(4)))
        out.append((direction, name, data))
    return out


def extract_records(text: str):
    """返回 [(direction, record_type, version_hex, payload_len), ...] —— 记录层观察用"""
    out = []
    for m in REC_PAT.finditer(text):
        b = [int(x, 16) for x in m.group(2).split()]
        out.append((
            "C→S" if m.group(1) == ">>>" else "S→C",
            RECORD_TYPES.get(b[0], f"type{b[0]}"),
            LEGACY_VERSIONS.get(f"{b[1]:02x} {b[2]:02x}", "legacy"),
            (b[3] << 8) | b[4],
        ))
    return out


# ---------- 字段字典 ----------

HANDSHAKE_TYPES = {
    0: "HelloRequest", 1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket",
    8: "EncryptedExtensions", 11: "Certificate", 12: "ServerKeyExchange",
    13: "CertificateRequest", 14: "ServerHelloDone", 15: "CertificateVerify",
    16: "ClientKeyExchange", 20: "Finished",
}

CIPHER_NAMES = {
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}

NAMED_GROUPS = {
    0x0017: "secp256r1(P-256)", 0x0018: "secp384r1(P-384)", 0x0019: "secp521r1",
    0x001D: "x25519", 0x001E: "x448", 0x0100: "ffdhe2048",
}

SIG_ALGS = {
    0x0403: "ecdsa_secp256r1_sha256", 0x0804: "rsa_pss_rsae_sha256",
    0x0401: "rsa_pkcs1_sha256", 0x0501: "rsa_pkcs1_sha384", 0x0601: "rsa_pkcs1_sha512",
    0x0807: "ed25519", 0x0201: "rsa_pkcs1_sha1",
}

EXT_NAMES = {
    0x0000: "server_name(SNI)", 0x0005: "status_request(OCSP)", 0x000A: "supported_groups",
    0x000B: "ec_point_formats", 0x000D: "signature_algorithms", 0x0010: "application_layer_protocol",
    0x0016: "encrypt_then_mac", 0x0017: "extended_master_secret", 0x0023: "session_ticket",
    0xFF01: "renegotiation_info", 0x002B: "supported_versions", 0x002D: "psk_key_exchange_modes",
    0x0029: "pre_shared_key", 0x0033: "key_share",
}

# ---------- 低层读取工具 ----------


class Reader:
    def __init__(self, data): self.d, self.p = data, 0
    def u8(self):
        v = self.d[self.p]; self.p += 1; return v
    def u16(self):
        v = int.from_bytes(self.d[self.p:self.p+2], "big"); self.p += 2; return v
    def u24(self):
        v = int.from_bytes(self.d[self.p:self.p+3], "big"); self.p += 3; return v
    def u32(self):
        v = int.from_bytes(self.d[self.p:self.p+4], "big"); self.p += 4; return v
    def take(self, n):
        v = self.d[self.p:self.p+n]; self.p += n; return v
    def take16(self): return self.take(self.u16())
    @property
    def left(self): return len(self.d) - self.p


def h(b, sep=" "): return b.hex(sep)
def short(b, n=16): return h(b[:n]) + (" …" if len(b) > n else "")


# ---------- 各报文解析 ----------


def parse_client_hello(d):
    r = Reader(d); out = []
    assert r.u8() == 1
    body_len = r.u24()
    out.append(("body_length", f"{body_len} (3字节: 00 {body_len:04x})"))
    v = r.take(2)
    out.append(("legacy_version", f"{v.hex()} ({'TLS1.2' if v==b'\x03\x03' else v.hex()}) —— TLS1.3 中为兼容字段，真实版本看 supported_versions"))
    rnd = r.take(32)
    out.append(("random[32]", short(rnd) + f"  (时间戳位={rnd[:4].hex()}，1.2 前含 gmt_unix_time，现仅随机)"))
    sid = r.take(r.u8())   # 注意: session_id 长度前缀是 1 字节 (vector<0..32>)
    out.append(("session_id", f"len={len(sid)}" + (f" {short(sid)}" if sid else " (空)") + " —— TLS1.3 中为兼容字段填 32B 随机, 1.2 用于会话恢复"))
    ncs = r.u16()
    suites = [int.from_bytes(r.take(2), "big") for _ in range(ncs // 2)]
    out.append(("cipher_suites", f"count={len(suites)}: " + ", ".join(f"0x{s:04x}({CIPHER_NAMES.get(s, '?')})" for s in suites[:6])))
    comp_n = r.u8()
    comps = r.take(comp_n)   # compression_methods: u8 长度前缀 + vector
    out.append(("compression_methods", f"{h(comps)} (1=null —— TLS1.3 强制 null)"))
    if r.left >= 2:
        ext_total = r.u16()
        out.append(("extensions_length", f"{ext_total}"))
        out += parse_extensions(r, "CH")
    return out


def parse_server_hello(d):
    r = Reader(d); out = []
    assert r.u8() == 2
    out.append(("body_length", str(r.u24())))
    v = r.take(2)
    out.append(("legacy_version", f"{v.hex()} (TLS1.3 中永远是 0303，真实版本在 supported_versions)"))
    rnd = r.take(32)
    out.append(("random[32]", short(rnd)))
    sid = r.take(r.u8())   # 1 字节长度前缀
    out.append(("session_id", f"len={len(sid)}" + (f" {short(sid)} (回显 ClientHello)" if sid else " (空)")))
    cs = int.from_bytes(r.take(2), "big")
    out.append(("cipher_suite", f"0x{cs:04x} = {CIPHER_NAMES.get(cs, '?')} —— 服务器最终选定"))
    out.append(("compression", str(r.u8()) + " (null)"))
    if r.left >= 2:
        r.u16()  # extensions length
        out += parse_extensions(r, "SH")
    if r.left:
        out.append(("!!剩余", h(r.take(r.left))))
    return out


def parse_extensions(r: Reader, ctx):
    out = []
    while r.left >= 4:
        etype, elen = r.u16(), r.u16()
        body = r.take(elen)
        name = EXT_NAMES.get(etype, f"0x{etype:04x}")
        line = f"len={elen}"
        if name == "supported_groups":
            n = int.from_bytes(body[:2], "big")
            groups = [int.from_bytes(body[2+i*2:4+i*2], "big") for i in range(n // 2)]
            line += ": " + ", ".join(f"0x{g:04x}({NAMED_GROUPS.get(g,'?')})" for g in groups)
        elif name == "signature_algorithms":
            n = int.from_bytes(body[:2], "big")
            algos = [int.from_bytes(body[2+i*2:4+i*2], "big") for i in range(n // 2)]
            line += ": " + ", ".join(SIG_ALGS.get(a, f"0x{a:04x}") for a in algos)
        elif name == "supported_versions":
            if ctx == "CH":
                n = body[0]
                vs = [int.from_bytes(body[1+i*2:3+i*2], "big") for i in range(n // 2)]
                line += " [客户端提供]: " + ", ".join(f"0x{v:04x}" for v in vs)
            else:
                line += f" [服务器选定]: 0x{int.from_bytes(body, 'big'):04x} ({'TLS1.3' if body==b'\x03\x04' else body.hex()})"
        elif name == "key_share":
            line += " —— ECDHE 公钥（服务器用其私钥 + 客户端公钥算出共享密钥）"
            if ctx == "CH":
                rr = Reader(body); rr.u16()
                while rr.left:
                    g = rr.u16(); klen = rr.u16(); k = rr.take(klen)
                    line += f"\n      group=0x{g:04x}({NAMED_GROUPS.get(g,'?')}) keylen={klen} pubkey={short(k)}"
            else:
                g = int.from_bytes(body[:2], "big"); klen = int.from_bytes(body[2:4], "big")
                k = body[4:4+klen]
                line += f"\n      group=0x{g:04x}({NAMED_GROUPS.get(g,'?')}) keylen={klen} pubkey={short(k)}"
        elif name == "server_name":
            line += ": SNI（客户端告知主机名）"
        elif name == "psk_key_exchange_modes":
            line += f": modes={h(body)} (0=psk_ke, 1=psk_dhe_ke)"
        elif name == "pre_shared_key":
            line += " —— PSK 恢复，见下方 (identity + binder)"
            rr = Reader(body)
            n = rr.u16(); ident = rr.take(n)
            line += f"\n      identity={short(ident, 8)} (NewSessionTicket 的 ticket)"
            # identities 后是 binders: u16 总长 + 每个 binder (u8 前缀)
            if rr.left >= 2:
                rr.u16()  # binders 总长
                while rr.left:
                    blen = rr.u8()
                    line += f"\n      binder={h(rr.take(blen))} —— HMAC(binder_key, TH(不含 binder 的 CH)), 防篡改/防重放"
        elif name == "session_ticket":
            line += " (TLS1.2 session ticket 扩展)"
        elif name == "extended_master_secret":
            line += " (RFC7627: master_secret 改为从整个握手转录推导)"
        elif name == "ec_point_formats":
            line += f": {h(body)}"
        out.append((f"ext[{name}]", line))
    return out


def parse_certificate(d):
    r = Reader(d); out = []
    assert r.u8() == 11
    out.append(("body_length", str(r.u24())))
    # TLS1.3: certificate_request_context(u8 vector) + certificate_list(u24 前缀)
    # TLS1.2: 直接是 certificate_list(u24 前缀)。探测区分: 1.3 中首字节 0 = 空 context
    probe = r.p
    rc_len = r.u8()
    if rc_len == 0 and int.from_bytes(r.d[r.p:r.p+3], "big") <= r.left - 1:
        out.append(("certificate_request_context", "len=0 (TLS1.3 格式)"))
    else:
        r.p = probe
    total = r.u24()
    out.append(("certificates_length", str(total)))
    idx = 0
    while r.left > 3:
        clen = r.u24(); cert = r.take(clen)
        out.append((f"certificate[{idx}]", f"len={clen} (DER)"))
        if idx == 0:
            out.append(("  证书内容摘要", summarize_cert(cert)))
        idx += 1
    return out


def summarize_cert(der):
    with tempfile.NamedTemporaryFile(suffix=".crt", delete=False) as f:
        f.write(der); p = f.name
    try:
        t = subprocess.run(["openssl", "x509", "-in", p, "-noout", "-subject", "-issuer", "-dates"],
                           capture_output=True, text=True, timeout=5).stdout.strip()
        return "\n      " + "\n      ".join(t.splitlines())
    finally:
        os.unlink(p)


def parse_certificate_request(d):
    """TLS 1.3 CertificateRequest (mTLS): context + extensions"""
    r = Reader(d); out = []
    assert r.u8() == 13
    out.append(("body_length", str(r.u24())))
    n = r.u8()
    out.append(("certificate_request_context", f"len={n} {h(r.take(n))} (服务器验证客户端证书时的标识)"))
    if r.left >= 2:
        r.u16()  # extensions length
        out += parse_extensions(r, "CR")
    return out


def parse_key_exchange(d, name):
    r = Reader(d); out = []
    hs = r.u8()
    out.append(("handshake_type", f"{hs} ({HANDSHAKE_TYPES.get(hs)})"))
    out.append(("body_length", str(r.u24())))
    if name == "ServerKeyExchange":
        ct = r.u8()
        out.append(("curve_type", f"{ct} (3=named_curve)"))
        g = r.u16()
        out.append(("named_curve", f"0x{g:04x} = {NAMED_GROUPS.get(g, '?')}"))
        plen = r.u8()   # ECPoint point: u8 前缀
        pubkey = r.take(plen)
        out.append(("pubkey", f"len={plen} = {short(pubkey)} —— 服务器临时 ECDHE 公钥（每次握手不同=前向安全）"))
        # OpenSSL 3.x 在 TLS1.2 SKE 中还带 2 字节签名算法标识 (TLS1.3 编码, 如 0x0804=rsa_pss_rsae_sha256)
        sa = r.u16()
        out.append(("signature_algorithm", f"0x{sa:04x} ({SIG_ALGS.get(sa, '?')})"))
        sig_len = r.u16(); sig = r.take(sig_len)
        out.append(("signature", f"len={sig_len} = {short(sig)} —— 对「client_random+server_random+ECDHE参数」的签名，防中间人替换密钥交换"))
    elif name == "ClientKeyExchange":
        plen = r.u16()  # EncryptedPreMasterSecret: u16 前缀 (opaque<16..2^16-1>)
        enc = r.take(plen)
        out.append(("EncryptedPreMasterSecret", f"len={plen} = {short(enc)} —— 用服务器证书公钥(RSA)加密的密文, 明文为 48B: 2B 客户端版本 + 46B 随机 (PKCS#1 v1.5 填充)"))
    if r.left:
        out.append(("!!剩余", h(r.take(r.left))))
    return out


def parse_certificate_verify(d):
    r = Reader(d); out = []
    hs = r.u8()
    out.append(("handshake_type", f"{hs} (CertificateVerify)"))
    out.append(("body_length", str(r.u24())))
    sa = r.u16()
    out.append(("signature_algorithm", f"0x{sa:04x} ({SIG_ALGS.get(sa, '?')})"))
    sig_len = r.u16(); sig = r.take(sig_len)
    out.append(("signature", f"len={sig_len} = {short(sig)} —— 签名内容 = \"TLS 1.3, ... CertificateVerify\"(重复串)+0x00+转录哈希, 把身份绑定到整个握手"))
    return out


def parse_finished(d):
    r = Reader(d); out = []
    hs = r.u8()
    out.append(("handshake_type", f"{hs} (Finished)"))
    out.append(("body_length", str(r.u24())))
    vd = r.take(r.left)
    out.append(("verify_data", f"len={len(vd)} = {h(vd)}"))
    out.append(("含义", "TLS1.2: PRF(master_secret,'client finished'+全部握手转录哈希) 的 12 字节。TLS1.3: 用 finished_key 对转录哈希做 HMAC。"))
    return out


def parse_nst(d):
    r = Reader(d); out = []
    hs = r.u8()
    out.append(("handshake_type", f"{hs} (NewSessionTicket)"))
    r.u24()
    life = r.u32()
    out.append(("ticket_lifetime", f"{life}s"))
    age = r.u32()
    out.append(("ticket_age_add", f"0x{age:08x} (混淆客户端真实年龄)"))
    n = r.u8()   # ticket_nonce: u8 前缀
    out.append(("ticket_nonce", f"len={n} {h(r.take(n))}"))
    tl = r.u16(); ticket = r.take(tl)   # identity: u16 前缀
    out.append(("ticket", f"len={tl} = {short(ticket)} —— 加密自鉴权票据，PSK 恢复握手时在 pre_shared_key 扩展回传"))
    if r.left >= 2:
        el = r.u16()
        out.append(("extensions", f"len={el} {h(r.take(el))}"))
    return out


def parse_generic(d):
    hs = d[0]
    return [("handshake_type", f"{hs} ({HANDSHAKE_TYPES.get(hs, '?')})"),
            ("body_length", str(int.from_bytes(d[1:4], "big"))),
            ("body(hex)", short(d[4:]))]


PARSERS = {
    "ClientHello": parse_client_hello, "ServerHello": parse_server_hello,
    "Certificate": parse_certificate, "CertificateRequest": parse_certificate_request,
    "ServerKeyExchange": lambda d: parse_key_exchange(d, "ServerKeyExchange"),
    "ClientKeyExchange": lambda d: parse_key_exchange(d, "ClientKeyExchange"),
    "CertificateVerify": parse_certificate_verify,
    "Finished": parse_finished, "NewSessionTicket": parse_nst,
}


def format_handshake(direction, name, data):
    lines = [f"{'='*76}", f"[{direction}] {name}  (握手层共 {len(data)} 字节)"]
    parser = PARSERS.get(name, parse_generic)
    for k, v in parser(data):
        lines.append(f"  {k:<42} {v}")
    lines.append("")
    return "\n".join(lines)


def parse_msg_file(path):
    """解析一个 -msg 输出文件, 返回格式化文本"""
    text = Path(path).read_text(errors="replace")
    out = [f"文件: {path}\n", "== 记录层（Record Layer）视图 ==",
           f"{'方向':<5} {'类型':<18} {'legacy版本':<14} 载荷长度"]
    for rec in extract_records(text):
        out.append(f"{rec[0]:<5} {rec[1]:<18} {rec[2]:<14} {rec[3]}")
    out.append("\n== 握手报文（Handshake）逐字段解析 ==\n")
    for direction, name, data in extract_handshakes(text):
        out.append(format_handshake(direction, name, data))
    return "\n".join(out)
