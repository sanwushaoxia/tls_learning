"""
TLS 密码学工具库：合并 TLS 1.2 (PRF) 与 TLS 1.3 (HKDF) 的推导函数、
keylog 解析与验证输出工具。供 verify_* 脚本复用。
"""
import hashlib
import hmac
import sys

# ---------- TLS 1.2 PRF (RFC 5246 §5) ----------


def p_hash(secret, seed, length, algo=hashlib.sha256):
    result = b""
    a = hmac.new(secret, seed, algo).digest()
    while len(result) < length:
        result += hmac.new(secret, a + seed, algo).digest()
        a = hmac.new(secret, a, algo).digest()
    return result[:length]


def prf(secret, label, seed, length, algo=hashlib.sha256):
    return p_hash(secret, label.encode() + seed, length, algo)


# ---------- HKDF (RFC 5869) + TLS1.3 label (RFC 8446 §7.1) ----------


def hkdf_extract(salt, ikm, h=hashlib.sha256):
    return hmac.new(salt, ikm, h).digest()


def hkdf_expand(prk, info, length, h=hashlib.sha256):
    result = b""; t = b""; i = 1
    while len(result) < length:
        t = hmac.new(prk, t + info + bytes([i]), h).digest()
        result += t; i += 1
    return result[:length]


def expand_label(secret, label, context, length, h=hashlib.sha256):
    """RFC 8446 §7.1: HKDF-Expand-Label(secret, label, context, length)"""
    full = b"tls13 " + label.encode()
    info = (length.to_bytes(2, "big") + bytes([len(full)]) + full +
            bytes([len(context)]) + context)
    return hkdf_expand(secret, info, length, h)


def derive_secret(secret, label, transcript_hash, h=hashlib.sha256):
    return expand_label(secret, label, transcript_hash, h().digest_size, h)


# ---------- keylog 解析 (SSLKEYLOGFILE 格式) ----------


def parse_keylog(path):
    """解析 OpenSSL keylog 文件。重复键覆盖 → 保留最后一组(最近会话)。
    返回 dict: label -> bytes。可能包含:
      'CLIENT_RANDOM'  (TLS1.2 master_secret; TLS1.3 会话无此行)
      'SERVER_HANDSHAKE_TRAFFIC_SECRET' 等 TLS1.3 五密钥行
      '_rsa_pms'       (TLS1.2 RSA 行的加密 premaster, 存在 '<label>' 旁)
    """
    out = {}
    for line in open(path).read().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split()
        if parts[0] == "RSA" and len(parts) == 3:
            out["rsa_session"] = bytes.fromhex(parts[1])
            out["_rsa_pms"] = bytes.fromhex(parts[2])
        elif len(parts) == 3:
            out[parts[0]] = bytes.fromhex(parts[2])
    return out


# ---------- 验证输出工具 ----------


def ok(step, detail=""):
    print(f"  [√] {step}" + (f"  {detail}" if detail else ""))


def fail(step, detail=""):
    print(f"  [×] {step}" + (f"  {detail}" if detail else ""))
    sys.exit(1)


def check_hex(name, calc, expect_hex):
    """与期望 hex (可含空格) 逐字节对比"""
    e = bytes.fromhex(expect_hex.replace(" ", ""))
    if calc == e:
        ok(name)
        return True
    fail(name, f"calc={calc.hex()[:24]}… expect={e.hex()[:24]}…")
    return False
