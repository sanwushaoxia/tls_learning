"""tlslib.crypto 单元测试：RFC 8448 密钥链向量 + TLS 1.2 PRF + keylog 解析"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from tlslib.crypto import (p_hash, prf, hkdf_extract, hkdf_expand,
                           expand_label, derive_secret, parse_keylog)


class TestTLS12PRF:
    def test_p_hash_truncation(self):
        """回归: 请求 48B 必须返回 48B (而非对齐的 64B)"""
        out = p_hash(b"secret", b"seed", 48)
        assert len(out) == 48

    def test_p_hash_large(self):
        out = p_hash(b"k", b"s", 100)
        assert len(out) == 100

    def test_prf_label(self):
        """PRF = P_hash(secret, label + seed); 不同 label 结果不同"""
        a = prf(b"secret", "master secret", b"seed", 32)
        b_ = prf(b"secret", "key expansion", b"seed", 32)
        assert a != b_


class TestRFC8448KeyChain:
    """RFC 8448 §2 (simple 1-RTT, AES_128_GCM_SHA256) 全链向量"""

    H = __import__("hashlib").sha256
    L = 32

    def test_full_chain(self):
        h, L = self.H, self.L
        early = hkdf_extract(bytes(L), bytes(L), h)
        assert early.hex() == ("33ad0a1c607ec03b09e6cd9893680ce2"
                               "10adf300aa1f2660e1b22e10f170f92a")
        derived = expand_label(early, "derived", h(b"").digest(), L, h)
        assert derived.hex() == ("6f2615a108c702c5678f54fc9dbab697"
                                 "16c076189c48250cebeac3576c3611ba")
        shared = bytes.fromhex(
            "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")
        hs_sec = hkdf_extract(derived, shared, h)
        assert hs_sec.hex() == ("1dc826e93606aa6fdc0aadc12f741b01"
                                "046aa6b99f691ed221a9f0ca043fbeac")
        th = bytes.fromhex("860c06edc07858ee8e78f0e7428c58ed"
                           "d6b43f2ca3e6e95f02ed063cf0e1cad8")
        c_hs = derive_secret(hs_sec, "c hs traffic", th, h)
        assert c_hs.hex() == ("b3eddb126e067f35a780b3abf45e2d8f"
                              "3b1a950738f52e9600746a0e27a55a21")
        master = hkdf_extract(
            expand_label(hs_sec, "derived", h(b"").digest(), L, h), bytes(L), h)
        assert master.hex() == ("18df06843d13a08bf2a449844c5f8a47"
                                "8001bc4d4c627984d5a41da8d0402919")

    def test_write_key_iv(self):
        h = self.H
        s_hs = bytes.fromhex("b67b7d690cc16c4e75e54213cb2d37b4"
                             "e9c912bcded9105d42befd59d391ad38")
        key = expand_label(s_hs, "key", b"", 16, h)
        assert key.hex() == "3fce516009c21727d0f2e4e86ee403bc"
        iv = expand_label(s_hs, "iv", b"", 12, h)
        assert iv.hex() == "5d313eb2671276ee13000b30"


class TestParseKeylog:
    def test_three_line_types(self, tmp_path):
        kl = tmp_path / "k.txt"
        kl.write_text(
            "# comment\n"
            "RSA aabb " + "00" * 48 + "\n"
            "CLIENT_RANDOM " + "11" * 32 + " " + "22" * 48 + "\n"
            "SERVER_TRAFFIC_SECRET_0 " + "11" * 32 + " " + "33" * 48 + "\n")
        d = parse_keylog(kl)
        assert d["_rsa_pms"] == bytes(48)
        assert d["CLIENT_RANDOM"] == bytes.fromhex("22" * 48)
        assert d["SERVER_TRAFFIC_SECRET_0"] == bytes.fromhex("33" * 48)

    def test_duplicate_keys_last_wins(self, tmp_path):
        """回归: keylog 为追加模式, 同名键保留最后一组(最近会话)"""
        kl = tmp_path / "k.txt"
        kl.write_text(
            "CLIENT_RANDOM " + "11" * 32 + " " + "aa" * 48 + "\n"
            "CLIENT_RANDOM " + "11" * 32 + " " + "bb" * 48 + "\n")
        d = parse_keylog(kl)
        assert d["CLIENT_RANDOM"] == bytes.fromhex("bb" * 48)
