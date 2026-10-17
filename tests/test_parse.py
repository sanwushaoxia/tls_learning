"""tlslib.parse 单元测试：手工构造报文 + RFC 8448 真实向量"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from tlslib.parse import (Reader, extract_handshakes, parse_msg_file,
                          parse_server_hello, parse_finished, parse_nst,
                          HANDSHAKE_TYPES)


def mk_client_hello(sid: bytes = b"", suites=(0x1302,), ext=b"") -> bytes:
    """构造最小 ClientHello body"""
    body = b"\x03\x03" + bytes(32)                      # version + random
    body += bytes([len(sid)]) + sid                     # session_id (u8 前缀!)
    body += (len(suites) * 2).to_bytes(2, "big")        # suites 长度
    for s in suites:
        body += s.to_bytes(2, "big")
    body += b"\x01\x00"                                 # compression: len=1, null
    if ext:
        body += len(ext).to_bytes(2, "big") + ext
    return b"\x01" + len(body).to_bytes(3, "big") + body


def mk_msg_block(direction, name, payload: bytes) -> str:
    """构造 -msg 风格的十六进制文本块"""
    lines = [f"{direction} TLS 1.3, Handshake [length {len(payload):04x}], {name}"]
    for i in range(0, len(payload), 16):
        lines.append("    " + payload[i:i+16].hex(" "))
    return "\n".join(lines) + "\n"


class TestReader:
    def test_u8_u16_u24_u32(self):
        r = Reader(b"\x01\x00\x02\x00\x00\x03\x00\x00\x00\x04")
        assert r.u8() == 1
        assert r.u16() == 2
        assert r.u24() == 3
        assert r.u32() == 4
        assert r.left == 0

    def test_take_u8_prefix(self):
        # session_id 式 1 字节前缀
        r = Reader(b"\x20" + bytes(32))
        assert len(r.take(r.u8())) == 32


class TestExtract:
    def test_extract_handshakes(self):
        text = mk_msg_block(">>>", "ClientHello", mk_client_hello())
        hs = extract_handshakes(text)
        assert len(hs) == 1
        d, name, data = hs[0]
        assert name == "ClientHello"
        assert data[0] == 1

    def test_session_id_u8_prefix(self):
        """回归: session_id 长度前缀是 1 字节 —— 32B id 必须正确解析"""
        sid = bytes(range(32))
        text = mk_msg_block(">>>", "ClientHello", mk_client_hello(sid=sid))
        hs = extract_handshakes(text)
        out = dict((k, v) for k, v in _parse_fields(hs[0][2]))
        assert "len=32" in out.get("session_id", "")

    def test_cipher_suite_roundtrip(self):
        text = mk_msg_block(">>>", "ClientHello", mk_client_hello(suites=(0x1302,)))
        out = dict((k, v) for k, v in _parse_fields(extract_handshakes(text)[0][2]))
        assert "TLS_AES_256_GCM_SHA384" in out.get("cipher_suites", "")


class TestServerHelloRFC8448:
    """RFC 8448 §2 的真实 ServerHello (90 字节)"""

    def test_parse(self):
        sh = bytes.fromhex(
            "02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95"
            " 93 0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e"
            " 00 33 00 24 00 1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6"
            " 72 1e 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02"
            " 03 04".replace(" ", ""))
        assert len(sh) == 90
        out = dict((k, v) for k, v in parse_server_hello(sh))
        assert "0x1301" in out["cipher_suite"]
        assert "TLS_AES_128_GCM_SHA256" in out["cipher_suite"]
        assert "len=0" in out["session_id"]
        assert "0x0304" in out.get("ext[supported_versions]", "")


class TestFinishedAndNST:
    def test_finished(self):
        fin = b"\x14\x00\x00\x0c" + bytes(12)
        out = dict((k, v) for k, v in parse_finished(fin))
        assert "len=12" in out["verify_data"]

    def test_nst_u8_nonce(self):
        """回归: ticket_nonce 长度前缀是 1 字节"""
        ticket = bytes(208)
        nst = (b"\x04\x00\x00\xe5"
               + (7200).to_bytes(4, "big")
               + b"\x25\x44\x93\x9d"
               + b"\x08" + bytes(8)          # nonce: u8 前缀!
               + len(ticket).to_bytes(2, "big") + ticket
               + b"\x00\x00")
        out = dict((k, v) for k, v in parse_nst(nst))
        assert "len=8" in out["ticket_nonce"]
        assert "len=208" in out["ticket"]


class TestParseMsgFile:
    def test_real_capture(self, tmp_path):
        """用真实抓包文件回归（若存在）"""
        cap = Path(__file__).resolve().parent.parent / "captures/tls13_msg.txt"
        if not cap.exists():
            pytest.skip("captures/tls13_msg.txt 不存在")
        text = parse_msg_file(cap)
        assert "ClientHello" in text
        assert "记录层" in text


def _parse_fields(data):
    """把 parse_client_hello 返回的 (k, v) 列表取出"""
    from tlslib.parse import PARSERS
    return PARSERS["ClientHello"](data)
