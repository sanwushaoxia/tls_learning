#!/usr/bin/env python3
"""
TLS 握手报文逐字段解析 CLI。
用法: python3 parse_handshake.py captures/tls13_msg.txt
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tlslib.parse import parse_msg_file  # noqa: E402


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    print(parse_msg_file(sys.argv[1]))


if __name__ == "__main__":
    main()
