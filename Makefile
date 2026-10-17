PYTHON ?= python3
PYTEST ?= $(PYTHON) -m pytest
CAP := captures

.PHONY: all tls12-ecdhe tls12-rsa tls13 tls13-relay tls13-psk mtls \
        parse verify tls12-records test clean help

all: tls12-ecdhe tls12-rsa tls13 tls13-relay tls12-records tls13-psk mtls parse verify test

help:
	@echo "TLS 学习项目目标:"
	@echo "  make tls12-ecdhe   TLS1.2 ECDHE 握手抓包"
	@echo "  make tls12-rsa     TLS1.2 静态 RSA 握手抓包"
	@echo "  make tls13         TLS1.3 握手抓包 (-msg + keylog)"
	@echo "  make tls13-relay   TLS1.3 中继抓包 (原始字节流)"
	@echo "  make tls13-psk     TLS1.3 PSK 恢复 + 0-RTT 实验"
	@echo "  make mtls          mTLS 双向认证实验"
	@echo "  make parse         解析抓包报文"
	@echo "  make verify        密码学全链路验证 (TLS1.2 + TLS1.3)"
	@echo "  make tls12-records TLS1.2 记录层密文解密"
	@echo "  make test          pytest 单元测试"
	@echo "  make clean         清理产物"

tls12-ecdhe:
	bash scripts/run_tls12.sh

tls12-rsa:
	bash scripts/run_tls12.sh AES128-GCM-SHA256

tls13:
	bash scripts/run_tls13.sh

tls13-relay:
	bash scripts/run_tls13_all.sh

tls13-psk:
	bash scripts/run_tls13_psk.sh

mtls:
	bash scripts/run_mtls.sh

parse:
	$(PYTHON) scripts/parse_handshake.py $(CAP)/tls13_msg.txt
	$(PYTHON) scripts/parse_handshake.py $(CAP)/tls12_ecdhe_msg.txt
	$(PYTHON) scripts/parse_handshake.py $(CAP)/tls12_rsa_ks_msg.txt

verify:
	$(PYTHON) scripts/verify_tls12_crypto.py
	$(PYTHON) scripts/verify_tls13_crypto.py
	$(PYTHON) scripts/verify_tls13_psk.py
	$(PYTHON) scripts/verify_mtls.py

tls12-records:
	$(PYTHON) scripts/run_tls12_relay.py
	$(PYTHON) scripts/verify_tls12_records.py

test:
	$(PYTEST) tests/ -v

clean:
	mkdir -p $(CAP) && rm -f $(CAP)/*
	rm -rf scripts/__pycache__ scripts/tlslib/__pycache__ .pytest_cache
