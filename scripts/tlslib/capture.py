"""
抓包工具库：openssl s_server 上下文管理器 + TCP 中继（落盘原始字节流）。
供 run_tls13_relay.py / run_tls12_relay.py 等复用。
"""
import contextlib
import socket
import subprocess
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent  # scripts/tlslib/../.. → 项目根
CERTS = ROOT / "certs"


@contextlib.contextmanager
def tls_server(port, version, cert, key, extra_args=()):
    """启动 openssl s_server，退出时可靠清理（含异常路径）"""
    proc = subprocess.Popen(
        ["openssl", "s_server", "-accept", str(port), f"-{version}", "-quiet",
         "-www", "-cert", str(CERTS / cert), "-key", str(CERTS / key), *extra_args],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL)
    time.sleep(0.6)
    try:
        yield proc
    finally:
        proc.kill()
        proc.wait()


def pipe(src, dst, f):
    """双向转发并落盘"""
    try:
        while True:
            d = src.recv(65536)
            if not d:
                break
            f.write(d)
            f.flush()
            dst.sendall(d)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class Relay:
    """TCP 中继: 监听 listen_port, 转发到 target_port, 双向原始字节落盘。
    弥补 openssl -msg 只显示解密后内容、不显示密文的不足。"""

    def __init__(self, listen_port, target_port, c2s_path, s2c_path):
        self.listen_port = listen_port
        self.target_port = target_port
        self.c2s_path = Path(c2s_path)
        self.s2c_path = Path(s2c_path)
        self._lsock = None
        self._thread = None
        self._stop = threading.Event()

    def start(self):
        self._lsock = socket.socket()
        self._lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._lsock.bind(("127.0.0.1", self.listen_port))
        self._lsock.listen(1)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        print(f"中继监听 127.0.0.1:{self.listen_port} → 127.0.0.1:{self.target_port}")

    def _serve(self):
        while not self._stop.is_set():
            self._lsock.settimeout(0.2)
            try:
                cli, _ = self._lsock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            up = None
            for _ in range(20):  # s_server 可能尚未监听, 重试 2s
                try:
                    up = socket.create_connection(("127.0.0.1", self.target_port), timeout=1)
                    break
                except OSError:
                    time.sleep(0.1)
            if up is None:
                return
            with open(self.c2s_path, "wb") as f1, open(self.s2c_path, "wb") as f2:
                threading.Thread(target=pipe, args=(cli, up, f1), daemon=True).start()
                threading.Thread(target=pipe, args=(up, cli, f2), daemon=True).start()
                while up.fileno() != -1 and cli.fileno() != -1:
                    time.sleep(0.1)
                    if f1.closed or f2.closed:
                        break

    def stop(self):
        self._stop.set()
        if self._lsock:
            self._lsock.close()


def run_s_client(args, stdin=b"", timeout=8, msg_out=None):
    """跑一次 openssl s_client; 若 msg_out 给定则把 -msg 输出(stdout)写入该文件"""
    cmd = ["openssl", "s_client", *args]
    r = subprocess.run(cmd, input=stdin, capture_output=True, timeout=timeout)
    if msg_out:
        Path(msg_out).write_bytes(r.stdout)  # -msg 报文输出在 stdout
    return r
