#!/usr/bin/env python3
"""Pinned AnyTLS test tools and isolated loopback interoperability validation."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import pathlib
import platform
import resource
import secrets
import signal
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request
import zipfile

VERSION = '0.0.13'
DEFAULT_SCHEME_MD5 = '75cff2ad89aadf5e257059ee571ebe11'
HASHES = {
    'x86_64': ('amd64', '7e80fc099ea54a71110d256dd60648c47c63c70a3c499eb1f6d7aaa4edb7016f',
               'c1a3a52cf3246a51b2cbf427283cde2482fe99b6868588a57786c24324ac44fa',
               '577e1b5e64ff36e04436363cf44d983f0fa4ed38cc662240505b7c4362e358a1'),
    'aarch64': ('arm64', '88cb762c3c8eb56b46a2d8d6feab9c0858655192143fc164874229499246a956',
                'e7a5f3bce9b5302fb1be92f9a23e948a5627fc8931d52d7b3e44f4bb8ed29709',
                'ef34055836989bfbc82660b4d0aa855f264dd22d00552289fda96c37694711ba'),
}


def state_dir():
    return pathlib.Path(os.environ.get('YJPADDING_STATE_DIR') or
                        str(pathlib.Path(os.environ.get('XDG_STATE_HOME', str(pathlib.Path.home()/'.local/state')))/'YJpdding'))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(state):
    spec = HASHES.get(platform.machine())
    if spec is None: raise RuntimeError('当前架构没有经过固定校验的 AnyTLS 测试工具')
    arch, archive_hash, server_hash, client_hash = spec
    directory = state/'anytls'/VERSION
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (directory/'.install.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        expected = {'anytls-server': server_hash, 'anytls-client': client_hash}
        if all((directory/n).is_file() and digest(directory/n) == h for n, h in expected.items()):
            return directory
        with tempfile.TemporaryDirectory(prefix='.download-', dir=directory) as temp:
            temp = pathlib.Path(temp)
            archive = temp/'anytls.zip'
            url = f'https://github.com/anytls/anytls-go/releases/download/v{VERSION}/anytls_{VERSION}_linux_{arch}.zip'
            with urllib.request.urlopen(url, timeout=30) as response, archive.open('wb') as out:
                total = 0
                while chunk := response.read(262144):
                    total += len(chunk)
                    if total > 16*1024*1024: raise RuntimeError('AnyTLS 附件大小异常')
                    out.write(chunk)
            if digest(archive) != archive_hash: raise RuntimeError('AnyTLS 官方附件 SHA-256 校验失败')
            with zipfile.ZipFile(archive) as z:
                for name, expected_hash in expected.items():
                    info = z.getinfo(name)
                    if info.file_size > 16*1024*1024: raise RuntimeError('AnyTLS 内核大小异常')
                    data = z.read(name)
                    if hashlib.sha256(data).hexdigest() != expected_hash: raise RuntimeError('AnyTLS 内核 SHA-256 校验失败')
                    path = temp/name
                    path.write_bytes(data); path.chmod(0o755); path.replace(directory/name)
    return directory


def free_address():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size-len(data))
        if not chunk: raise RuntimeError('测试连接提前结束')
        data.extend(chunk)
    return bytes(data)


def socks_connect(address, target):
    sock = socket.create_connection(address, timeout=2)
    try:
        sock.settimeout(2)
        sock.sendall(b'\x05\x01\x00')
        if recv_exact(sock, 2) != b'\x05\x00': raise RuntimeError('SOCKS 握手失败')
        sock.sendall(b'\x05\x01\x00\x01'+socket.inet_aton(target[0])+struct.pack('!H', target[1]))
        answer = recv_exact(sock, 4)
        if answer[:2] != b'\x05\x00': raise RuntimeError('AnyTLS 无法连接本机测试端点')
        sizes = {1: 4, 4: 16}
        size = sizes.get(answer[3])
        if answer[3] == 3: size = recv_exact(sock, 1)[0]
        if size is None: raise RuntimeError('无效 SOCKS 响应')
        recv_exact(sock, size+2)
        return sock
    except BaseException:
        sock.close(); raise


def child_limits(pid):
    # Avoid preexec_fn: the echo server has threads when the client is spawned.
    os.setpriority(os.PRIO_PROCESS, pid, 10)
    resource.prlimit(pid, resource.RLIMIT_CPU, (20, 20))
    resource.prlimit(pid, resource.RLIMIT_NOFILE, (128, 128))


def wait_listener(proc, address):
    end = time.monotonic()+4
    while time.monotonic() < end:
        if proc.poll() is not None: raise RuntimeError('临时节点启动失败；可能端口被其他进程先占用')
        try:
            with socket.create_connection(address, timeout=0.1): return
        except OSError: time.sleep(0.05)
    raise RuntimeError('临时节点监听超时')


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try: proc.wait(timeout=2)
        except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=2)


def verify(scheme, state, result_path):
    report = {'status': 'failed', 'implementation': f'anytls-go v{VERSION}',
              'scope': '本机回环节点的配置同步、连接与双向数据完整性；不等同于生产节点或流量相似性验证',
              'streams': 0, 'bytes_checked': 0, 'modes': [], 'cleanup_ok': False}
    started = time.monotonic()
    children = []
    node_dir = None
    def interrupted(signum, frame): raise RuntimeError(f'验证被中断（signal {signum}）')
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM): signal.signal(sig, interrupted)
    signal.alarm(45)
    try:
        if scheme.stat().st_size > 65536: raise RuntimeError('配置超过 64 KiB')
        raw = scheme.read_bytes()
        report['scheme_sha256'] = hashlib.sha256(raw).hexdigest()
        md5 = hashlib.md5(raw).hexdigest()  # Protocol identifier, not a security hash.
        report['scheme_md5'] = md5
        binary_dir = prepare(state)
        with tempfile.TemporaryDirectory(prefix='yjpdding-anytls-') as temp:
            node_dir = pathlib.Path(temp)
            config = node_dir/'padding.txt'; config.write_bytes(raw)
            password = secrets.token_hex(24)
            env = dict(os.environ, LOG_LEVEL='info', GOMAXPROCS='1', GOMEMLIMIT='64MiB')
            for name in ('CLIENT_DEBUG_PADDING_SCHEME', 'TLS_KEY_LOG'): env.pop(name, None)
            with contextlib.ExitStack() as resources:
                def launch(name, arguments, log_name):
                    log = resources.enter_context((node_dir/log_name).open('wb'))
                    child = subprocess.Popen([str(binary_dir/name)]+arguments, stdin=subprocess.DEVNULL,
                                             stdout=log, stderr=subprocess.STDOUT, cwd=node_dir,
                                             env=env)
                    children.append(child)
                    child_limits(child.pid)
                    return child
                try:
                    server_addr = free_address()
                    server = launch('anytls-server', ['-l', f'{server_addr[0]}:{server_addr[1]}', '-p', password,
                                                     '-padding-scheme', str(config)], 'server.log')
                    wait_listener(server, server_addr)
                    if 'loaded padding scheme file:' not in (node_dir/'server.log').read_text():
                        raise RuntimeError('服务端未确认加载候选配置')
                    class Echo(socketserver.BaseRequestHandler):
                        def handle(self):
                            self.request.settimeout(2)
                            try:
                                while data := self.request.recv(65536): self.request.sendall(data)
                            except OSError: pass
                    class EchoServer(socketserver.ThreadingTCPServer):
                        daemon_threads = True
                    echo = EchoServer(('127.0.0.1', 0), Echo)
                    threading.Thread(target=lambda: echo.serve_forever(poll_interval=0.05), daemon=True).start()
                    try:
                        for mode in ('reuse', 'fresh'):
                            address = free_address()
                            arguments = ['-l', f'{address[0]}:{address[1]}', '-s', f'{server_addr[0]}:{server_addr[1]}', '-p', password, '-m', '0']
                            if mode == 'fresh': arguments += ['-dr']
                            client = launch('anytls-client', arguments, f'client-{mode}.log')
                            wait_listener(client, address)
                            with socks_connect(address, echo.server_address) as sock:
                                sock.sendall(b'padding-sync'); recv_exact(sock, 12)
                            end = time.monotonic()+2
                            while time.monotonic() < end:
                                if md5 == DEFAULT_SCHEME_MD5 or f'[Update padding succeed] {md5}' in (node_dir/f'client-{mode}.log').read_text(): break
                                time.sleep(0.02)
                            else: raise RuntimeError('客户端未确认同步候选 padding，不能判定验证通过')
                            for size in (1, 64, 512, 1400, 4096, 16384, 65536):
                                with socks_connect(address, echo.server_address) as sock:
                                    payload = secrets.token_bytes(size)
                                    sock.sendall(payload)
                                    if recv_exact(sock, size) != payload: raise RuntimeError('双向传输数据不一致')
                                report['streams'] += 1; report['bytes_checked'] += size*2
                            report['modes'].append(mode)
                            stop(client)
                    finally:
                        echo.shutdown(); echo.server_close()
                    report['client_scheme_confirmed'] = True
                    report['status'] = 'passed'
                finally:
                    for child in reversed(children): stop(child)
    except BaseException as error:
        report['error'] = str(error) or type(error).__name__
        report['status'] = 'failed'
    finally:
        signal.alarm(0)
        for child in reversed(children): stop(child)
        report['cleanup_ok'] = all(c.poll() is not None for c in children) and (node_dir is None or not node_dir.exists())
        if not report['cleanup_ok']: report['status'] = 'failed'; report['error'] = '临时节点未完成清理'
        report['seconds'] = round(time.monotonic()-started, 3)
        result_path.parent.mkdir(parents=True, exist_ok=True)
        result_path.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report['status'] == 'passed' else 2


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['prepare', 'verify'])
    parser.add_argument('--state-dir', type=pathlib.Path, default=state_dir())
    parser.add_argument('--scheme', type=pathlib.Path)
    parser.add_argument('--result', type=pathlib.Path)
    args = parser.parse_args()
    if args.action == 'prepare':
        print(prepare(args.state_dir)); return 0
    if args.scheme is None or args.result is None: parser.error('verify requires --scheme and --result')
    return verify(args.scheme.resolve(), args.state_dir.resolve(), args.result.resolve())


if __name__ == '__main__':
    raise SystemExit(main())
