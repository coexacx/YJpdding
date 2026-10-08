#!/usr/bin/env python3
"""Replay bounded length traces through owned AnyTLS nodes. Rust independently checks
all tagged record sequences against libpcap before allowing them into the score."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import pathlib
import random
import secrets
import selectors
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
import time

import runtime


class Tunnel:
    def __init__(self, local, remote):
        self.local = '%s:%d' % local
        self.remote = '%s:%d' % remote
        self.records = []
        self.buffer = bytearray()
        self.lock = threading.Lock()
        self.error = None
        self.updated = time.monotonic()

    def feed(self, data):
        with self.lock:
            self.updated = time.monotonic()
            self.buffer.extend(data)
            while len(self.buffer) >= 5:
                kind, major = self.buffer[:2]
                length = int.from_bytes(self.buffer[3:5], 'big')
                if kind not in (20, 21, 22, 23, 24) or major != 3 or length > 18432:
                    raise RuntimeError('中继收到非法 TLS record')
                if len(self.buffer) < 5 + length: break
                if kind == 23: self.records.append(length)
                del self.buffer[:5+length]
                if len(self.records) > 10000: raise RuntimeError('测试连接 TLS 记录过多')

    def snapshot(self):
        with self.lock:
            if self.error: raise RuntimeError(self.error)
            return list(self.records)

    def settled(self):
        end = time.monotonic()+0.3
        while time.monotonic() < end:
            with self.lock:
                quiet = not self.buffer and time.monotonic()-self.updated >= 0.015
            if quiet: return self.snapshot()
            time.sleep(0.003)
        raise RuntimeError('测试 TLS 写入未在限时内稳定')


class TapHandler(socketserver.BaseRequestHandler):
    def handle(self):
        tunnel = Tunnel(self.request.getpeername(), self.request.getsockname())
        with self.server.lock: self.server.tunnels.append(tunnel)
        try:
            with socket.create_connection(self.server.target, timeout=2) as upstream:
                upstream.settimeout(2); self.request.settimeout(2)
                upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                with selectors.DefaultSelector() as select:
                    select.register(self.request, selectors.EVENT_READ, upstream)
                    select.register(upstream, selectors.EVENT_READ, self.request)
                    while not self.server.stopping.is_set():
                        for key, _ in select.select(timeout=0.1):
                            data = key.fileobj.recv(65536)
                            if not data: return
                            if key.fileobj is self.request: tunnel.feed(data)
                            key.data.sendall(data)
        except OSError:
            pass  # Closing owned clients terminates idle streams as well.
        except BaseException as error:
            with tunnel.lock: tunnel.error = str(error)


class Tap(socketserver.ThreadingTCPServer):
    daemon_threads = True
    def __init__(self, target):
        self.target = target
        self.tunnels = []
        self.lock = threading.Lock()
        self.stopping = threading.Event()
        super().__init__(('127.0.0.1', 0), TapHandler)

    def latest(self):
        with self.lock:
            if not self.tunnels: raise RuntimeError('未建立测试隧道')
            return self.tunnels[-1]

    def close(self):
        self.stopping.set(); self.shutdown(); self.server_close()


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            while data := self.request.recv(65536): self.request.sendall(data)
        except OSError: pass


class EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


def serve(server):
    threading.Thread(target=lambda: server.serve_forever(poll_interval=0.03), daemon=True).start()


def validate_manifest(data):
    if data.get('schema_version') != 1 or data.get('repetitions') != 2:
        raise RuntimeError('不支持的比对任务格式')
    candidates, traces = data.get('candidates', []), data.get('traces', [])
    if not 2 <= len(candidates) <= 3 or not 18 <= len(traces) <= 30:
        raise RuntimeError('候选或测试序列数量超过限制')
    if len({c['id'] for c in candidates}) != len(candidates) or len({t['id'] for t in traces}) != len(traces):
        raise RuntimeError('重复任务标识')
    for candidate in candidates:
        if candidate['id'] not in ('default', 'position-iqr', 'position-wide') or len(candidate['scheme']) > 4096:
            raise RuntimeError('非法候选配置')
    for trace in traces:
        if trace['partition'] not in ('train', 'holdout') or not 3 <= len(trace['payload']) <= 8:
            raise RuntimeError('非法测试序列')
        if len(trace['target']) != len(trace['payload']) or any(type(v) is not int or not 1 <= v <= 16384 for v in trace['payload']):
            raise RuntimeError('非法负载长度')


def calibrate(manifest, state, result_path):
    report = {'status': 'failed', 'implementation': f'anytls-go v{runtime.VERSION}',
              'cleanup_ok': False, 'runs': [], 'scope': '本机样本长度驱动负载；Rust pcap 独立重组验证'}
    children, pending = [], []
    node_dir = None
    started = time.monotonic()
    def interrupted(signum, frame): raise RuntimeError(f'比对被中断（signal {signum}）')
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM): signal.signal(sig, interrupted)
    signal.alarm(90)
    try:
        if manifest.stat().st_size > 128*1024: raise RuntimeError('任务文件过大')
        data = json.loads(manifest.read_text()); validate_manifest(data)
        state.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (state/'calibration.lock').open('a') as lock:
            try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise RuntimeError('已有本机比对任务运行，请稍后重试') from None
            binary_dir = runtime.prepare(state)
            with tempfile.TemporaryDirectory(prefix='yjpdding-anytls-') as temp:
                node_dir = pathlib.Path(temp)
                env = dict(os.environ, LOG_LEVEL='info', GOMAXPROCS='1', GOMEMLIMIT='64MiB')
                for name in ('CLIENT_DEBUG_PADDING_SCHEME', 'TLS_KEY_LOG'): env.pop(name, None)
                with contextlib.ExitStack() as resources:
                    def launch(name, arguments, label):
                        log = resources.enter_context((node_dir/(label+'.log')).open('wb'))
                        child = subprocess.Popen([str(binary_dir/name)]+arguments, stdin=subprocess.DEVNULL,
                                                 stdout=log, stderr=subprocess.STDOUT, cwd=node_dir, env=env)
                        children.append(child); runtime.child_limits(child.pid)
                        return child
                    echo = EchoServer(('127.0.0.1', 0), Echo); serve(echo)
                    try:
                        for repetition in range(2):
                            candidates = data['candidates'][:]
                            if repetition: candidates.reverse()
                            for candidate in candidates:
                                label = f'{repetition}-{candidate["id"]}'
                                config = node_dir/'padding.txt'; config.write_text(candidate['scheme'])
                                md5 = hashlib.md5(config.read_bytes()).hexdigest()
                                password = secrets.token_hex(24)
                                address = runtime.free_address()
                                server = launch('anytls-server', ['-l', '%s:%d' % address, '-p', password,
                                                                 '-padding-scheme', str(config)], label+'-server')
                                runtime.wait_listener(server, address)
                                if 'loaded padding scheme file:' not in (node_dir/(label+'-server.log')).read_text():
                                    raise RuntimeError('服务端未确认加载配置')
                                tap = Tap(address); serve(tap)
                                try:
                                    socks = runtime.free_address()
                                    client = launch('anytls-client', ['-l', '%s:%d' % socks, '-s', '%s:%d' % tap.server_address,
                                                                     '-p', password, '-m', '0', '-dr'], label+'-client')
                                    runtime.wait_listener(client, socks)
                                    # Warm-up authenticates and synchronizes settings; never score it.
                                    with runtime.socks_connect(socks, echo.server_address) as sock:
                                        sock.sendall(b'padding-sync')
                                        if runtime.recv_exact(sock, 12) != b'padding-sync': raise RuntimeError('同步传输失败')
                                    end = time.monotonic()+2
                                    while time.monotonic() < end:
                                        if md5 == runtime.DEFAULT_SCHEME_MD5 or f'[Update padding succeed] {md5}' in (node_dir/(label+'-client.log')).read_text(): break
                                        time.sleep(0.02)
                                    else: raise RuntimeError('客户端未同步配置')
                                    previous = tap.latest()
                                    traces = data['traces'][:]
                                    random.Random(20261008+repetition).shuffle(traces)
                                    for trace in traces:
                                        with runtime.socks_connect(socks, echo.server_address) as sock:
                                            deadline = time.monotonic()+2
                                            while tap.latest() is previous and time.monotonic() < deadline: time.sleep(0.005)
                                            tunnel = tap.latest()
                                            if tunnel is previous: raise RuntimeError('本次测试需要独立的新 AnyTLS 会话')
                                            previous = tunnel
                                            # Pinned implementation emits Finished, authentication and
                                            # settings/address before the first payload Write. SOCKS
                                            # may reply early, so explicitly await these three records.
                                            deadline = time.monotonic()+2
                                            while len(tunnel.snapshot()) < 3 and time.monotonic() < deadline: time.sleep(0.005)
                                            if len(tunnel.snapshot()) < 3: raise RuntimeError('测试隧道初始化未完成')
                                            windows = []
                                            for size in trace['payload']:
                                                begin = len(tunnel.settled())
                                                if windows and begin != windows[-1]['end']: raise RuntimeError('测试窗口间出现未归属的 TLS record')
                                                payload = bytes((i*73+19) % 256 for i in range(size))
                                                start = time.monotonic(); sock.sendall(payload)
                                                if runtime.recv_exact(sock, size) != payload: raise RuntimeError('双向数据不一致')
                                                elapsed = time.monotonic()-start
                                                end_record = len(tunnel.settled())
                                                if end_record <= begin: raise RuntimeError('未观察到数据 TLS record')
                                                windows.append({'begin': begin, 'end': end_record, 'seconds': elapsed})
                                        entry = {'candidate': candidate['id'], 'trace': trace['id'], 'repetition': repetition,
                                                 'local': tunnel.local, 'remote': tunnel.remote,
                                                 'windows': windows, 'payload_bytes': sum(trace['payload']),
                                                 'data_ok': True, 'scheme_confirmed': True}
                                        pending.append((entry, tunnel))
                                    runtime.stop(client)
                                finally:
                                    # Stop the client before relay so every sent record is drained.
                                    for child in reversed(children): runtime.stop(child)
                                    time.sleep(0.03)
                                    tap.close()
                                print(json.dumps({'candidate': candidate['id'], 'repetition': repetition, 'streams': len(data['traces']), 'passed': True}), flush=True)
                    finally:
                        for child in reversed(children): runtime.stop(child)
                        echo.shutdown(); echo.server_close()
            for entry, tunnel in pending:
                entry['up_records'] = tunnel.snapshot()
                if tunnel.buffer: raise RuntimeError('中继存在不完整 TLS record')
                report['runs'].append(entry)
            report['status'] = 'passed'
    except BaseException as error:
        report['error'] = str(error) or type(error).__name__
    finally:
        signal.alarm(0)
        for child in reversed(children): runtime.stop(child)
        report['cleanup_ok'] = all(c.poll() is not None for c in children) and (node_dir is None or not node_dir.exists())
        if not report['cleanup_ok']: report['status'] = 'failed'; report['error'] = '临时节点未完成清理'
        report['seconds'] = round(time.monotonic()-started, 3)
        result_path.parent.mkdir(parents=True, exist_ok=True)
        result_path.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps({k: v for k, v in report.items() if k != 'runs'}, ensure_ascii=False), flush=True)
    return 0 if report['status'] == 'passed' else 2


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=pathlib.Path, required=True)
    parser.add_argument('--result', type=pathlib.Path, required=True)
    parser.add_argument('--state-dir', type=pathlib.Path, default=runtime.state_dir())
    args = parser.parse_args()
    return calibrate(args.input.resolve(), args.state_dir.resolve(), args.result.resolve())


if __name__ == '__main__': raise SystemExit(main())
