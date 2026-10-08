#!/usr/bin/env python3
"""Real Chrome/libpcap acceptance tests against disposable local HTTPS servers.
Requires root, Chrome, OpenSSL and Xvfb. No external target is contacted.
"""
import argparse
import http.client
import http.server
import json
import os
import pathlib
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=pathlib.Path)
    parser.add_argument('--output', type=pathlib.Path, default=pathlib.Path('test-output'))
    parser.add_argument('--cases', default='all')
    args = parser.parse_args()
    binary = args.binary.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    records, noise_ports, results = [], set(), []
    with tempfile.TemporaryDirectory(prefix='yjpdding-test-') as temp:
        temp = pathlib.Path(temp)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1',
                        '-keyout', str(temp/'key.pem'), '-out', str(temp/'cert.pem')], check=True, capture_output=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(temp/'cert.pem', temp/'key.pem')

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *unused):
                pass

            def setup(self):
                self.request.settimeout(3)
                super().setup()

            def respond(self, body, content_type='text/plain', status=200, extra=None):
                self.send_response(status)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Connection', 'close')
                self.send_header('Access-Control-Allow-Origin', '*')
                for k, v in (extra or {}).items(): self.send_header(k, v)
                self.end_headers()
                self.close_connection = True
                try: self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError): pass

            def do_GET(self):
                records.append({'path': self.path, 'ua': self.headers.get('User-Agent'),
                                'platform': self.headers.get('Sec-CH-UA-Platform'), 'port': self.client_address[1]})
                if self.path == '/redirect':
                    return self.respond(b'', status=302, extra={'Location': f'https://localhost:{server4.server_port}/'})
                if self.path == '/denied': return self.respond(b'Access denied', status=403)
                if self.path == '/slow': time.sleep(8); return self.respond(b'Late')
                if self.path == '/bulk': return self.respond(b'B' * (3 * 1024 * 1024))
                if self.path == '/':
                    return self.respond(b'<html><body style="height:4000px"><h1>Chrome fixture</h1><script src="/app.js"></script><img src="/image.svg"></body></html>', 'text/html')
                if self.path == '/app.js':
                    return self.respond(b'Promise.all(Array.from({length:12}, (_,i)=>fetch("/data?i="+i))).then(()=>fetch("/ua",{method:"POST",body:JSON.stringify({ua:navigator.userAgent,platform:navigator.platform,hints:navigator.userAgentData?.toJSON()})}));', 'application/javascript')
                if self.path == '/image.svg': return self.respond(b'<svg xmlns="http://www.w3.org/2000/svg" width="2" height="2"/>', 'image/svg+xml')
                return self.respond(b'x' * (400 + len(self.path)*17))

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                try: data = json.loads(body)
                except ValueError: data = {}
                records.append({'path': self.path, 'javascript': data, 'ua': self.headers.get('User-Agent')})
                self.respond(b'ok')

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = True
            def handle_error(self, request, address): pass
        class Server6(Server): address_family = socket.AF_INET6
        server4 = Server(('127.0.0.1', 0), Handler)
        server6 = Server6(('::1', 0), Handler)
        for server in (server4, server6):
            server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
            threading.Thread(target=server.serve_forever, daemon=True).start()

        stop_noise = threading.Event()
        def noise():
            while not stop_noise.is_set():
                try:
                    connection = http.client.HTTPSConnection('127.0.0.1', server4.server_port, timeout=2, context=ssl._create_unverified_context())
                    connection.connect(); noise_ports.add((f'127.0.0.1:{connection.sock.getsockname()[1]}',f'127.0.0.1:{server4.server_port}'))
                    connection.request('GET', '/noise', headers={'User-Agent': 'Unrelated-Process'})
                    connection.getresponse().read(); connection.close()
                except (OSError, http.client.HTTPException): pass
                stop_noise.wait(0.2)
        threading.Thread(target=noise, daemon=True).start()

        target = f'https://127.0.0.1:{server4.server_port}'
        cases = [
            ('native', target+'/', ['--keylog'], 0),
            ('random', target+'/', ['--ua', 'random'], 0),
            ('custom', target+'/', ['--ua', 'custom', '--user-agent', 'YJpdding-Test/2.0'], 0),
            ('headed', target+'/', ['--browser', 'headed'], 0),
            ('ipv6', f'https://[::1]:{server6.server_port}/', [], 0),
            ('redirect', target+'/redirect', [], 0),
            ('natural', target+'/', ['--protocol', 'natural'], 0),
            ('certificate', target+'/', [], 2),
            ('http403', target+'/denied', [], 2),
            ('deadline', target+'/slow', [], 2),
            ('dns_failure', 'https://this-host-does-not-exist.invalid/', [], 2),
            ('size_limit', target+'/bulk', ['--max-mib','1'], 2),
            ('interrupt', target+'/', [], 130),
            ('bad_interface', target+'/', ['--interface','not-a-real-interface'], 1),
        ]
        requested = set(args.cases.split(','))
        try:
            for name, url, extras, expected in cases:
                if args.cases != 'all' and name not in requested: continue
                directory = args.output/name
                directory.mkdir(exist_ok=True)
                before = set(directory.iterdir()); initial = len(records)
                command = [str(binary),'capture',url,'--duration','3','--reload-interval','0','--output',str(directory)] + extras
                if name != 'certificate': command += ['--insecure']
                if name == 'interrupt': command[command.index('--duration')+1] = '30'
                started = time.monotonic()
                with (directory/'console.log').open('w') as log:
                    proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
                    if name == 'interrupt': time.sleep(2); proc.send_signal(signal.SIGINT)
                    code = proc.wait(timeout=35)
                elapsed = time.monotonic()-started
                assert code == expected, (name, code, expected, (directory/'console.log').read_text())
                created = [p for p in set(directory.iterdir())-before if p.is_dir()]
                assert len(created) == 1
                run = created[0]
                if expected != 1:
                    report = json.loads((run/'report.json').read_text())
                    session = json.loads((run/'session.json').read_text())
                    if expected == 0:
                        assert report['summary']['packets_matched'] > 0, name
                        assert session['browser']['requests'], name
                        assert report['summary']['up_ip']['count'] > 0 and report['summary']['down_ip']['count'] > 0
                        selected_ports = {(c['local'],c['remote']) for c in session['connections']}
                        assert not selected_ports.intersection(noise_ports), (name, 'foreign connection selected')
                        assert any(r['path'] == '/ua' for r in records[initial:] if 'javascript' in r), (name,'JavaScript not executed')
                    if name == 'native':
                        assert (run/'tls.keys').stat().st_size > 0
                        assert report['padding']['status'] == 'experimental_candidate', report['padding']
                        subprocess.run([str(binary),'validate',str(run/'padding-candidate.txt')],check=True,capture_output=True)
                        offline = directory/'offline'
                        subprocess.run([str(binary),'analyze',str(run/'capture.pcap'),'--session',str(run/'session.json'),'--output',str(offline)],check=True,capture_output=True)
                        off = json.loads(next(offline.glob('*/report.json')).read_text())
                        for key in ('up_tcp_payload','down_tcp_payload','up_tls_record','down_tls_record','packets_matched'):
                            assert off['summary'][key] == report['summary'][key], key
                    if name == 'custom':
                        owned = [r for r in records[initial:] if r.get('ua') != 'Unrelated-Process']
                        assert all(r['ua'] == 'YJpdding-Test/2.0' for r in owned), owned
                    if name == 'headed': assert session['browser']['virtual_display'] == (not os.environ.get('DISPLAY'))
                    if name == 'ipv6': assert any('[' in c['remote'] for c in session['connections'])
                    if name == 'redirect': assert any(r.get('status') == 302 for r in session['browser']['requests'])
                    if name == 'size_limit': assert session['capture']['size_limit_reached']
                    if name == 'interrupt': assert session['interrupted']
                    if expected != 0: assert report['padding']['scheme'] is None
                assert elapsed < 25, (name,'deadline exceeded',elapsed)
                assert not list(run.glob('.staging-*')), (name,'staging file leaked')
                result={'case':name,'exit':code,'seconds':round(elapsed,2),'passed':True}
                results.append(result); print(json.dumps(result),flush=True)
        finally:
            stop_noise.set()
            server4.shutdown();server6.shutdown()
        (args.output/'results.json').write_text(json.dumps(results,indent=2))
        print(f'PASS: {len(results)} Chrome integration cases',flush=True)


if __name__ == '__main__': main()
