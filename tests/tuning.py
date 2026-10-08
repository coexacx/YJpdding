#!/usr/bin/env python3
"""Real Chrome + AnyTLS + pcap integration with independent sampling rounds."""
import argparse
import http.server
import json
import os
import pathlib
import signal
import shutil
import ssl
import subprocess
import tempfile
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument('--binary', type=pathlib.Path, default=pathlib.Path('target/debug/capture-rs'))
parser.add_argument('--output', type=pathlib.Path, default=pathlib.Path('test-output/tuning'))
parser.add_argument('--case', choices=['success', 'insufficient', 'interrupt', 'tampered'], default='success')
args = parser.parse_args()
binary = args.binary.resolve(); args.output.mkdir(parents=True, exist_ok=True)
os.environ['YJPADDING_SKIP_TIMER'] = '1'
before = set(pathlib.Path('/tmp').glob('yjpdding-anytls-*'))
with tempfile.TemporaryDirectory(prefix='yjpdding-tuning-fixture-') as temp:
    temp = pathlib.Path(temp)
    if args.case == 'tampered':
        tools = temp/'package'/'tools'; tools.mkdir(parents=True)
        project = pathlib.Path(__file__).resolve().parent.parent
        shutil.copy2(project/'tools/runtime.py',tools/'runtime.py')
        helper = (project/'tools/calibrate.py').read_text().replace("entry['up_records'] = tunnel.snapshot()", "entry['up_records'] = tunnel.snapshot(); entry['up_records'][0] += 1")
        (tools/'calibrate.py').write_text(helper)
        os.environ['CAPTURE_PROJECT_DIR'] = str(tools.parent)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(temp/'key'),'-out',str(temp/'cert'),'-days','1','-subj','/CN=localhost'], check=True, capture_output=True)
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *args): pass
        def do_GET(self):
            script = '''<html><body>Stratified fixture<script>
(async()=>{for(let wave=0;wave<6;wave++){
await Promise.all(Array.from({length:18},(_,i)=>fetch('/sample?i='+i+'&w='+wave,{method:'POST',body:'A'.repeat([16,128,800,3000,8000,16000][(i+wave)%6])})));
}document.title='done';})();</script></body></html>'''.encode()
            self.send_response(200); self.send_header('Content-Type','text/html');self.send_header('Content-Length',str(len(script)));self.end_headers();self.wfile.write(script)
        def do_POST(self):
            size = int(self.headers.get('Content-Length', '0')); self.rfile.read(size)
            body = b'B' * (size+35)
            self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    class Server(http.server.ThreadingHTTPServer):
        daemon_threads=True
        def handle_error(self,*args):pass
    server=Server(('127.0.0.1',0),Handler)
    if args.case != 'insufficient':
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(temp/'cert',temp/'key')
        server.socket=context.wrap_socket(server.socket,server_side=True,do_handshake_on_connect=False)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        protocol='http' if args.case=='insufficient' else 'https'
        command=[str(binary),'capture',f'{protocol}://127.0.0.1:{server.server_port}/','--rounds','3','--duration','12','--reload-interval','0','--browse-interval','0','--insecure','--output',str(args.output)]
        old=set(args.output.iterdir())
        logpath=args.output/'console.log'
        with logpath.open('w') as log:
            proc=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT)
            try:
                if args.case=='interrupt':
                    deadline=time.monotonic()+50
                    while time.monotonic()<deadline:
                        if '实测筛选：' in logpath.read_text():
                            time.sleep(1);proc.send_signal(signal.SIGINT);break
                        if proc.poll() is not None:raise AssertionError(logpath.read_text())
                        time.sleep(0.1)
                    else:raise AssertionError('未进入比对阶段')
                code=proc.wait(timeout=130)
            except BaseException:
                proc.send_signal(signal.SIGTERM);proc.wait(timeout=8);raise
        runs=[p for p in set(args.output.iterdir())-old if p.is_dir()]
        assert len(runs)==1,runs
        output=runs[0]
        assert not list(output.rglob('.calibration-*.pcap')),'暂存抓包泄漏'
        assert set(pathlib.Path('/tmp').glob('yjpdding-anytls-*'))==before,'临时节点目录泄漏'
        if args.case=='success':
            assert code==0,(code,logpath.read_text())
            selection=json.loads((output/'selection.json').read_text())
            sampling=json.loads((output/'sampling.json').read_text())
            manifest=json.loads((output/'calibration-input.json').read_text())
            benchmark=json.loads((output/'calibration-runtime.json').read_text())
            assert len(sampling)==3 and all(s['quality_ok'] and len(s['flows'])>=6 for s in sampling)
            assert selection['status'] in ('baseline_retained','measured_candidate_selected'),selection
            assert selection['validation']['cleanup_ok'] and selection['validation']['status']=='passed'
            assert (output/'padding-verified.txt').is_file()
            assert benchmark['cleanup_ok'] and len(benchmark['runs'])==len(manifest['candidates'])*18*2
            assert all(len(e['holdout_repetitions'])==2 for e in selection['evaluations'])
            assert next(output.glob('*-anytls-comparison.pcap')).stat().st_size>1000
            assert all(len(set(c['scheme'].splitlines()[3:]))>1 for c in manifest['candidates'][1:])
        elif args.case=='tampered':
            assert code!=0 and 'pcap 与测试记录不一致' in logpath.read_text(),logpath.read_text()
            assert not (output/'padding-verified.txt').exists()
            assert json.loads((output/'calibration-runtime.json').read_text())['cleanup_ok']
        elif args.case=='insufficient':
            assert code!=0 and (output/'failure.json').is_file(),logpath.read_text()
            assert not (output/'padding-verified.txt').exists()
        else:
            assert code==130,(code,logpath.read_text())
            assert not (output/'padding-verified.txt').exists()
            result=json.loads((output/'calibration-runtime.json').read_text())
            assert result['status']=='failed' and result['cleanup_ok'],result
        print(json.dumps({'case':args.case,'passed':True,'exit':code,'output':str(output)},ensure_ascii=False))
    finally:server.shutdown();server.server_close()
