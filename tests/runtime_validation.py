#!/usr/bin/env python3
"""Exercise real temporary AnyTLS processes, including exception cleanup."""
import importlib.util
import json
import os
import pathlib
import signal
import tempfile
from unittest import mock

root = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('runtime', root/'tools/runtime.py')
runtime = importlib.util.module_from_spec(spec); spec.loader.exec_module(runtime)
runtime.prepare(runtime.state_dir())
before = set(pathlib.Path('/tmp').glob('yjpdding-anytls-*'))
with tempfile.TemporaryDirectory(prefix='yjpdding-validation-tests-') as temp:
    temp = pathlib.Path(temp)
    scheme = temp/'candidate.txt'; scheme.write_text('stop=3\n0=30-30\n1=100-400\n2=64-512\n')
    old_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM)}
    results = []
    try:
        for case in ('success', 'network_error', 'interrupted', 'bad_scheme'):
            result = temp/(case+'.json')
            context = mock.patch.object(runtime, 'socks_connect', wraps=runtime.socks_connect)
            if case == 'network_error': context = mock.patch.object(runtime, 'socks_connect', side_effect=RuntimeError('injected network failure'))
            if case == 'interrupted':
                def interrupt(*args): os.kill(os.getpid(), signal.SIGTERM)
                context = mock.patch.object(runtime, 'socks_connect', side_effect=interrupt)
            if case == 'bad_scheme': scheme.write_text('stop=invalid\n0=30-30\n')
            with context:
                code = runtime.verify(scheme, runtime.state_dir(), result)
            report = json.loads(result.read_text())
            assert report['cleanup_ok'], report
            assert code == (0 if case == 'success' else 2), report
            if case == 'success':
                assert report['streams'] == 14 and report['modes'] == ['reuse', 'fresh']
                assert report['client_scheme_confirmed'] and report['bytes_checked'] == 351972
            assert set(pathlib.Path('/tmp').glob('yjpdding-anytls-*')) == before
            results.append(case)
    finally:
        for sig, handler in old_handlers.items(): signal.signal(sig, handler)
    print('PASS: AnyTLS validation and cleanup:', ', '.join(results))
