#!/usr/bin/env python3
"""Fail real calibration nodes at connection and verify cleanup on all paths."""
import fcntl
import json
import pathlib
import signal
import sys
import tempfile
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent.parent/'tools'))
import calibrate
import runtime

scheme='stop=3\n0=30-30\n1=100-400\n2=64-512\n'
manifest={'schema_version':1,'repetitions':2,'candidates':[{'id':'default','scheme':scheme},{'id':'position-iqr','scheme':scheme}],
          'traces':[{'id':f'r{r}-s{s}','partition':'holdout' if r==3 else 'train','round':r,'target':[69,600,1600],'payload':[52,583,1583]} for r in (1,2,3) for s in range(6)]}
old_handlers={sig:signal.getsignal(sig) for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGALRM)}
before=set(pathlib.Path('/tmp').glob('yjpdding-anytls-*'))
try:
    with tempfile.TemporaryDirectory(prefix='yjpdding-calibration-test-') as temp:
        temp=pathlib.Path(temp); source=temp/'manifest.json';source.write_text(json.dumps(manifest))
        for name in ('network_error','interrupted','concurrent','invalid_manifest'):
            result=temp/(name+'.json')
            def stop_test(*args):
                if name=='interrupted':signal.raise_signal(signal.SIGTERM)
                raise RuntimeError('injected connection failure')
            state=runtime.state_dir()
            if name=='invalid_manifest':source.write_text('{}')
            with (state/'calibration.lock').open('a') as lock:
                if name=='concurrent':fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with mock.patch.object(runtime,'socks_connect',side_effect=stop_test):
                    code=calibrate.calibrate(source,state,result)
            report=json.loads(result.read_text())
            assert code==2 and report['status']=='failed' and report['cleanup_ok'],report
            assert set(pathlib.Path('/tmp').glob('yjpdding-anytls-*'))==before
            print('PASS:',name)
finally:
    for sig,handler in old_handlers.items():signal.signal(sig,handler)
