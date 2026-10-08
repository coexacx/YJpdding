#!/usr/bin/env python3
"""Real systemd timer/cleanup check using only disposable owned fixture paths."""
import fcntl
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

binary = pathlib.Path(sys.argv[1]).resolve()
root = pathlib.Path(__file__).resolve().parent.parent
assert os.geteuid() == 0 and pathlib.Path('/run/systemd/system').is_dir()
with tempfile.TemporaryDirectory(prefix='yjpdding-cleanup-test-') as temporary:
    temporary = pathlib.Path(temporary)
    state = temporary/'state'; state.mkdir()
    output = temporary/'captures'; output.mkdir()
    (state/'capture-roots.json').write_text(json.dumps([str(output)]))
    for name, days in [('expired', 4), ('active', 4), ('recent', 1), ('unrelated', 4)]:
        directory = output/name; directory.mkdir()
        (directory/'.active.lock').touch()
        if name != 'unrelated':
            (directory/'.yjpdding-capture.json').write_text(json.dumps({'owner':'YJpdding','created_at':int(time.time())-days*86400,'target':'fixture'}))
    active = (output/'active/.active.lock').open('r+')
    fcntl.flock(active, fcntl.LOCK_EX)
    (output/'link').symlink_to(output/'recent')
    name = 'yjpdding-cleanup-0-'+hashlib.sha256(str(state).encode()).hexdigest()[:10]
    units = [pathlib.Path('/etc/systemd/system')/(name+'.'+extension) for extension in ('service','timer')]
    assert not any(p.exists() for p in units)
    try:
        subprocess.run([sys.executable,str(root/'tools/setup-cleanup.py'),'--binary',str(binary),'--state-dir',str(state)],check=True)
        subprocess.run(['systemctl','is-active','--quiet',name+'.timer'],check=True)
        subprocess.run(['systemctl','start',name+'.service'],check=True,timeout=15)
        assert not (output/'expired').exists()
        for item in ('active','recent','unrelated','link'): assert (output/item).exists(), item
        active.close()
        subprocess.run(['systemctl','start',name+'.service'],check=True,timeout=15)
        assert not (output/'active').exists()
        print('PASS: real timer, expired cleanup, active lock, unrelated data and symlink protection')
    finally:
        active.close()
        subprocess.run(['systemctl','disable','--now',name+'.timer'],check=False,capture_output=True)
        subprocess.run(['systemctl','stop',name+'.service'],check=False,capture_output=True)
        for path in units: path.unlink(missing_ok=True)
        subprocess.run(['systemctl','daemon-reload'],check=True)
