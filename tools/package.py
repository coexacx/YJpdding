#!/usr/bin/env python3
"""Package the locally built, static kernel, launcher and third-party notices."""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile

root = pathlib.Path(__file__).resolve().parent.parent
target, pcap_license = sys.argv[1:]
arch = target.split('-')[0]
dist = root/'dist'; dist.mkdir(exist_ok=True)
binary = root/'target'/target/'release'/'capture-rs'
if not binary.is_file(): raise SystemExit('Build binary first')
description = subprocess.check_output(['file', str(binary)], text=True)
if 'static' not in description: raise SystemExit('Release kernel must be statically linked')
metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--format-version', '1', '--locked'], cwd=root))
with tempfile.TemporaryDirectory(prefix='yjpdding-package-') as tmp:
    package = pathlib.Path(tmp)/'yjpdding'
    (package/'bin').mkdir(parents=True)
    shutil.copy2(binary, package/'bin'/'capture-rs')
    for name in ('capture.sh','install.sh','README.md'):
        shutil.copy2(root/name, package/name)
    shutil.copytree(root/'docs',package/'docs')
    shutil.copytree(root/'tools',package/'tools',ignore=shutil.ignore_patterns('__pycache__','package.py'))
    (package/'capture.sh').chmod(0o755); (package/'install.sh').chmod(0o755)
    licenses = package/'licenses'; licenses.mkdir()
    shutil.copy2(pcap_license, licenses/'libpcap-1.10.5-LICENSE')
    musl_notice = pathlib.Path('/usr/share/doc/musl/copyright')
    if not musl_notice.is_file(): raise SystemExit('Missing musl copyright notice')
    shutil.copy2(musl_notice,licenses/'musl-COPYRIGHT')
    rustc = os.environ.get('RUSTC','rustc')
    sysroot = pathlib.Path(subprocess.check_output([rustc,'--print','sysroot'],text=True).strip())
    rust_notices = sysroot/'share/doc/rust'
    if not rust_notices.is_dir(): raise SystemExit('Missing Rust standard library notices; use rustup release toolchain')
    shutil.copytree(rust_notices/'licenses',licenses/'rust-licenses')
    shutil.copy2(rust_notices/'COPYRIGHT-library.html',licenses/'rust-COPYRIGHT-library.html')
    entries = []
    for dep in metadata['packages']:
        if dep['name'] == 'capture-rs': continue
        directory = pathlib.Path(dep['manifest_path']).parent
        copied = []
        for source in directory.iterdir():
            if source.is_file() and source.name.upper().startswith(('LICENSE','COPYING','COPYRIGHT','NOTICE')):
                dest = licenses/(dep['name']+'-'+dep['version']+'-'+source.name)
                shutil.copy2(source,dest);copied.append(dest.name)
        entries.append({'name':dep['name'],'version':dep['version'],'license':dep.get('license'),'notices':copied,'repository':dep.get('repository')})
    (licenses/'dependencies.json').write_text(json.dumps(entries,indent=2))
    archive=dist/f'yjpdding-linux-{arch}.tar.gz'
    with tarfile.open(archive,'w:gz') as tar: tar.add(package,arcname='yjpdding')
shutil.copy2(binary,dist/f'capture-rs-linux-{arch}')
shutil.copy2(root/'capture.sh',dist/'capture.sh')
lines=[]
for archive in sorted(list(dist.glob('yjpdding-linux-*.tar.gz'))+list(dist.glob('capture-rs-linux-*'))+[dist/'capture.sh']):
    lines.append(hashlib.sha256(archive.read_bytes()).hexdigest()+'  '+archive.name)
(dist/'SHA256SUMS').write_text('\n'.join(lines)+'\n')
print(archive)
