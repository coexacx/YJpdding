#!/usr/bin/env python3
"""Release transaction tests with local archive fixtures; no network/systemd changes."""
import hashlib
import io
import json
import os
import pathlib
import sys
import tarfile
import tempfile
import urllib.request
from unittest import mock

root = pathlib.Path(__file__).resolve().parent.parent
source = (root/'capture.sh').read_text().split('python3 - "$REPOSITORY" "$asset" "$INSTALL_DIR" <<\'PY\'\n', 1)[1].split('\nPY\n', 1)[0]
asset = 'yjpdding-linux-x86_64.tar.gz'

for case in ('success', 'self_test_failure', 'checksum_failure'):
    with tempfile.TemporaryDirectory(prefix='yjpdding-installer-test-') as temp:
        temp = pathlib.Path(temp)
        package = temp/'yjpdding'; (package/'bin').mkdir(parents=True); (package/'tools').mkdir()
        code = 2 if case == 'self_test_failure' else 0
        binary = package/'bin/capture-rs'
        binary.write_text(f'#!/bin/sh\nif [ "$1" = --version ]; then echo fixture-2.1.0; exit 0; fi\nexit {code}\n')
        binary.chmod(0o755)
        for name in ('runtime.py', 'setup-cleanup.py'): (package/'tools'/name).write_text('print("fixture helper")\n')
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w:gz') as tar: tar.add(package, arcname='yjpdding')
        content = archive.getvalue(); checksum = hashlib.sha256(content).hexdigest()
        destination = temp/'installed'; destination.mkdir()
        old = destination/'old'; old.mkdir(); (destination/'current').symlink_to(old)
        release = {'tag_name':'v2.1.0','assets':[{'name': name, 'url': 'https://fixtures.test/'+name, 'browser_download_url':'https://fixtures.test/'+name} for name in (asset, 'SHA256SUMS')]}
        class Opener:
            def open(self, request, timeout):
                url = request.full_url
                if '/releases/' in url: data = json.dumps(release).encode()
                elif url.endswith('SHA256SUMS'): data = ((('0'*64) if case == 'checksum_failure' else checksum)+'  '+asset+'\n').encode()
                else: data = content
                return io.BytesIO(data)
        with mock.patch.object(sys, 'argv', ['installer','coexacx/YJpdding',asset,str(destination)]), mock.patch.object(urllib.request,'build_opener',return_value=Opener()):
            try:
                exec(compile(source, 'installer', 'exec'), {'__name__':'__main__'})
                assert case == 'success', case
            except SystemExit as error:
                assert case != 'success', str(error)
        if case == 'success': assert (destination/'current').resolve() != old
        else: assert (destination/'current').resolve() == old
        assert not list(destination.glob('.install-*'))
        print('PASS:', case)
