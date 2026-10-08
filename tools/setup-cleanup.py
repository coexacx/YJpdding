#!/usr/bin/env python3
"""Install a timer for registered, inactive YJpdding captures only."""
import argparse
import hashlib
import os
import pathlib
import shlex
import shutil
import subprocess
import tempfile


def atomic(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as f:
        temporary = pathlib.Path(f.name)
        f.write(text)
    temporary.chmod(0o644); temporary.replace(path)


def configure(binary, state):
    # Preserve a /current/ path so the timer follows future atomic upgrades.
    binary = pathlib.Path(os.path.abspath(binary))
    state = state.resolve(); state.mkdir(parents=True, exist_ok=True, mode=0o700)
    for value in (str(binary), str(state)):
        if any(ord(c) < 32 for c in value): raise RuntimeError('定时任务路径不能包含控制字符')
    name = 'yjpdding-cleanup-'+str(os.getuid())+'-'+hashlib.sha256(str(state).encode()).hexdigest()[:10]
    command = [str(binary), 'cleanup', '--state-dir', str(state)]
    if pathlib.Path('/run/systemd/system').is_dir() and shutil.which('systemctl'):
        user = [] if os.geteuid() == 0 else ['--user']
        directory = pathlib.Path('/etc/systemd/system') if not user else pathlib.Path.home()/'.config/systemd/user'
        def quote(s): return '"'+s.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('$', '$$')+'"'
        service = '[Unit]\nDescription=YJpdding expired capture cleanup\n\n[Service]\nType=oneshot\nNice=10\nNoNewPrivileges=true\nTimeoutStartSec=120\nExecStart='+ ' '.join(map(quote, command))+'\n'
        timer = '[Unit]\nDescription=Clean YJpdding captures older than 3 days\n\n[Timer]\nOnCalendar=hourly\nRandomizedDelaySec=5m\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n'
        changed = False
        for extension, data in [('service', service), ('timer', timer)]:
            path = directory/(name+'.'+extension)
            if not path.exists() or path.read_text() != data:
                atomic(path, data); changed = True
        if changed: subprocess.run(['systemctl']+user+['daemon-reload'], check=True, timeout=15, capture_output=True)
        subprocess.run(['systemctl']+user+['enable', '--now', name+'.timer'], check=True, timeout=15, capture_output=True)
        subprocess.run(['systemctl']+user+['is-active', '--quiet', name+'.timer'], check=True, timeout=10)
        print('三天清理定时器已启用：'+name+'.timer')
        return
    if not shutil.which('crontab'): raise RuntimeError('缺少 systemd 定时器或 crontab，无法保证无人值守清理')
    running = False
    for proc in pathlib.Path('/proc').glob('[0-9]*/comm'):
        try:
            if proc.read_text().strip() in ('cron', 'crond'): running = True; break
        except OSError: pass
    if not running: raise RuntimeError('检测到 crontab，但 cron 守护进程未运行，尚未启用自动清理')
    current = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=10)
    if current.returncode not in (0, 1): raise RuntimeError('读取当前用户 crontab 失败')
    lines = [line for line in current.stdout.splitlines() if not line.endswith('# '+name)]
    shell = shlex.join(command).replace('%', '\\%')
    lines.append('0 * * * * '+shell+' >/dev/null 2>&1 # '+name)
    subprocess.run(['crontab', '-'], input='\n'.join(lines)+'\n', text=True, check=True, timeout=10)
    print('三天清理计划已写入当前用户 crontab：'+name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=pathlib.Path, required=True)
    parser.add_argument('--state-dir', type=pathlib.Path, required=True)
    args = parser.parse_args()
    configure(args.binary, args.state_dir)
