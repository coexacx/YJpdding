#!/usr/bin/env bash
# YJpdding launcher and runtime installer. No Rust toolchain is needed to deploy.
set -euo pipefail
REPOSITORY="coexacx/YJpdding"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${YJPADDING_INSTALL_DIR:-${XDG_DATA_HOME:-${HOME}/.local/share}/YJpdding}"

banner() {
    if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then printf '\033[1;36m'; fi
    cat <<'BANNER'

  ╭──────────────────────────────────────────────────────╮
  │  YJ PADDING               CHROME × RUST              │
  │  真实浏览器采集 · 预编译内核 · 一键部署              │
  ╰──────────────────────────────────────────────────────╯
BANNER
    if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then printf '\033[0m'; fi
}
die() { printf '错误：%s\n' "$*" >&2; exit 1; }
chrome_available() {
    local name
    for name in google-chrome google-chrome-stable chromium chromium-browser; do
        if command -v "$name" >/dev/null 2>&1; then return 0; fi
    done
    return 1
}
system_info() {
    [[ "$(uname -s)" == Linux ]] || die "目前仅支持 Linux"
    [[ -r /etc/os-release ]] || die "无法识别操作系统（缺少 /etc/os-release）"
    # Trusted system metadata, not downloaded content.
    # shellcheck disable=SC1091
    . /etc/os-release
    printf '系统：%s\n架构：%s\n' "${PRETTY_NAME:-$ID}" "$(uname -m)"
    local mem_kib free_kib cgroup_limit
    mem_kib=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
    if [[ -r /sys/fs/cgroup/memory.max ]]; then
        cgroup_limit=$(cat /sys/fs/cgroup/memory.max)
        if [[ "$cgroup_limit" =~ ^[0-9]+$ ]] && (( cgroup_limit / 1024 < mem_kib )); then mem_kib=$((cgroup_limit / 1024)); fi
    fi
    free_kib=$(df -Pk "$SCRIPT_DIR" | awk 'NR==2 {print $4}')
    printf '可用内存：%s MiB\n启动目录可用磁盘：%s MiB\n' "$((mem_kib / 1024))" "$((free_kib / 1024))"
    printf 'Rust：部署无需安装\nChrome：'
    if chrome_available; then printf '已检测到\n'; else printf '待安装\n'; fi
    printf 'Xvfb：'; if command -v Xvfb >/dev/null 2>&1; then printf '已安装\n'; else printf '待安装（用于无桌面的有界面模式）\n'; fi
    YJ_MEM_KIB="$mem_kib"
}
runtime_packages() {
    local root_cmd=()
    if (( EUID != 0 )); then command -v sudo >/dev/null 2>&1 || die "安装系统依赖需要 root 或 sudo"; root_cmd=(sudo); fi
    local family=" ${ID:-} ${ID_LIKE:-} "
    if [[ "$family" == *debian* || "$family" == *ubuntu* ]]; then
        "${root_cmd[@]}" env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 update
        "${root_cmd[@]}" env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y --no-install-recommends ca-certificates python3 tar gzip coreutils xvfb xauth
        if ! chrome_available; then
            if [[ "${ID:-}" == ubuntu && "$(uname -m)" == x86_64 ]]; then
                local deb_dir
                deb_dir=$(mktemp -d /tmp/yjpdding-chrome.XXXXXX)
                python3 - "$deb_dir/chrome.deb" <<'PY'
import sys, urllib.request
urllib.request.urlretrieve('https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb', sys.argv[1])
PY
                chmod 755 "$deb_dir"
                chmod 644 "$deb_dir/chrome.deb"
                "${root_cmd[@]}" env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y "$deb_dir/chrome.deb"
                rm -f -- "$deb_dir/chrome.deb"; rmdir -- "$deb_dir"
            else
                "${root_cmd[@]}" env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y chromium
            fi
        fi
    elif [[ "$family" == *fedora* || "$family" == *rhel* || "$family" == *centos* ]]; then
        "${root_cmd[@]}" dnf install -y ca-certificates python3 tar gzip coreutils xorg-x11-server-Xvfb xorg-x11-xauth
        if ! chrome_available; then "${root_cmd[@]}" dnf install -y chromium; fi
    elif [[ "$family" == *arch* ]]; then
        "${root_cmd[@]}" pacman -S --noconfirm --needed ca-certificates python tar gzip coreutils xorg-server-xvfb xorg-xauth
        if ! chrome_available; then "${root_cmd[@]}" pacman -S --noconfirm --needed chromium; fi
    elif [[ "$family" == *suse* ]]; then
        "${root_cmd[@]}" zypper --non-interactive install ca-certificates python3 tar gzip coreutils xorg-x11-server-Xvfb xauth
        if ! chrome_available; then "${root_cmd[@]}" zypper --non-interactive install chromium; fi
    elif [[ "${ID:-}" == alpine ]]; then
        "${root_cmd[@]}" apk add ca-certificates python3 tar gzip coreutils xvfb xauth chromium
    else
        die "暂未自动适配 ${PRETTY_NAME:-$ID}；请手动安装 Chrome、Python3、tar、gzip 后使用 --install --skip-packages"
    fi
}
install_release() {
    local skip_packages="${1:-}" asset arch
    banner; system_info
    (( YJ_MEM_KIB >= 524288 )) || die "可用内存不足 512 MiB，无法可靠运行 Chrome"
    case "$(uname -m)" in
        x86_64|amd64) arch=x86_64 ;;
        aarch64|arm64) arch=aarch64 ;;
        *) die "暂无当前架构的预编译内核" ;;
    esac
    asset="yjpdding-linux-${arch}.tar.gz"
    mkdir -p -- "$INSTALL_DIR"
    local free_kib
    free_kib=$(df -Pk "$INSTALL_DIR" | awk 'NR==2 {print $4}')
    (( free_kib >= 1048576 )) || die "安装目录可用磁盘不足 1 GiB"
    if [[ "$skip_packages" != --skip-packages ]]; then runtime_packages; fi
    command -v python3 >/dev/null 2>&1 || die "需要 Python3 下载和校验发行包"
    chrome_available || die "未找到 Chrome/Chromium，系统依赖安装未完成"
    # Python streams downloads, strips authorization on cross-host redirects, and
    # only installs a checksum-verified archive. Token support is optional.
    python3 - "$REPOSITORY" "$asset" "$INSTALL_DIR" <<'PY'
import hashlib, json, os, pathlib, shutil, subprocess, sys, tarfile, tempfile, urllib.error, urllib.request
repo, asset_name, destination = sys.argv[1:]
root = pathlib.Path(destination).resolve()
token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
version = os.environ.get('YJPADDING_VERSION', 'latest')
if not version or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-' for c in version):
    raise SystemExit('无效版本号')
class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        result = super().redirect_request(req, fp, code, msg, headers, newurl)
        from urllib.parse import urlparse
        if urlparse(newurl).scheme != 'https': raise RuntimeError('拒绝非 HTTPS 重定向')
        if urlparse(newurl).hostname != 'api.github.com': result.remove_header('Authorization')
        return result
opener = urllib.request.build_opener(Redirect())
def request(url, accept='application/vnd.github+json'):
    headers = {'Accept': accept, 'User-Agent': 'YJpdding-installer/2.0', 'X-GitHub-Api-Version': '2022-11-28'}
    if token and url.startswith('https://api.github.com/'): headers['Authorization'] = 'Bearer ' + token
    return opener.open(urllib.request.Request(url, headers=headers), timeout=45)
try:
    endpoint = 'latest' if version == 'latest' else 'tags/' + version
    with request(f'https://api.github.com/repos/{repo}/releases/{endpoint}') as response:
        release = json.load(response)
    assets = {a['name']: a for a in release['assets']}
    if asset_name not in assets: raise RuntimeError(f'此发行版尚未提供 {asset_name}，不会尝试运行其他架构的程序')
    if 'SHA256SUMS' not in assets: raise RuntimeError('发行版缺少 SHA256SUMS')
    with tempfile.TemporaryDirectory(prefix='.install-', dir=root) as scratch:
        scratch = pathlib.Path(scratch)
        for name in ('SHA256SUMS', asset_name):
            info = assets[name]
            url = info['url'] if token else info['browser_download_url']
            with request(url, 'application/octet-stream') as response, (scratch/name).open('wb') as out:
                size = 0
                while chunk := response.read(1024*1024):
                    size += len(chunk)
                    if size > 100*1024*1024: raise RuntimeError('发行附件超过 100 MiB 限制')
                    out.write(chunk)
        expected = None
        for line in (scratch/'SHA256SUMS').read_text().splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[1].lstrip('*') == asset_name: expected = fields[0].lower()
        actual = hashlib.sha256((scratch/asset_name).read_bytes()).hexdigest()
        if not expected or actual != expected: raise RuntimeError('SHA-256 校验失败，保留原安装')
        extracted = scratch/'package'; extracted.mkdir()
        with tarfile.open(scratch/asset_name, 'r:gz') as archive:
            members = archive.getmembers()
            if sum(m.size for m in members) > 200*1024*1024: raise RuntimeError('解压大小超限')
            for member in members:
                p = pathlib.PurePosixPath(member.name)
                if p.is_absolute() or '..' in p.parts or not (member.isfile() or member.isdir()): raise RuntimeError('不安全的压缩包成员')
                if member.mode & 0o7000: raise RuntimeError('压缩包含特殊权限')
            archive.extractall(extracted, members=members)
        package = extracted/'yjpdding'
        executable = package/'bin'/'capture-rs'
        if not executable.is_file(): raise RuntimeError('发行包缺少内核')
        executable.chmod(0o755)
        subprocess.run([str(executable), '--version'], check=True, timeout=10)
        releases = root/'releases'; releases.mkdir(exist_ok=True)
        tag = release['tag_name']
        if not tag or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-' for c in tag): raise RuntimeError('无效发行 tag')
        installed = releases/(tag + '-' + actual[:12])
        if not installed.exists(): shutil.move(str(package), installed)
        tmp_link = root/('.current-' + str(os.getpid()))
        tmp_link.symlink_to(installed, target_is_directory=True)
        tmp_link.replace(root/'current')
        print('✓ SHA-256 校验通过；已安装：', installed)
except (urllib.error.HTTPError, urllib.error.URLError) as error:
    raise SystemExit(f'GitHub 下载失败（检查网络、版本或仓库读取权限）：{error}')
except Exception as error:
    raise SystemExit(f'安装失败，原内核未替换：{error}')
PY
    printf '\n安装完成。启动：bash %q\n' "${BASH_SOURCE[0]}"
}

case "${1:-}" in
    --install|--update) install_release "${2:-}"; exit ;;
    --check) banner; system_info; exit ;;
esac
PROJECT_DIR=""
for candidate in "$INSTALL_DIR/current" "$SCRIPT_DIR" "$SCRIPT_DIR/capture-rs"; do
    if [[ -x "$candidate/bin/capture-rs" ]]; then PROJECT_DIR="$candidate"; break; fi
done
if [[ -z "$PROJECT_DIR" ]]; then
    banner
    if [[ ! -t 0 ]]; then die "尚未安装内核，请执行 bash ${BASH_SOURCE[0]} --install"; fi
    printf '\n  1  一键检测并安装运行环境与内核\n  2  仅查看系统与资源\n  0  退出\n\n'
    read -rp '请选择 [1]: ' choice
    case "${choice:-1}" in
        1) install_release; PROJECT_DIR="$INSTALL_DIR/current" ;;
        2) system_info; exit ;;
        0) exit ;;
        *) die "无效菜单项" ;;
    esac
fi
export CAPTURE_PROJECT_DIR="$PROJECT_DIR"
exec "$PROJECT_DIR/bin/capture-rs" "$@"
