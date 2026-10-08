#!/usr/bin/env bash
# Development host only. Deployment uses prebuilt release assets.
set -euo pipefail
directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$directory"
export PATH="${HOME}/.cargo/bin:${PATH}"
case "$(uname -m)" in x86_64) arch=x86_64 ;; aarch64) arch=aarch64 ;; *) echo 'Unsupported build architecture' >&2; exit 1 ;; esac
target="${arch}-unknown-linux-musl"
for program in cargo rustup musl-gcc make gcc flex bison python3; do command -v "$program" >/dev/null || { echo "Missing developer dependency: $program" >&2; exit 1; }; done
rustup target add "$target"
build="$directory/.build/$arch"
mkdir -p "$build" "$directory/dist"
python3 - "$build" <<'PY'
import hashlib, pathlib, sys, tarfile, urllib.request
p = pathlib.Path(sys.argv[1]); archive = p/'libpcap-1.10.5.tar.gz'
if not archive.exists(): urllib.request.urlretrieve('https://www.tcpdump.org/release/libpcap-1.10.5.tar.gz', archive)
assert hashlib.sha256(archive.read_bytes()).hexdigest() == '37ced90a19a302a7f32e458224a00c365c117905c2cd35ac544b6880a81488f0', 'libpcap checksum mismatch'
if not (p/'libpcap-1.10.5').exists():
    with tarfile.open(archive) as t: t.extractall(p, filter='data')
PY
mkdir -p "$build/kernel-headers"
for name in linux asm-generic; do ln -sfn "/usr/include/$name" "$build/kernel-headers/$name"; done
ln -sfn "/usr/include/$(gcc -dumpmachine)/asm" "$build/kernel-headers/asm"
jobs=$(python3 - <<'PY'
import os
mem = next(int(l.split()[1]) for l in open('/proc/meminfo') if l.startswith('MemAvailable:'))
print(max(1, min(4, os.cpu_count() or 1, mem//524288)))
PY
)
(
    cd "$build/libpcap-1.10.5"
    CC=musl-gcc CFLAGS="-O2 -isystem $build/kernel-headers" ./configure --prefix="$build/pcap" --disable-shared --disable-dbus --without-libnl --disable-bluetooth --disable-usb --without-dag --without-snf --without-dpdk
    make -j"$jobs"
    make install
)
export LIBPCAP_LIBDIR="$build/pcap/lib" LIBPCAP_VER=1.10.5
RUSTC="$(rustup which rustc)"
export RUSTC
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
cargo build --release --locked --target "$target" -j"$jobs"
python3 tools/package.py "$target" "$build/libpcap-1.10.5/LICENSE"
