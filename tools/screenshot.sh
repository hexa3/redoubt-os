#!/usr/bin/env bash
# Boot redoubt in QEMU (Docker) with a monitor TCP port, take a screenshot,
# and print it as PNG at the given path. Usage: ./tools/screenshot.sh [out.png] [wait_secs]
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${1:-/tmp/opencode/redoubt-screen.png}"
WAIT="${2:-8}"
MON_PORT=4444

docker rm -f redoubt-shot >/dev/null 2>&1 || true
sleep 1

docker run -d --rm --name redoubt-shot \
    -u "$(id -u):$(id -g)" -e HOME=/tmp \
    -v "$(pwd):/work" -w /work \
    -p "${MON_PORT}:${MON_PORT}" \
    redoubt-qemu \
    qemu-system-x86_64 \
        -drive format=raw,file=redoubt-bios.img \
        -display none \
        -serial file:/work/.redoubt-serial.log \
        -monitor telnet:0.0.0.0:${MON_PORT},server,nowait \
        -no-reboot >/dev/null

sleep "$WAIT"

# talk to the QEMU monitor over bash's /dev/tcp
exec 3<>/dev/tcp/127.0.0.1/${MON_PORT}
read -t 1 -u 3 banner || true
printf 'screendump /work/.redoubt-screen.ppm\n' >&3
sleep 1
printf 'quit\n' >&3
exec 3<&- 3>&-
sleep 1

python3 - "$OUT" <<'PYEOF'
import sys, zlib, struct

ppm_path = '.redoubt-screen.ppm'
with open(ppm_path,'rb') as f:
    data = f.read()

# parse P6 header (skip whitespace/comments)
assert data[:2] == b'P6', data[:10]
pos, fields = 2, []
while len(fields) < 3:
    while pos < len(data) and data[pos:pos+1].isspace(): pos += 1
    if data[pos:pos+1] == b'#':
        while data[pos:pos+1] != b'\n': pos += 1
        continue
    start = pos
    while not data[pos:pos+1].isspace(): pos += 1
    fields.append(int(data[start:pos]))
pos += 1
w, h, maxval = fields
pix = data[pos:pos+w*h*3]
assert len(pix) == w*h*3, (len(pix), w*h*3)

def chunk(t, d):
    c = t + d
    return struct.pack('>I', len(d)) + c + struct.pack('>I', zlib.crc32(c))

raw = b''.join(b'\x00' + pix[y*w*3:(y+1)*w*3] for y in range(h))
png = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w,h,8,2,0,0,0)) + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b'')
open(sys.argv[1],'wb').write(png)
print(f"saved {sys.argv[1]} ({w}x{h})")
PYEOF

docker rm -f redoubt-shot >/dev/null 2>&1 || true
