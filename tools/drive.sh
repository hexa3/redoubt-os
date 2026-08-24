#!/usr/bin/env bash
# Drive an interactive redoubt session headlessly.
#
# Boots the disk image in QEMU (Docker) with a monitor TCP port, waits for
# boot, types a scripted sequence of lines through the emulated PS/2
# keyboard (monitor `sendkey`), then dumps serial output + screenshots.
#
# Usage: ./tools/drive.sh [wait_secs] [line1] [line2] ...
set -euo pipefail
cd "$(dirname "$0")/.."

WAIT="${1:-10}"; shift || true
MON_PORT="${REDOUBT_MON_PORT:-4444}"
IMAGE="${REDOUBT_IMAGE:-redoubt-bios.img}"
VOLUME="${REDOUBT_VOLUME:-store.img}"
SERIAL_LOG=".drive-serial.log"
SHOT_PREFIX=".drive-screen"

if [ ! -f "$IMAGE" ]; then
    echo "image not found: $IMAGE" >&2
    exit 2
fi

# Reboot scenarios must let QEMU reset instead of exiting.
REBOOT_FLAG="-no-reboot"
if [[ "${REDOUBT_REBOOT_OK:-0}" = "1" ]]; then
    REBOOT_FLAG=""
fi

docker rm -f redoubt-drive >/dev/null 2>&1 || true
rm -f "$SERIAL_LOG" "$SHOT_PREFIX".ppm "$SHOT_PREFIX".png

DRIVE_ARGS=(-drive "format=raw,file=$IMAGE")
if [ -f "$VOLUME" ]; then
    # persistent volume rides the secondary IDE master; the kernel's ATA
    # driver enumerates it as disk 1 and storaged mounts it via caps
    DRIVE_ARGS+=(-drive "format=raw,file=$VOLUME,if=none,id=d1" \
                 "-device" "ide-hd,drive=d1,bus=ide.1")
fi

docker run -d --rm --name redoubt-drive \
    -u "$(id -u):$(id -g)" -e HOME=/tmp \
    -v "$(pwd):/work" -w /work \
    -p "${MON_PORT}:${MON_PORT}" \
    redoubt-qemu \
    qemu-system-x86_64 \
        "${DRIVE_ARGS[@]}" \
        -display none \
        -serial file:/work/$SERIAL_LOG \
        -monitor telnet:0.0.0.0:${MON_PORT},server,nowait \
        $REBOOT_FLAG >/dev/null

cleanup() { docker rm -f redoubt-drive >/dev/null 2>&1 || true; }
trap cleanup EXIT

sleep "$WAIT"

mon() {
    exec 3<>/dev/tcp/127.0.0.1/${MON_PORT}
    printf '%s\n' "$1" >&3
    sleep 0.15
    exec 3<&- 3>&-
}

for line in "$@"; do
    # map characters to PS/2 sendkey names and type them one by one
    while read -r k; do
        [ -n "$k" ] || continue
        mon "sendkey $k"
        sleep 0.06
    done < <(python3 - "$line" <<'PYEOF'
import sys
mapping = {' ': 'spc', '-': 'minus', '=': 'equal', ',': 'comma', '.': 'dot',
           '/': 'slash', ';': 'semicolon', "'": 'apostrophe',
           '\\': 'backslash', '`': 'grave_accent'}
out = []
for c in sys.argv[1]:
    if c.isalnum():
        out.append(c if not c.isupper() else 'shift-' + c.lower())
    elif c in mapping:
        out.append(mapping[c])
print('\n'.join(out))
PYEOF
)
    mon "sendkey ret"
    sleep 1.5   # let the command run before the next prompt
done

# let a reboot scenario settle before capturing
sleep "${REDOUBT_POST_WAIT:-2}"

# capture final state: screenshot via monitor screendump
exec 3<>/dev/tcp/127.0.0.1/${MON_PORT}
read -t 1 -u 3 banner || true
printf 'screendump %s.ppm\n' "$SHOT_PREFIX" >&3
sleep 1
printf 'quit\n' >&3
exec 3<&- 3>&-
sleep 1

python3 - "$SHOT_PREFIX.ppm" "${SHOT_PREFIX}.png" <<'PYEOF'
import sys, zlib, struct
with open(sys.argv[1],'rb') as f: data = f.read()
assert data[:2] == b'P6'
pos, fields = 2, []
while len(fields) < 3:
    while data[pos:pos+1].isspace(): pos += 1
    if data[pos:pos+1] == b'#':
        while data[pos:pos+1] != b'\n': pos += 1
        continue
    start = pos
    while not data[pos:pos+1].isspace(): pos += 1
    fields.append(int(data[start:pos]))
pos += 1
w,h,_ = fields
pix = data[pos:pos+w*h*3]
def chunk(t,d):
    c=t+d; return struct.pack('>I',len(d))+c+struct.pack('>I',zlib.crc32(c))
raw = b''.join(b'\x00'+pix[y*w*3:(y+1)*w*3] for y in range(h))
png = b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',w,h,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(raw))+chunk(b'IEND',b'')
open(sys.argv[2],'wb').write(png)
print(f"saved {sys.argv[2]} ({w}x{h})")
PYEOF

echo "---- serial log ----"
cat "$SERIAL_LOG"
