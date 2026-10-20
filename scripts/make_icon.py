"""Generate a small code-native application icon (no external image dependencies)."""
import struct
import zlib
from pathlib import Path

size = 64
rows = []
for y in range(size):
    row = bytearray()
    for x in range(size):
        shield = 14 <= x <= 49 and 12 <= y <= 37 or (38 <= y <= 52 and abs(x - 31.5) <= (53 - y) * 1.2)
        inner = 19 <= x <= 44 and 18 <= y <= 36 or (37 <= y <= 46 and abs(x - 31.5) <= (47 - y) * 1.25)
        color = (141, 219, 197, 255) if shield and not inner else (16, 22, 29, 255)
        row.extend(color)
    rows.append(b'\0' + row)
def chunk(name, data):
    return struct.pack('>I', len(data)) + name + data + struct.pack('>I', zlib.crc32(name + data) & 0xffffffff)
png = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(b''.join(rows))) + chunk(b'IEND', b'')
root = Path(__file__).resolve().parent.parent / 'src-tauri' / 'icons'
root.mkdir(parents=True, exist_ok=True)
(root / 'icon.png').write_bytes(png)
(root / 'icon.ico').write_bytes(struct.pack('<HHH', 0, 1, 1) + struct.pack('<BBBBHHII', size, size, 0, 0, 1, 32, len(png), 22) + png)
