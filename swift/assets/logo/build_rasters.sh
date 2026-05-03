#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
SVG="$DIR/swift_logo.svg"

pip install cairosvg Pillow -q

for SIZE in 16 32 64 256 1024; do
  python3 -c "import cairosvg; cairosvg.svg2png(url='$SVG', write_to='$DIR/swift_logo_${SIZE}.png', output_width=${SIZE}, output_height=${SIZE})"
  echo "Generated swift_logo_${SIZE}.png"
done

python3 - <<'PY'
import os
from PIL import Image
dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in dir() else '.'
images = []
for s in [16, 32, 48]:
    src = 32 if s == 48 else s
    img = Image.open(f"{dir}/swift_logo_{src}.png").resize((s,s)).convert('RGBA')
    images.append(img)
images[0].save(f"{dir}/favicon.ico", format="ICO", sizes=[(16,16),(32,32),(48,48)], append_images=images[1:])
print("Generated favicon.ico")
PY
