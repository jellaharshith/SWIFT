#!/usr/bin/env bash
# Record SWIFT TUI demo GIF for README.
# Output: docs/demo.gif  (via asciinema → agg → gifsicle)
#
# Prerequisites:
#   brew install asciinema agg gifsicle
#   docker run -d -p 3000:3000 bkimminich/juice-shop
#   export ANTHROPIC_API_KEY=sk-ant-...
#   cp roe.example.yaml roe.yaml  # ensure juice-shop target is authorised

set -euo pipefail

CAST_FILE="$(mktemp /tmp/swift_demo.XXXXXX.cast)"
GIF_OUT="docs/demo.gif"
TARGET="${TARGET:-http://localhost:3000}"
ROE="${ROE:-roe.yaml}"

check_deps() {
  for cmd in asciinema agg gifsicle swiftsec docker; do
    if ! command -v "$cmd" &>/dev/null; then
      echo "[!] Missing: $cmd"
      case "$cmd" in
        asciinema) echo "    brew install asciinema" ;;
        agg)       echo "    brew install agg" ;;
        gifsicle)  echo "    brew install gifsicle" ;;
        swiftsec)  echo "    pip install 'swiftsec[ctf]'" ;;
        docker)    echo "    https://docs.docker.com/get-docker/" ;;
      esac
      exit 1
    fi
  done
}

wait_for_juice_shop() {
  echo "[*] Waiting for Juice Shop at $TARGET ..."
  for i in $(seq 1 30); do
    if curl -sf "$TARGET" -o /dev/null; then
      echo "[+] Juice Shop reachable"
      return 0
    fi
    sleep 2
  done
  echo "[!] Juice Shop not reachable at $TARGET after 60s"
  echo "    docker run -d -p 3000:3000 bkimminich/juice-shop"
  exit 1
}

record() {
  echo "[*] Recording to $CAST_FILE ..."
  asciinema rec "$CAST_FILE" \
    --cols 130 --rows 35 \
    --title "SWIFT v7 — Live TUI scan on Juice Shop" \
    --command "swiftsec web-scan --target $TARGET --roe $ROE --live"
}

convert_to_gif() {
  mkdir -p docs
  echo "[*] Converting cast → GIF ..."
  agg "$CAST_FILE" "$GIF_OUT.raw.gif" \
    --font-size 14 \
    --theme monokai
  gifsicle --optimize=3 --colors 128 "$GIF_OUT.raw.gif" -o "$GIF_OUT"
  rm -f "$GIF_OUT.raw.gif" "$CAST_FILE"
  echo "[+] Saved: $GIF_OUT"
}

check_deps
wait_for_juice_shop
record
convert_to_gif

echo ""
echo "Next: git add $GIF_OUT && git commit -m 'docs: add TUI demo GIF'"
