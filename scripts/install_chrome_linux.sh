#!/usr/bin/env bash
# Install Chrome for Testing + matching chromedriver for Render native builds.
# Selenium Manager can also fetch drivers; this ensures a browser binary exists.
set -euo pipefail

DEST="${CHROME_INSTALL_DIR:-${HOME}/.cache/vantacrawl-chrome}"
mkdir -p "$DEST"

if [[ -x "$DEST/chrome/chrome" ]] || [[ -x "$DEST/chrome-linux64/chrome" ]]; then
  echo "Chrome already present under $DEST"
else
  echo "Downloading Chrome for Testing (linux64)…"
  # Pin via last-known-good stable endpoint
  JSON_URL="https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"
  TMP="$(mktemp -d)"
  curl -fsSL "$JSON_URL" -o "$TMP/versions.json"
  python3 - <<'PY' "$TMP/versions.json" "$TMP"
import json, sys, urllib.request
data = json.load(open(sys.argv[1], encoding="utf-8"))
stable = data["channels"]["Stable"]
ver = stable["version"]
chrome_url = None
driver_url = None
for item in stable["downloads"].get("chrome", []):
    if item.get("platform") == "linux64":
        chrome_url = item["url"]
for item in stable["downloads"].get("chromedriver", []):
    if item.get("platform") == "linux64":
        driver_url = item["url"]
if not chrome_url or not driver_url:
    raise SystemExit("Could not find linux64 chrome/chromedriver download URLs")
open(sys.argv[2] + "/chrome.url", "w").write(chrome_url)
open(sys.argv[2] + "/driver.url", "w").write(driver_url)
open(sys.argv[2] + "/version.txt", "w").write(ver)
print("Chrome for Testing", ver)
PY
  curl -fsSL "$(cat "$TMP/chrome.url")" -o "$TMP/chrome.zip"
  curl -fsSL "$(cat "$TMP/driver.url")" -o "$TMP/driver.zip"
  unzip -q -o "$TMP/chrome.zip" -d "$DEST"
  unzip -q -o "$TMP/driver.zip" -d "$DEST"
  rm -rf "$TMP"
fi

# Normalize paths
if [[ -d "$DEST/chrome-linux64" ]]; then
  CHROME_BIN_PATH="$DEST/chrome-linux64/chrome"
elif [[ -d "$DEST/chrome" ]]; then
  CHROME_BIN_PATH="$DEST/chrome/chrome"
else
  CHROME_BIN_PATH="$(find "$DEST" -type f -name chrome | head -n 1)"
fi
DRIVER_BIN_PATH="$(find "$DEST" -type f -name chromedriver | head -n 1)"

chmod +x "$CHROME_BIN_PATH" "$DRIVER_BIN_PATH" || true

# Export for subsequent build/start steps when this script is sourced
export CHROME_BIN="${CHROME_BIN:-$CHROME_BIN_PATH}"
export CHROMEDRIVER_PATH="${CHROMEDRIVER_PATH:-$DRIVER_BIN_PATH}"
export PATH="$(dirname "$DRIVER_BIN_PATH"):$PATH"

mkdir -p "$DEST"
printf '%s\n' "$CHROME_BIN" > "$DEST/chrome_bin.path"
printf '%s\n' "$CHROMEDRIVER_PATH" > "$DEST/chromedriver.path"

echo "CHROME_BIN=$CHROME_BIN"
echo "CHROMEDRIVER_PATH=$CHROMEDRIVER_PATH"
