#!/usr/bin/env bash
# Apply the houji YAAP 17 patch series onto a freshly synced `yaap` workspace.
# Run AFTER `repo sync` + LFS checkout + `verify-preflight.py`.
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
YAAP_DIR="${1:-$ROOT/yaap}"

[[ -d "$YAAP_DIR/.repo" ]] || { echo "Usage: $0 [/path/to/yaap]" >&2; exit 1; }

declare -A BASES=(
    ["device/xiaomi/houji"]="9236d9e936771ee9587a6569de6a00d340ec5781"
    ["device/xiaomi/sm8650-common"]="db264b4226242d40477154d93f0fbb9a7cc5a7cc"
    ["vendor/xiaomi/houji"]="e7f91c48d3096d423f25d5b036361609d8cfa235"
    ["hardware/xiaomi"]="66389495bf9a81a0e714b4153247f265dedb43a7"
    ["kernel/xiaomi/houji"]="0c3d559bcd85c64dae9c9c9687abbe5347fff3ad"
    ["vendor/yaap"]="7ac9801a850fe3db9e08cadf23217a1e83495deb"
    ["vendor/microg"]="29c3c3249daabd2a727a7fa4aedcd4cd87bc3879"
    ["bootable/recovery"]="2bc75fbed39574986be294b510ee07ed269b8176"
)

for proj in \
    "device/xiaomi/houji" \
    "device/xiaomi/sm8650-common" \
    "vendor/xiaomi/houji" \
    "hardware/xiaomi" \
    "kernel/xiaomi/houji" \
    "vendor/yaap" \
    "vendor/microg" \
    "bootable/recovery"; do
    base="${BASES[$proj]}"
    slug="${proj//\//_}"
    repo_path="$YAAP_DIR/$proj"
    patch_dir="$ROOT/patches/$slug"

    echo "==> $proj (base ${base:0:12})"
    git -C "$repo_path" checkout -B yaap-17 "$base"
    git -C "$repo_path" am --3way "$patch_dir"/*.patch
done

echo "All patch series applied cleanly onto branch 'yaap-17'."
