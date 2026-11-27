#!/usr/bin/env python3
"""Build and release-sign copy-partitions-houji.zip for Xiaomi 14 (houji / houjiin).

The generated Recovery-flashable ZIP contains zero Xiaomi firmware blobs: it holds a
pure POSIX /system/bin/sh META-INF/com/google/android/update-binary script that mirrors
the active slot's 28 non-OS slotted firmware / boot-LUN partitions to the inactive slot
before A/B sideloading a bring-your-own-firmware ROM.
"""

import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

UPDATE_BINARY = """#!/system/bin/sh
# Sync the active slot's 28 non-OS slotted firmware partitions to the inactive slot
# on Xiaomi 14 (houji / houjiin) before sideloading a firmware-free YAAP OTA.
# Leaves the 7 OS boot partitions, super, userdata, persist, metadata, misc,
# and RF calibration (modemst1/modemst2/fsg/fsc) untouched.

set -u

OUTFD="${2:-}"

ui_print() {
    if [ -n "$OUTFD" ]; then
        printf 'ui_print %s\\n' "$1" >&"$OUTFD"
    else
        printf '%s\\n' "$1"
    fi
}

die() {
    ui_print "ERROR: $1"
    exit 1
}

set_progress() {
    if [ -n "$OUTFD" ]; then
        printf 'set_progress %s\\n' "$1" >&"$OUTFD"
    fi
}

dev=$(getprop ro.product.device)
sku=$(getprop ro.boot.hardware.sku)
case "$dev" in
    houji|houjiin) ;;
    *) die "Unsupported device '$dev' (expected houji or houjiin)" ;;
esac
case "$sku" in
    ""|houji|houjiin) ;;
    *) die "Unsupported hardware SKU '$sku' (expected houji or houjiin)" ;;
esac

slot=$(getprop ro.boot.slot_suffix)
case "$slot" in
    _a) target="_b" ;;
    _b) target="_a" ;;
    *) die "Unsupported active slot suffix '$slot'" ;;
esac

if [ -d /dev/block/bootdevice/by-name ]; then
    BY_NAME=/dev/block/bootdevice/by-name
elif [ -d /dev/block/by-name ]; then
    BY_NAME=/dev/block/by-name
else
    die "Missing /dev/block/{bootdevice/,}by-name directory"
fi

part_kib() {
    local target_name="$1" maj min blocks name rest
    while read -r maj min blocks name rest; do
        if [ -n "$blocks" ] && [ "$name" = "$target_name" ]; then
            printf '%s\\n' "$blocks"
            return 0
        fi
    done < /proc/partitions
    return 1
}

# Exact 28 non-OS slotted partitions (boot-critical xbl and abl ordered last).
PARTITIONS="
aop
aop_config
bluetooth
cpucp
cpucp_dtb
devcfg
dsp
featenabler
hyp
imagefv
keymaster
modem
modemfirmware
multiimgoem
multiimgqti
qupfw
qweslicstore
shrm
spuservice
tz
uefi
uefisecapp
vm-bootsys
xbl_config
xbl_config_nof
xbl_ramdump
xbl
abl
"

ui_print "Validating non-OS firmware partition pairs ($slot -> $target)..."
total=0
for p in $PARTITIONS; do
    total=$((total + 1))
    src="$BY_NAME/${p}${slot}"
    dst="$BY_NAME/${p}${target}"
    [ -e "$src" ] || die "Missing source symlink: $src"
    [ -e "$dst" ] || die "Missing target symlink: $dst"
    rsrc=$(readlink -f "$src") || die "readlink failed for $src"
    rdst=$(readlink -f "$dst") || die "readlink failed for $dst"
    [ -b "$rsrc" ] || die "Source is not a block device: $rsrc"
    [ -b "$rdst" ] || die "Target is not a block device: $rdst"
    [ "$rsrc" != "$rdst" ] || die "Source and target resolve to same block node: $rsrc"
    bsrc=$(basename "$rsrc")
    bdst=$(basename "$rdst")
    ksrc=$(part_kib "$bsrc") || die "Missing $bsrc in /proc/partitions"
    kdst=$(part_kib "$bdst") || die "Missing $bdst in /proc/partitions"
    [ "$ksrc" = "$kdst" ] || die "Size mismatch on $p: ${bsrc}=${ksrc}KiB != ${bdst}=${kdst}KiB"
done

if [ -n "$OUTFD" ]; then
    printf 'progress 1.0 0\\n' >&"$OUTFD"
fi
set_progress "0.00"

idx=0
copied=0
skipped=0
for p in $PARTITIONS; do
    idx=$((idx + 1))
    src=$(readlink -f "$BY_NAME/${p}${slot}")
    dst=$(readlink -f "$BY_NAME/${p}${target}")
    if cmp -s "$src" "$dst"; then
        skipped=$((skipped + 1))
        ui_print "[$idx/$total] ${p}${target}: already identical (skipped)"
    else
        ui_print "[$idx/$total] Copying ${p}${slot} -> ${p}${target}..."
        dd if="$src" of="$dst" bs=1048576 conv=fsync status=none || die "dd failed on $p ($src -> $dst)"
        cmp -s "$src" "$dst" || die "Readback cmp failed after copying $p ($src -> $dst)"
        copied=$((copied + 1))
    fi
    pct=$(( (idx * 100) / total ))
    if [ "$pct" -eq 100 ]; then
        set_progress "1.00"
    else
        set_progress "0.$(printf '%02d' "$pct")"
    fi
done

sync
ui_print "Done ($slot -> $target): $copied copied, $skipped already matched."
exit 0
"""

UPDATER_SCRIPT = "# Dummy file; update-binary is a shell script.\n"
FIXED_ZIP_DT = (1980, 1, 1, 0, 0, 0)


def write_member(archive: zipfile.ZipFile, name: str, data: str, mode: int) -> None:
    info = zipfile.ZipInfo(filename=name, date_time=FIXED_ZIP_DT)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (0o100000 | mode) << 16
    archive.writestr(info, data.encode("utf-8"))


def build_and_sign(args: argparse.Namespace) -> None:
    cert = args.keys_dir / "releasekey.x509.pem"
    pk8 = args.keys_dir / "releasekey.pk8"
    signapk = args.host_out / "framework/signapk.jar"
    lib64 = args.host_out / "lib64"
    checker = args.host_out / "bin/check_ota_package_signature"
    for req in (cert, pk8, signapk, lib64, checker, args.java):
        if not req.exists():
            raise FileNotFoundError(f"Missing required build/signing asset: {req}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="copy-partitions-") as tmp:
        unsigned = Path(tmp) / "unsigned.zip"
        signed = Path(tmp) / "signed.zip"
        with zipfile.ZipFile(unsigned, "w") as archive:
            write_member(archive, "META-INF/com/google/android/update-binary", UPDATE_BINARY, 0o755)
            write_member(archive, "META-INF/com/google/android/updater-script", UPDATER_SCRIPT, 0o644)

        subprocess.run(
            [
                str(args.java), "-Xmx2048m",
                f"-Djava.library.path={lib64}",
                "-jar", str(signapk), "-w",
                str(cert), str(pk8),
                str(unsigned), str(signed),
            ],
            check=True,
        )
        env = {"LD_LIBRARY_PATH": str(lib64)}
        subprocess.run([str(checker), str(cert), str(signed)], env=env, check=True)
        shutil.move(signed, args.output)
        args.output.chmod(0o644)


def main() -> None:
    repo = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keys-dir", type=Path, default=repo.parent / "keys")
    parser.add_argument("--host-out", type=Path, default=repo / "yaap/out/host/linux-x86")
    parser.add_argument("--java", type=Path, default=repo / "yaap/prebuilts/jdk/jdk21/linux-x86/bin/java")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build_and_sign(args)
    print(f"Signed and verified {args.output} ({args.output.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
