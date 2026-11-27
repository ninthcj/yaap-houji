#!/usr/bin/env python3
"""Validate staged houji vendor and microG inputs; emit source evidence as JSON."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

ROM = "OS3.0.307.0.WNCCNXM"
LFS_MARKER = b"version https://git-lfs.github.com/spec/v1"
MICROG_SIGNER = "9bd06727e62796c0130eb6dab39b73157451582cbd138e86c468acc395d14165"
MODULE_TREES = ("vendor_ramdisk", "vendor_dlkm", "system_dlkm")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True, stderr=subprocess.PIPE)


def digest(path, algorithm="sha256"):
    with path.open("rb") as source:
        return hashlib.file_digest(source, algorithm).hexdigest()


def files_under(root):
    require(root.is_dir(), f"Missing tree: {root}")
    for folder, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d != ".git")
        for name in sorted(names):
            path = Path(folder) / name
            if name != ".git" and not path.is_symlink() and path.is_file():
                yield path


def header(path, count):
    with path.open("rb") as source:
        return source.read(count)


def evidence(path, kind, sha256=None):
    return {"format": kind, "bytes": path.stat().st_size, "sha256": sha256 or digest(path)}


def check_vendor(root):
    paths = list(files_under(root))
    require(paths, f"Empty tree: {root}")
    pointers = [str(p.relative_to(root)) for p in paths if header(p, len(LFS_MARKER)) == LFS_MARKER]
    require(not pointers, f"{root}: unhydrated Git LFS pointers: {', '.join(pointers)}")
    objects = {}
    inventory = json.loads(command("git", "lfs", "ls-files", "--json", cwd=root))["files"]
    for row in () if inventory is None else inventory:
        name = row["name"]
        path = root / name
        require(path.is_file() and not path.is_symlink() and row["oid_type"] == "sha256",
                f"{path}: not a regular SHA-256-tracked LFS file")
        require(path.stat().st_size == row["size"] and digest(path) == row["oid"],
                f"{path}: content differs from pinned LFS object {row['oid']}")
        objects[name] = row["oid"]
    return objects


def read_radio_inventory(device, vendor):
    items = {}
    for line in (device / "proprietary-firmware.txt").read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = re.fullmatch(r"([^:/]+):([a-z0-9_]+\.img);AB\|([0-9a-f]{40})", line)
        require(match, f"Unrecognized firmware declaration: {line!r}")
        stock_name, target, sha1 = match.groups()
        require(target not in items, f"Duplicate firmware declaration: {target}")
        items[target] = (stock_name, sha1)
    wired = re.findall(r"\$\(call add-radio-file-sha1-checked,radio/([^,]+),([0-9a-f]{40})\)",
                       (vendor / "Android.mk").read_text())
    ab_lines = (vendor / "BoardConfigVendor.mk").read_text().splitlines()
    start = ab_lines.index("AB_OTA_PARTITIONS += \\")
    ab_names = []
    for line in ab_lines[start + 1:]:
        ab_names.append(line.removesuffix("\\").strip())
        if not line.endswith("\\"):
            break
    require(len(items) == 21 and len(wired) == len(items) == len(ab_names)
            and dict(wired) == {name: row[1] for name, row in items.items()}
            and {name + ".img" for name in ab_names} == set(items)
            and {p.name for p in (vendor / "radio").glob("*.img")} == set(items),
            "The 21 firmware entries, radio files, SHA-1 checks, and A/B partitions do not agree")
    return items


def firmware_format(path):
    data = header(path, 2048)
    if path.name == "dsp.img":
        require(data[0x438:0x43a] == b"\x53\xef" and data[0x478:0x488].split(b"\0")[0] == b"dsp",
                f"{path}: missing ext4 superblock or dsp volume label")
        blocks, = struct.unpack_from("<I", data, 0x404)
        logblock, = struct.unpack_from("<I", data, 0x418)
        require(logblock <= 6 and blocks * (1024 << logblock) == path.stat().st_size,
                f"{path}: ext4 block count does not match file size")
        return "ext4"
    if path.name in {"bluetooth.img", "modem.img", "modemfirmware.img"}:
        sector, cluster, reserved, fats, entries = struct.unpack_from("<HBHBH", data, 11)
        fat_size, = struct.unpack_from("<H", data, 22)
        first_data_sector = reserved + fats * fat_size + (entries * 32 + sector - 1) // max(sector, 1)
        # Xiaomi ships these FAT images without the trailing unused partition space.
        require(data[0] in (0xEB, 0xE9) and data[510:512] == b"\x55\xaa" and data[54:62] == b"FAT16   "
                and sector in (512, 1024, 2048, 4096) and cluster and not cluster & (cluster - 1)
                and reserved and fats and entries and fat_size
                and first_data_sector * sector < path.stat().st_size,
                f"{path}: invalid FAT16 boot sector or truncated tables")
        return "FAT16"
    require(data.startswith(b"\x7fELF") and data[4] in (1, 2) and data[5:7] == b"\x01\x01",
            f"{path}: invalid little-endian ELF identification")
    return f"ELF{32 if data[4] == 1 else 64}"


def check_radio(device, vendor, objects):
    entries = {}
    for name, (stock_name, sha1) in sorted(read_radio_inventory(device, vendor).items()):
        path = vendor / "radio" / name
        sha256 = objects.get("radio/" + name)
        require(sha256 and digest(path, "sha1") == sha1,
                f"{path}: missing pinned LFS entry or extracted firmware SHA-1 mismatch")
        entries[name] = evidence(path, firmware_format(path), sha256) | {"stock_name": stock_name, "sha1": sha1}
    return entries


def check_kernel(root):
    files = {p.relative_to(root).as_posix(): p for p in files_under(root)}
    hashes = dict(line.split("  ", 1)[::-1] for line in files.pop("SHA256SUMS").read_text().splitlines())
    require(hashes.keys() == files.keys(), "Stock checksum list does not cover exactly the stock bundle")
    for name, path in files.items():
        require(digest(path) == hashes[name], f"{path}: stock bundle SHA-256 mismatch")
    provenance = json.loads(files["provenance.json"].read_bytes())
    require(provenance["rom"] == ROM, "Stock kernel ROM version mismatch")
    image = files["Image"]
    boot = header(image, 64)
    image_size, = struct.unpack_from("<Q", boot, 0x10)
    require(boot[:2] == b"MZ" and boot[0x38:0x3c] == b"ARM\x64" and image_size >= image.stat().st_size,
            f"{image}: invalid ARM64 Image header")
    dtbo = files["dtbo.img"]
    magic, total, size, entry_size, count, offset, _, _ = struct.unpack(">8I", header(dtbo, 32))
    require(magic == 0xD7B7AB1E and total == dtbo.stat().st_size and size == 32 and entry_size == 32
            and count and size <= offset and offset + count * entry_size < total,
            f"{dtbo}: invalid DTBO header or table")
    dtb = files["dtb/stock.dtb"]
    with dtb.open("rb") as source:
        offset = 0
        count = 0
        while offset < dtb.stat().st_size:
            magic, total = struct.unpack(">II", source.read(8))
            require(magic == 0xD00DFEED and 40 <= total <= dtb.stat().st_size - offset,
                    f"{dtb}: invalid flattened device tree at offset {offset}")
            offset += total
            count += 1
            source.seek(offset)
    require(count == provenance["dtb_count"], f"{dtb}: wrong number of device trees")
    images = {name: evidence(files[name], kind, hashes[name]) for name, kind in
              (("Image", "ARM64 Image"), ("dtbo.img", "DTBO"), ("dtb/stock.dtb", "concatenated FDT"))}
    module_counts = dict.fromkeys(MODULE_TREES, 0)
    for name, path in files.items():
        if path.suffix != ".ko":
            continue
        elf = header(path, 64)
        require(len(elf) == 64 and elf[:7] == b"\x7fELF\x02\x01\x01" and elf[16:20] == b"\x01\x00\xb7\x00",
                f"{path}: invalid AArch64 relocatable ELF module")
        module_counts[name.split("/", 1)[0]] += 1
        images[name] = evidence(path, "AArch64 ELF64 relocatable", hashes[name])
    require(module_counts == provenance["module_counts"], "Kernel module tree counts differ from stock provenance")
    return {"provenance": provenance, "images": images}


def check_apks(root):
    result = {}
    for name in ("GmsCore", "GsfProxy", "FakeStore", "FDroid"):
        apk = root / name / f"{name}.apk"
        require(header(apk, 4) == b"PK\x03\x04", f"{apk}: expected ZIP/APK magic")
        verification = command("apksigner", "verify", "--verbose", "--print-certs", str(apk))
        signers = re.findall(r"^Signer #\d+ certificate SHA-256 digest: ([0-9a-f]{64})$", verification, re.M)
        require(len(signers) == 1, f"{apk}: expected exactly one verified signer")
        if name != "FDroid":
            require(signers == [MICROG_SIGNER], f"{apk}: signer does not match YAAP microG certificate pin")
        result[name] = evidence(apk, "APK") | {"signer_sha256": signers[0]}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Root of the staged checkouts or repo workspace")
    args = parser.parse_args()
    root = args.root.resolve()
    vendor = root / "vendor/xiaomi/houji"
    microg = root / "vendor/microg"
    repos = ("device/xiaomi/houji", "device/xiaomi/sm8650-common", "vendor/xiaomi/houji",
             "vendor/xiaomi/sm8650-common", "vendor/microg", "vendor/yaap", "hardware/xiaomi")
    shas = {p: command("git", "rev-parse", "HEAD", cwd=root / p).strip() for p in repos}
    lfs = {p: check_vendor(root / p) for p in repos if p.startswith("vendor/xiaomi/") or p == "vendor/microg"}
    report = {"baseline": ROM, "repository_commits": shas, "lfs_objects": lfs,
              "radio": check_radio(root / "device/xiaomi/houji", vendor, lfs["vendor/xiaomi/houji"]),
              "stock_kernel": check_kernel(vendor / "kernel/stock"), "apk": check_apks(microg)}
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    print()


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, ValueError, struct.error, subprocess.CalledProcessError) as error:
        print(f"Source verification failed: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr, error.stdout, file=sys.stderr)
        sys.exit(1)
