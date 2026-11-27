#!/usr/bin/env python3
"""Publish the verified houji release from audited build outputs and SDK tools."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import zipfile

AUDIT_PROFILE = "byof-houji-houjiin-android17"
DEVICE_ALIASES = ["houji", "houjiin"]
CORE_PARTITIONS = ("boot", "init_boot", "vendor_boot", "dtbo", "vbmeta", "vbmeta_system",
                   "recovery", "odm", "system", "system_ext", "product", "vendor", "vendor_dlkm", "system_dlkm")
REQUIRED_CHECKS = (
    "ota_signature_matches_release_certificate",
    "ota_metadata_is_full_ab_without_pre_build",
    "ota_metadata_device_aliases_are_exactly_houji_and_houjiin_pipe_separated",
    "payload_partitions_are_exactly_the_14_core_partitions",
    "target_files_meta_ab_partitions_are_exactly_the_14_core_partitions",
    "no_radio_items_in_target_files",
    "system_bin_init_is_arm64_elf_with_houji_houjiin_sku_normalization_strings",
    "root_init_links_to_system_bin_init",
    "target_files_system_bin_init_equals_payload",
    "esim_openeuicc_apk_installed_once_at_expected_path",
    "esim_openeuicc_privapp_allowlist_grants_euicc_permissions",
    "esim_openeuicc_app_links_to_arm64_system_ext_lpac_library",
    "esim_xiaomi_esim_switcher_apk_installed_once_at_expected_path",
    "esim_xiaomi_switcher_privapp_allowlist",
    "esim_telephony_euicc_feature_installed",
    "esim_no_google_euicc_prebuilt",
    "esim_framework_overlay_declares_euicc_capabilities_and_two_physical_slots",
    "qti_ims_and_extphone_dex_linkage",
    "microg_aperture_esim_apk_jni_and_config_bytes_in_payload_filesystems",
    "boot_kernel_equals_retained_stock_image",
    "gki_kmi_symbol_crc_parity",
    "gki_drm_clone_compat",
    "houji_kernel_module_purification",
    "payload_recovery_contains_qti_boot_control_hal",
    "vendor_contains_qti_boot_control_hal",
    "xiaomi_fastcharge_sepolicy_labels_and_rules",
    "camera_sphal_odm_file_contexts",
    "atfwd_seccomp_allows_lseek",
    "readonly_partitions_use_erofs",
    "userspace_dead_daemons_pruned",
    "flagship_hardware_and_ux_unlocks",
    "bootstrap_super_empty_header_and_geometry",
    "avb_vbmeta",
    "avb_vbmeta_system",
    "apk_set_signers_permissions_and_gms_free",
)
BOOTSTRAP = ("boot", "init_boot", "vendor_boot", "dtbo", "vbmeta", "vbmeta_system", "recovery", "super_empty")
SDK_FILES = ("adb", "fastboot", "NOTICE.txt", "source.properties")
SDK_ARCHIVE_SHA256 = "214548146cadb2ca3508143d8a1d4be4c59de5bb837253e3ede89ed74cf450d1"


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def copy_audited(src, dest, record):
    if not src.is_file() or src.stat().st_size != record["bytes"]:
        raise ValueError(f"{src}: missing or different size from the verified artifact")
    shutil.copyfile(src, dest)
    if sha256(dest) != record["sha256"]:
        raise ValueError(f"{src}: different digest from the verified artifact")


def publish(args):
    report = json.loads(args.verification.read_text())
    checks = report["checks"]
    by_name = {c["check"]: c for c in checks}
    provenance = report.get("retained_stock_provenance", {})
    if (report.get("audit") != AUDIT_PROFILE or report["status"] != "pass" or not checks
            or report["failed_checks"] or any(c["gating"] and not c["ok"] for c in checks)
            or not all(by_name.get(name, {}).get("ok") for name in REQUIRED_CHECKS)
            or report["artifacts"].get("device_aliases") != DEVICE_ALIASES
            or report["artifacts"].get("payload_partitions") != sorted(CORE_PARTITIONS)
            or provenance.get("firmware_partitions_shipped") != []):
        raise ValueError("Refusing to publish a failed/incomplete BYOF release audit")
    artifacts = report["artifacts"]
    ota = artifacts["ota"]
    images = artifacts["standalone_images"]
    if (not re.fullmatch(r"YAAP-17-[a-zA-Z0-9._-]*houji[a-zA-Z0-9._-]*\.zip", ota["file"])
            or images.keys() != set(BOOTSTRAP)):
        raise ValueError("Audit is missing the houji OTA and exact first-flash image set")
    if sha256(args.platform_tools) != SDK_ARCHIVE_SHA256:
        raise ValueError("Unexpected Android platform-tools archive SHA-256")
    if args.dist.exists() or args.dist.is_symlink():
        raise ValueError(f"Destination already exists: {args.dist}")

    staging = Path(tempfile.mkdtemp(prefix=".dist-", dir=args.dist.parent))
    try:
        (staging / "images").mkdir()
        (staging / "platform-tools").mkdir()
        copy_audited(args.product_out / ota["file"], staging / ota["file"], ota)
        for name in BOOTSTRAP:
            file = f"{name}.img"
            copy_audited(args.images_dir / file, staging / "images" / file, images[name])
        with zipfile.ZipFile(args.platform_tools) as sdk:
            for name in SDK_FILES:
                path = staging / "platform-tools" / name
                with sdk.open(f"platform-tools/{name}") as source, path.open("xb") as dest:
                    shutil.copyfileobj(source, dest)
                path.chmod(0o755 if name in ("adb", "fastboot") else 0o644)
        script = staging / "flash.sh"
        shutil.copyfile(args.flash_script, script)
        script.chmod(0o755)
        shutil.copyfile(args.verification, staging / "BUILD_VERIFICATION.json")
        sums = [(path.relative_to(staging).as_posix(), sha256(path))
                for path in sorted(staging.rglob("*")) if stat.S_ISREG(path.lstat().st_mode)]
        (staging / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name, digest in sums))
        staging.chmod(0o755)
        os.rename(staging, args.dist)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("product-out", "images-dir", "verification", "platform-tools", "flash-script", "dist"):
        parser.add_argument(f"--{argument}", type=Path, required=True)
    args = parser.parse_args()
    try:
        publish(args)
    except (KeyError, OSError, ValueError, zipfile.BadZipFile) as error:
        parser.exit(1, f"Release was not published: {error}\n")
    print(f"Verified release published locally: {args.dist}")


if __name__ == "__main__":
    main()
