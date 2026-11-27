#!/usr/bin/env python3
"""Audit a built YAAP 17 houji/houjiin BYOF release: full OTA, target-files, images, APK set, keys.

Scope: the release delivers exactly the 14 CORE_PARTITIONS (payload and target-files META/ab_partitions.txt)
and zero RADIO items; no vendor firmware is shipped or gated on. The stock kernel, dtb/dtbo, DLKM modules
and vendor blobs are retained from the stock ROM named in --source-json; their provenance is reported, not
gated on the stock ROM's region or on any OEM OTA postcondition.

Host tools required (build once from the ROM tree, then point --host-bin at the
output directory):

    cd yaap && source build/envsetup.sh && lunch yaap_houji-cp2a-user
    m check_ota_package_signature check_target_files_vintf checkvintf ota_extractor
    m simg2img aapt2 apksigner avbtool unpack_bootimg lz4 sepolicy-analyze

Run (all paths explicit; nothing is flashed, published or sent to a device):

    ./verify-release.py \\
      --rom-dir yaap \\
      --product-out yaap/out/target/product/houji \\
      --host-bin yaap/out/host/linux-x86/bin \\
      --source-json preflight/SYNCED_SOURCE_VERIFICATION.json \\
      --ota <signed full OTA>.zip \\
      --target-files <signed target-files dir or .zip> \\
      --ota-cert keys/releasekey.x509.pem \\
      --avb-key keys/avb.pem \\
      --keys-dir keys \\
      --work-dir preflight/release-audit-work \\
      --output preflight/RELEASE_VERIFICATION.json

Disk: --work-dir receives the extracted payload (every OTA partition raw), the
target-files APK/module subset when a zip is given, and one transient raw image
at a time for sparse comparison. Hashing is streamed in 1 MiB chunks, so peak
RAM is dominated by the apksigner JVMs (--jobs, default 4) and the vendor ramdisk
cpio walk (streamed from disk).
"""

import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ElementTree
import zipfile

CHUNK = 1 << 20
SPARSE_MAGIC = b"\x3a\xff\x26\xed"
MICROG_PACKAGES = {
    "FDroid": "org.fdroid.fdroid",
    "FakeStore": "com.android.vending",
    "GmsCore": "com.google.android.gms",
    "GsfProxy": "com.google.android.gsf",
}
VANADIUM_APKS = {
    "TrichromeChromeDualArch": ("app.vanadium.browser", "702ab8bf065c3790df2a632523ce4af673f18ab633eadbda9bd4915bc367d2a9"),
    "TrichromeWebViewDualArch": ("app.vanadium.webview", "f8ebbc61de940cd46e6a3c9e27ac7ac2f8b1a4fd93449bbd5b8182f8fcb9b0c8"),
    "VanadiumConfig": ("app.vanadium.config", "859af201df06d0fa2e698496f1a14b959be173f14da81cf15036df7f6d8df42a"),
}
VANADIUM_SIGNER = "c6adb8b83c6d4c17d292afde56fd488a51d316ff8f2c11c5410223bff8a7dbb3"
YASR_APK = "SYSTEM_EXT/app/YASR/YASR.apk"
YASR_PACKAGE = "com.idoybh.yasr"
YASR_SHA256 = "903603b5618855906926793e0af9c7881c7d9e172216703e3f555af1450c75be"
YASR_SIGNERS = [
    "27fdbcc159491e419d65f31d97fcf599194c38a94d81abc52bb02159672da927",
    "3257d599a49d2c961a471ca9843f59d341a405884583fc087df4237b733bbd6d",
]
TALKBACK_APK = "PRODUCT/app/Talkback/Talkback.apk"
TALKBACK_PACKAGE = "org.calyxos.talkback"
CORE_PARTITIONS = ("boot", "init_boot", "vendor_boot", "dtbo", "vbmeta", "vbmeta_system",
                   "recovery", "odm", "system", "system_ext", "product", "vendor", "vendor_dlkm", "system_dlkm")
AUDIT_PROFILE = "byof-houji-houjiin-android17"
DEVICE_ALIASES = frozenset({"houji", "houjiin"})
OTA_ASSERT_SEPARATOR = "|"
INIT_IMAGE_PATH = "/system/bin/init"
INIT_LINK_PATH = "/init"
INIT_TARGET_FILES_PATH = "SYSTEM/bin/init"
INIT_REQUIRED_STRINGS = (b"houji", b"houjiin", b"ro.boot.hardware.sku", b"ro.boot.hwc",
                         b"ro.boot.hardware.revision", b"ro.build.product", b"23127PN0CC", b"23127PN0CG", b"houji_global")
EUICC_PACKAGE = "im.angry.openeuicc"
EUICC_APK = "SYSTEM_EXT/priv-app/OpenEUICC/OpenEUICC.apk"
EUICC_JNI_LINK = "SYSTEM_EXT/priv-app/OpenEUICC/lib/arm64/liblpac-jni.so"
EUICC_JNI = "SYSTEM_EXT/lib64/liblpac-jni.so"
EUICC_ALLOWLIST = "SYSTEM_EXT/etc/permissions/privapp_whitelist_im.angry.openeuicc.xml"
EUICC_PERMISSIONS = {
    "android.permission.READ_PRIVILEGED_PHONE_STATE", "android.permission.WRITE_EMBEDDED_SUBSCRIPTIONS",
    "android.permission.MODIFY_PHONE_STATE", "android.permission.SECURE_ELEMENT_PRIVILEGED_OPERATION",
}
EUICC_FEATURE_XML = "PRODUCT/etc/permissions/android.hardware.telephony.euicc.xml"
ESIM_SWITCHER_PACKAGE = "com.xiaomi.mtb"
ESIM_SWITCHER_APK = "SYSTEM_EXT/priv-app/XiaomiEsimSwitcher/XiaomiEsimSwitcher.apk"
ESIM_SWITCHER_ALLOWLIST = "SYSTEM_EXT/etc/permissions/XiaomiEsimSwitcher.xml"
ESIM_OVERLAY_APK = "ODM/overlay/FrameworksResXiaomi.apk"
ESIM_OVERLAY_PACKAGE = "android.overlay.xiaomi"
STOCK_VENDOR_PROJECTS = ("vendor/xiaomi/houji", "vendor/xiaomi/sm8650-common")
BOOTSTRAP_HEADERS = {
    "boot": b"ANDROID!", "init_boot": b"ANDROID!", "vendor_boot": b"VNDRBOOT",
    "dtbo": bytes.fromhex("d7b7ab1e"), "vbmeta": b"AVB0", "vbmeta_system": b"AVB0", "recovery": b"ANDROID!",
}
STANDALONE_IMAGES = tuple(BOOTSTRAP_HEADERS)
VBMETA_IMAGES = ("vbmeta", "vbmeta_system")
AVB_ALGORITHM = "SHA256_RSA4096"
AVB_ROOT_FLAGS = 3
SIGNING_KEYS = (
    "releasekey", "platform", "shared", "media", "networkstack", "nfc",
    "bluetooth", "sdk_sandbox",
)
# Package namespaces AOSP itself builds under com.google.android.* (mainline resource/stub modules).
AOSP_GOOGLE_NAMED = {
    "com.google.android.permissioncontroller",
    "com.google.android.cellbroadcastreceiver", "com.google.android.cellbroadcastservice",
    "com.google.android.connectivity.resources", "com.google.android.wifi.resources",
    "com.google.android.networkstack", "com.google.android.networkstack.tethering",
    "com.google.android.safetycenter.resources", "com.google.android.ondevicepersonalization.services",
    "com.google.android.uwb.resources", "com.google.android.healthconnect.controller",
    "com.google.android.ext.services", "com.google.android.ext.shared",
}
GOOGLE_NAMESPACE = re.compile(r"^(com\.google\.|com\.android\.vending$|com\.android\.chrome$)")
GOOGLE_FILE = re.compile(
    r"(?i)(^|/)(Phonesky|PrebuiltGmsCore\w*|GoogleServicesFramework|GoogleLoginService|SetupWizard\w*|"
    r"Velvet|Gboard|LatinImeGoogle|GoogleCamera|GCam|Pixel\w+|Turbo\w*|Wellbeing|"
    r"GoogleDialer|GoogleContacts\w*|GoogleOneTimeInitializer|GooglePartnerSetup|"
    r"GoogleRestore|ConfigUpdater|GmsCore\w*GoogleSigned|WebViewGoogle|Trichrome(?:Library|WebView|Chrome)\w*|"
    r"Chrome\w*|Maps|Photos|Gmail\w*|YouTube\w*|Drive|Duo|Meet)\.apk$"
)
GOOGLE_MODULE_PATH = re.compile(r"^(vendor/google|vendor/pixel|packages/apps/Pixel|vendor/partner_gms|vendor/gapps)")
GOOGLE_SHARED_USER = re.compile(r"^com\.google\.uid\.")
GOOGLE_SDK_MARKER = re.compile(r"(?:play-services|firebase)-[^/]+\.properties", re.I)
APERTURE_LENS_ACTIVITY = "com.google.android.apps.googlecamera.fishfood"
APERTURE_LENS_APK = "PRODUCT/app/ApertureLensLauncher/ApertureLensLauncher.apk"
APK_ROOTS = ("SYSTEM", "SYSTEM_EXT", "PRODUCT", "VENDOR", "ODM", "VENDOR_DLKM", "SYSTEM_DLKM")
MICROG_JNI_ROOT = "PRODUCT/priv-app/GmsCore/lib/arm64/"
MICROG_JNI_ARCHIVE_ROOT = "lib/arm64-v8a/"
MICROG_SYSCONFIG = "PRODUCT/etc/sysconfig/sysconfig-com.google.android.gms.xml"
EXTRACT_ROOTS = ("META", "IMAGES", "PREBUILT_IMAGES")
WIDEVINE_APEX = "com.google.android.widevine.nonupdatable.apex"
PRESIGNED_APEX_SOURCES = {
    "VENDOR/apex/" + WIDEVINE_APEX:
        "vendor/xiaomi/sm8650-common/proprietary/vendor/apex/" + WIDEVINE_APEX,
    "SYSTEM/apex/com.android.apex.cts.shim.apex": None,
}
OTA_CERTS_APK_PATH = "RECOVERY/RAMDISK/system/etc/security/otacerts.zip"
RECOVERY_BINARY_PATH = "system/bin/recovery"
RECOVERY_OTACERTS_PATH = "system/etc/security/otacerts.zip"
RECOVERY_BOOTCTRL_PATH = "system/bin/hw/android.hardware.boot-service.qti.recovery"
RECOVERY_BOOTCTRL_RC_PATH = "system/etc/init/android.hardware.boot-service.qti.recovery.rc"
RECOVERY_BOOTCTRL_VINTF_PATH = "system/etc/vintf/manifest/boot-service.qti.xml"
RECOVERY_TF_BINARY_PATH = "RECOVERY/RAMDISK/" + RECOVERY_BINARY_PATH
VENDOR_BOOTCTRL_TF_PATH = "VENDOR/bin/hw/android.hardware.boot-service.qti"
VENDOR_BOOTCTRL_RC_TF_PATH = "VENDOR/etc/init/android.hardware.boot-service.qti.rc"
VENDOR_BOOTCTRL_VINTF_TF_PATH = "VENDOR/etc/vintf/manifest/boot-service.qti.xml"
VENDOR_SEPOLICY_CIL_TF_PATH = "VENDOR/etc/selinux/vendor_sepolicy.cil"
VENDOR_FILE_CONTEXTS_TF_PATH = "VENDOR/etc/selinux/vendor_file_contexts"
VENDOR_ATFWD_SECCOMP_TF_PATH = "VENDOR/etc/seccomp_policy/atfwd@2.0.policy"
VENDOR_HEALTH_VINTF_TF_PATH = "VENDOR/etc/vintf/manifest/android.hardware.health-service.xiaomi.xml"
VENDOR_POWERSHARE_VINTF_TF_PATH = "VENDOR/etc/vintf/manifest/vendor.lineage.powershare-service.default.xml"
DYNAMIC_RO_PARTITIONS = ("system", "system_ext", "product", "vendor", "odm", "system_dlkm", "vendor_dlkm")
PRUNED_USERSPACE_DAEMONS = (
    "VENDOR/bin/hw/vendor.rongcard.eid@1.0-service",
    "VENDOR/bin/hw/vendor.qti.sla.service@1.0-service",
    "VENDOR/bin/slad",
    "ODM/bin/mlipayd",
    "ODM/bin/fidoca",
    "ODM/bin/tidad",
    "ODM/bin/mtd",
    "ODM/bin/toucheventcheck",
)
EROFS_SUPER_MAGIC = b"\xe2\xe1\xf5\xe0"
# Literals of install.cpp ConfirmUntrustedInstall (bootable/recovery): the prompt a user sees
# for firmware ZIPs that are not signed by the release key.
RECOVERY_MENU_HEADERS = (b"Signature verification failed", b"Install untrusted package?")
RECOVERY_PROJECT = "bootable/recovery"
EXTRA_EXTRACTED = {
    OTA_CERTS_APK_PATH, INIT_TARGET_FILES_PATH, EUICC_JNI, RECOVERY_TF_BINARY_PATH,
    VENDOR_BOOTCTRL_TF_PATH, VENDOR_BOOTCTRL_RC_TF_PATH, VENDOR_BOOTCTRL_VINTF_TF_PATH,
    VENDOR_SEPOLICY_CIL_TF_PATH, VENDOR_FILE_CONTEXTS_TF_PATH, VENDOR_ATFWD_SECCOMP_TF_PATH,
    VENDOR_HEALTH_VINTF_TF_PATH, VENDOR_POWERSHARE_VINTF_TF_PATH,
}
LOCAL_PORT_PROJECTS = {"device/xiaomi/houji", "device/xiaomi/sm8650-common", "hardware/xiaomi",
                       "vendor/yaap", "vendor/microg", "vendor/xiaomi/houji"}
NOT_RUN = (
    "Flash or fastboot boot of any image on a real Xiaomi 14 (houji 23127PN0CC / houjiin 23127PN0CG)",
    "Bootloader unlock/relock flow and verified-boot state with the custom AVB key",
    "update_engine A/B apply of the OTA on device and post-install slot switch",
    "Compatibility of the retained stock kernel/vendor with the firmware already installed on the device (no firmware is shipped)",
    "Rollback-index and anti-rollback fuse acceptance by the device bootloader",
    "First boot, selinux enforcing denial review, logcat and tombstone review",
    "Runtime kernel module load order and vendor_dlkm/system_dlkm mount",
    "microG self-check, signature spoofing, push registration, location backends",
    "Aperture camera, fingerprint, audio, modem/VoLTE/eSIM, Wi-Fi, Bluetooth, NFC, sensors",
    "CTS/VTS/GTS, power, thermal and charging behaviour",
)


class Report:
    def __init__(self):
        self.checks = []
        self.artifacts = {}

    def add(self, name, ok, gating=True, **detail):
        self.checks.append({"check": name, "ok": bool(ok), "gating": gating, "detail": detail})
        return bool(ok)

    def guard(self, name, function, *args):
        try:
            return function(*args)
        except (OSError, ValueError, subprocess.CalledProcessError, KeyError, zipfile.BadZipFile,
                ElementTree.ParseError) as error:
            detail = error.output if isinstance(error, subprocess.CalledProcessError) else None
            self.add(name, False, error=f"{type(error).__name__}: {error}", output=detail)
            return None


def sha256_file(path, limit=None):
    h = hashlib.sha256()
    remaining = limit
    with open(path, "rb") as source:
        while remaining is None or remaining > 0:
            block = source.read(CHUNK if remaining is None else min(CHUNK, remaining))
            if not block:
                break
            h.update(block)
            remaining = None if remaining is None else remaining - len(block)
    return h.hexdigest()


def zero_from(path, offset):
    with open(path, "rb") as source:
        source.seek(offset)
        while block := source.read(CHUNK):
            if block.count(0) != len(block):
                return False
    return True


def run(args, **kwargs):
    done = subprocess.run([str(a) for a in args], capture_output=True, text=True, **kwargs)
    if done.returncode:
        tail = (done.stdout + done.stderr).strip()[-1500:]
        raise subprocess.CalledProcessError(done.returncode, [str(a) for a in args], output=tail)
    return done.stdout + done.stderr


def cert_sha256(pem_path):
    der = ssl.PEM_cert_to_DER_cert(Path(pem_path).read_text())
    return hashlib.sha256(der).hexdigest()


class Tools:
    def __init__(self, host_bin):
        self.host_bin = Path(host_bin)

    def __call__(self, name):
        local = self.host_bin / name
        found = str(local) if local.is_file() else shutil.which(name)
        if not found:
            raise ValueError(f"Missing host tool {name}; build it with `m {name}` and pass --host-bin")
        return found

    def env(self):
        env = dict(os.environ)
        env["PATH"] = f"{self.host_bin}{os.pathsep}{env['PATH']}"
        env["ANDROID_HOST_OUT"] = str(self.host_bin.parent)
        return env


class TargetFiles:
    """Directory view of target-files; a zip is materialised as the audited subset only."""

    def __init__(self, source, work):
        self.source = Path(source)
        self.names = set()
        if self.source.is_dir():
            self.root = self.source
            for folder, _, files in os.walk(self.root):
                for name in files:
                    self.names.add(str((Path(folder) / name).relative_to(self.root)))
            return
        self.root = work / "target_files"
        shutil.rmtree(self.root, ignore_errors=True)
        with zipfile.ZipFile(self.source) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                self.names.add(info.filename)
                mode = info.external_attr >> 16
                top = info.filename.split("/", 1)[0]
                if stat.S_ISLNK(mode):
                    continue
                if (top in EXTRACT_ROOTS or info.filename in EXTRA_EXTRACTED or
                        re.fullmatch(r"(?:VENDOR|ODM)/etc/selinux/precompiled_sepolicy", info.filename) or
                        (info.filename.startswith(MICROG_JNI_ROOT) and info.filename.endswith(".so")) or
                        (top in APK_ROOTS and re.search(r"(\.apk|\.jar|\.capex|\.apex|\.ko|\.prop|\.xml|modules\.(?:load|blocklist))$", info.filename))):
                    target = self.root / info.filename
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info) as src, open(target, "wb") as dst:
                        shutil.copyfileobj(src, dst, CHUNK)

    def path(self, relative):
        return self.root / relative

    def props(self, relative):
        out = {}
        for line in self.path(relative).read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                out[key.strip()] = value.strip()
        return out


def read_manifest(args, report):
    if args.manifest_file:
        text = Path(args.manifest_file).read_text()
    else:
        text = run(args.manifest_command.split(), cwd=args.rom_dir)
    root = ElementTree.fromstring(text)
    nodes = list(root.iter("project"))
    projects = {p.get("path") or p.get("name"): p.get("revision") for p in nodes}
    if len(nodes) != len(projects):
        raise ValueError("duplicate project paths in pinned manifest")
    manifest_head = run(["git", "-C", Path(args.rom_dir) / ".repo/manifests", "rev-parse", "HEAD"]).strip()
    return {"sha256": hashlib.sha256(text.encode()).hexdigest(), "manifest_repository": manifest_head,
            "projects": dict(sorted(projects.items()))}


def check_sources(report, args, source, manifest):
    projects = manifest["projects"]
    for path, verified in sorted(source["repository_commits"].items()):
        actual = projects.get(path)
        repo = Path(args.rom_dir) / path
        head = run(["git", "rev-parse", "HEAD"], cwd=repo).strip()
        ok = head == actual == verified
        if path in LOCAL_PORT_PROJECTS and head == actual:
            port = run(["git", "rev-parse", "refs/heads/yaap-17"], cwd=repo).strip()
            ancestry = subprocess.run(["git", "merge-base", "--is-ancestor", verified, head], cwd=repo)
            ok = ancestry.returncode == 0 and head == port
        report.add(f"source_pin_{path}", ok, verified_revision=verified, built_revision=actual)
    report.add("source_manifest_all_revisions_are_commit_hashes",
               all(re.fullmatch(r"[0-9a-f]{40}", revision or "") for revision in projects.values()))
    google_paths = sorted(path for path in projects if GOOGLE_MODULE_PATH.match(path))
    report.add("proprietary_google_projects_excluded", not google_paths, projects=google_paths)


def check_kernel_sources(report, args, manifest):
    path = "kernel/xiaomi/houji"
    repo = Path(args.rom_dir) / path
    root = repo / "include/uapi"
    pins = json.loads((root / "houji-provenance.json").read_text())
    head = run(["git", "rev-parse", "HEAD"], cwd=repo).strip()
    base = pins["generic_kernel_commit"]
    ancestry = subprocess.run(["git", "merge-base", "--is-ancestor", base, head], cwd=repo)
    mismatches = [name for name, entry in pins["headers"].items()
                  if sha256_file(root / name) != entry["sha256"]]
    report.add("stock_generic_kernel_revision_and_vendor_uapi_pins", bool(pins["headers"]) and not mismatches
               and ancestry.returncode == 0 and manifest["projects"].get(path) == head,
               generic_commit=base, compiled_headers_commit=head, mismatches=mismatches)
    return pins


def check_ota(report, args, tools, work, tf, payload_dir):
    ota = Path(args.ota)
    out = {"bytes": ota.stat().st_size, "sha256": sha256_file(ota)}
    report.artifacts["ota"] = {"file": ota.name, **out}
    run([tools("check_ota_package_signature"), args.ota_cert, ota], env=tools.env())
    report.add("ota_signature_matches_release_certificate", True,
               certificate_sha256=cert_sha256(args.ota_cert), **out)
    with zipfile.ZipFile(ota) as archive:
        names = set(archive.namelist())
        required = {"payload.bin", "payload_properties.txt", "META-INF/com/android/metadata",
                    "META-INF/com/android/metadata.pb", "care_map.pb"}
        report.add("ota_has_ab_full_package_members", required <= names, missing=sorted(required - names))
        if "care_map.pb" in names:
            care_map = archive.read("care_map.pb")
            report.add("ota_has_nonempty_care_map", bool(care_map), sha256=hashlib.sha256(care_map).hexdigest())
        metadata = dict(l.split("=", 1) for l in archive.read(
            "META-INF/com/android/metadata").decode().splitlines() if "=" in l)
        properties = dict(l.split("=", 1) for l in archive.read(
            "payload_properties.txt").decode().splitlines() if "=" in l)
        payload = work / "payload.bin"
        with archive.open("payload.bin") as src, open(payload, "wb") as dst:
            shutil.copyfileobj(src, dst, CHUNK)
    file_hash = base64.b64decode(properties["FILE_HASH"]).hex()
    report.add("ota_payload_hash_matches_payload_properties",
               file_hash == sha256_file(payload) and int(properties["FILE_SIZE"]) == payload.stat().st_size,
               payload_sha256=file_hash)
    aliases = metadata.get("pre-device", "").split(OTA_ASSERT_SEPARATOR)
    report.artifacts["device_aliases"] = sorted(aliases)
    report.add("ota_metadata_is_full_ab_without_pre_build",
               metadata.get("ota-type") == "AB" and
               "pre-build" not in metadata and "pre-build-incremental" not in metadata,
               ota_type=metadata.get("ota-type"))
    report.add("ota_metadata_device_aliases_are_exactly_houji_and_houjiin_pipe_separated",
               len(aliases) == len(set(aliases)) and set(aliases) == DEVICE_ALIASES,
               pre_device=metadata.get("pre-device"))
    system = tf.props("SYSTEM/build.prop")
    report.add("ota_metadata_post_build_matches_target_files",
               metadata.get("post-build") == system.get("ro.build.fingerprint", system.get("ro.system.build.fingerprint")),
               post_build=metadata.get("post-build"))
    report.add("ota_metadata_security_patch_matches_target_files",
               metadata.get("post-security-patch-level") == system.get("ro.build.version.security_patch"),
               patch=metadata.get("post-security-patch-level"))
    report.add("ota_metadata_timestamp_is_a_positive_integer",
               re.fullmatch(r"[1-9]\d*", metadata.get("post-timestamp", "")) is not None,
               timestamp=metadata.get("post-timestamp"))
    shutil.rmtree(payload_dir, ignore_errors=True)
    payload_dir.mkdir(parents=True)
    run([tools("ota_extractor"), "--payload", payload, "--output_dir", payload_dir], env=tools.env())
    extracted = {p.stem: p for p in payload_dir.glob("*.img")}
    report.add("ota_extractor_validated_all_partitions", bool(extracted), partitions=sorted(extracted))
    payload.unlink()
    return extracted


def is_erofs_image(path):
    with open(path, "rb") as stream:
        stream.seek(1024)
        return stream.read(4) == EROFS_SUPER_MAGIC


def resolve_in_extracted_root(root, rel_path):
    cur = Path(root)
    for part in Path(rel_path.lstrip("/")).parts:
        nxt = cur / part
        for _ in range(16):
            if not nxt.is_symlink():
                break
            target = os.readlink(nxt)
            nxt = (Path(root) / target.lstrip("/")) if target.startswith("/") else (nxt.parent / target)
        cur = nxt
    return cur


def check_partitions(report, tf, extracted):
    core = set(CORE_PARTITIONS)
    ab = tf.path("META/ab_partitions.txt").read_text().split()
    report.add("payload_partitions_are_exactly_the_14_core_partitions",
               len(CORE_PARTITIONS) == len(core) == 14 and set(extracted) == core,
               only_payload=sorted(set(extracted) - core), missing_from_payload=sorted(core - set(extracted)))
    report.add("target_files_meta_ab_partitions_are_exactly_the_14_core_partitions",
               len(ab) == len(set(ab)) and set(ab) == core,
               only_target_files=sorted(set(ab) - core), missing_from_target_files=sorted(core - set(ab)))
    radio = sorted(name for name in tf.names if name.split("/", 1)[0] == "RADIO")
    report.artifacts["payload_partitions"] = sorted(extracted)
    report.add("no_radio_items_in_target_files", not radio, radio_items=radio)
    non_erofs = sorted(p for p in DYNAMIC_RO_PARTITIONS if p not in extracted or not is_erofs_image(extracted[p]))
    report.add("readonly_partitions_use_erofs", not non_erofs, non_erofs=non_erofs)


def check_init_aliases(report, tools, work, tf, extracted):
    image = extracted["system"]
    with tempfile.TemporaryDirectory(prefix="init-", dir=work) as scratch:
        if is_erofs_image(image):
            run([tools("fsck.erofs"), f"--extract={scratch}", "--overwrite", image], env=tools.env())
            dest = resolve_in_extracted_root(scratch, INIT_IMAGE_PATH)
            link_node = Path(scratch) / INIT_LINK_PATH.lstrip("/")
            link_dest = os.readlink(link_node) if link_node.is_symlink() else None
            data = dest.read_bytes() if dest.is_file() else b""
        else:
            dest = Path(scratch) / "init"
            run([tools("debugfs"), "-R", f'dump "{INIT_IMAGE_PATH}" "{dest}"', image], env=tools.env())
            link = run([tools("debugfs"), "-R", f"stat {INIT_LINK_PATH}", image], env=tools.env())
            m = re.search(r'Fast link dest: "([^"]*)"', link)
            link_dest = m[1] if m else None
            data = dest.read_bytes() if dest.is_file() else b""
    digest = hashlib.sha256(data).hexdigest()
    missing = [s.decode() for s in INIT_REQUIRED_STRINGS if b"\0" + s + b"\0" not in data]
    elf_arm64 = data[:6] == b"\x7fELF\x02\x01" and data[18:20] == b"\xb7\x00"
    report.add("system_bin_init_is_arm64_elf_with_houji_houjiin_sku_normalization_strings",
               elf_arm64 and not missing, bytes=len(data), sha256=digest, missing_strings=missing)
    report.add("root_init_links_to_system_bin_init", link_dest == INIT_IMAGE_PATH,
               link_destination=link_dest)
    staged = tf.path(INIT_TARGET_FILES_PATH)
    report.add("target_files_system_bin_init_equals_payload", staged.is_file() and sha256_file(staged) == digest,
               sha256=digest)


def check_esim(report, tools, tf, rows):
    def apk(label, package, path):
        paths = [name for name, row in rows.items() if row["package"] == package]
        return report.add(f"esim_{label}_apk_installed_once_at_expected_path", paths == [path], paths=paths)

    def grants(path, package, expected):
        root = ElementTree.parse(tf.path(path)).getroot()
        granted = {p.get("name") for node in root if node.get("package") == package
                   for p in node.findall("permission")}
        return expected <= granted

    installed = apk("openeuicc", EUICC_PACKAGE, EUICC_APK)
    report.add("esim_openeuicc_privapp_allowlist_grants_euicc_permissions",
               installed and grants(EUICC_ALLOWLIST, EUICC_PACKAGE, EUICC_PERMISSIONS),
               path=EUICC_ALLOWLIST, permissions=sorted(EUICC_PERMISSIONS))
    library = tf.path(EUICC_JNI)
    header = library.read_bytes()[:20] if library.is_file() else b""
    report.add("esim_openeuicc_app_links_to_arm64_system_ext_lpac_library",
               EUICC_JNI_LINK in tf.names and header[:6] == b"\x7fELF\x02\x01" and header[18:20] == b"\xb7\x00",
               app_link=EUICC_JNI_LINK, library=EUICC_JNI)
    installed = apk("xiaomi_esim_switcher", ESIM_SWITCHER_PACKAGE, ESIM_SWITCHER_APK)
    report.add("esim_xiaomi_switcher_privapp_allowlist",
               installed and grants(ESIM_SWITCHER_ALLOWLIST, ESIM_SWITCHER_PACKAGE,
                                    {"android.permission.WRITE_SECURE_SETTINGS"}),
               path=ESIM_SWITCHER_ALLOWLIST)
    report.add("esim_telephony_euicc_feature_installed", EUICC_FEATURE_XML in tf.names, path=EUICC_FEATURE_XML)
    google = sorted(name for name, row in rows.items()
                    if row["package"] == "com.google.android.euicc" or "EuiccGoogle" in name)
    report.add("esim_no_google_euicc_prebuilt", not google, apks=google)
    overlay_ok = rows.get(ESIM_OVERLAY_APK, {}).get("package") == ESIM_OVERLAY_PACKAGE
    resources = run([tools("aapt2"), "dump", "resources", tf.path(ESIM_OVERLAY_APK)]) if overlay_ok else ""
    capabilities = re.search(r"array/config_telephonyEuiccDeviceCapabilities\n\s*\(\) \(array\) size=(\d+)", resources)
    slots = re.search(r"integer/config_num_physical_slots\n\s*\(\) (\d+)", resources)
    report.add("esim_framework_overlay_declares_euicc_capabilities_and_two_physical_slots",
               overlay_ok and bool(capabilities) and int(capabilities[1]) > 0 and bool(slots) and slots[1] == "2",
               overlay=ESIM_OVERLAY_APK, capability_entries=int(capabilities[1]) if capabilities else None,
               physical_slots=slots[1] if slots else None)
    regional = "ODM/overlay/HoujiEuiccOverlay.apk"
    installed = apk("houji_regional_overlay", "android.overlay.xiaomi.euicc.houji", regional)
    manifest = run([tools("aapt2"), "dump", "xmltree", tf.path(regional), "--file", "AndroidManifest.xml"]) if installed else ""
    report.add("houji_esim_overlay_uses_regional_model_guard",
               bool(re.search(r'requiredSystemPropertyValue[^\n]*"\+\(23127PN0CG\)"', manifest)), path=regional)


QTI_TELEPHONY_JARS = (
    "PRODUCT/framework/ims-ext-common.jar",
    "SYSTEM_EXT/framework/extphonelib.jar",
    "PRODUCT/framework/extphonelib-product.jar",
    "SYSTEM_EXT/framework/qti-telephony-hidl-wrapper.jar",
    "SYSTEM_EXT/framework/qti-telephony-utils.jar",
)
QTI_TELEPHONY_APKS = (
    "SYSTEM_EXT/priv-app/ims/ims.apk",
    "SYSTEM_EXT/priv-app/QtiTelephony/QtiTelephony.apk",
)
QTI_TELEPHONY_PREFIXES = ("Lorg/codeaurora/ims/", "Lcom/qti/extphone/")


def parse_dex_archive(path):
    def uleb128(buf, pos):
        value, shift = 0, 0
        while True:
            byte = buf[pos]
            pos += 1
            value |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                return value, pos
            shift += 7

    supers, ifaces, defined, referenced = {}, {}, set(), set()
    with zipfile.ZipFile(path) as archive:
        for member in archive.namelist():
            if not (member.startswith("classes") and member.endswith(".dex")):
                continue
            dex = archive.read(member)
            s_sz, s_off = struct.unpack_from("<II", dex, 56)
            t_sz, t_off = struct.unpack_from("<II", dex, 64)
            p_sz, p_off = struct.unpack_from("<II", dex, 72)
            m_sz, m_off = struct.unpack_from("<II", dex, 88)
            c_sz, c_off = struct.unpack_from("<II", dex, 96)
            strings = []
            for idx in range(s_sz):
                off, = struct.unpack_from("<I", dex, s_off + idx * 4)
                _, pos = uleb128(dex, off)
                strings.append(dex[pos:dex.index(0, pos)].decode("utf-8", "replace"))
            types = [strings[struct.unpack_from("<I", dex, t_off + idx * 4)[0]] for idx in range(t_sz)]
            protos = []
            for idx in range(p_sz):
                _, ret_idx, params_off = struct.unpack_from("<III", dex, p_off + idx * 12)
                params = ""
                if params_off:
                    count, = struct.unpack_from("<I", dex, params_off)
                    params = "".join(types[struct.unpack_from("<H", dex, params_off + 4 + j * 2)[0]]
                                     for j in range(count))
                protos.append(f"({params}){types[ret_idx]}")
            methods = [(types[c], strings[n], protos[p])
                       for c, p, n in (struct.unpack_from("<HHI", dex, m_off + idx * 8) for idx in range(m_sz))]
            referenced.update(methods)
            for idx in range(c_sz):
                c_idx, _, sup_idx, iface_off, _, _, data_off, _ = struct.unpack_from(
                    "<IIIIIIII", dex, c_off + idx * 32)
                cname = types[c_idx]
                supers[cname] = types[sup_idx] if sup_idx != 0xFFFFFFFF else None
                if iface_off:
                    count, = struct.unpack_from("<I", dex, iface_off)
                    ifaces[cname] = [types[struct.unpack_from("<H", dex, iface_off + 4 + j * 2)[0]]
                                     for j in range(count)]
                else:
                    ifaces[cname] = []
                if not data_off:
                    continue
                pos = data_off
                sf_sz, pos = uleb128(dex, pos)
                if_sz, pos = uleb128(dex, pos)
                dm_sz, pos = uleb128(dex, pos)
                vm_sz, pos = uleb128(dex, pos)
                for _ in range(sf_sz + if_sz):
                    _, pos = uleb128(dex, pos)
                    _, pos = uleb128(dex, pos)
                for count in (dm_sz, vm_sz):
                    midx = 0
                    for _ in range(count):
                        diff, pos = uleb128(dex, pos)
                        midx += diff
                        _, pos = uleb128(dex, pos)
                        _, pos = uleb128(dex, pos)
                        defined.add((cname, methods[midx][1], methods[midx][2]))
    return supers, ifaces, defined, referenced


def check_qti_telephony_linkage(report, args, tf):
    missing_files = [rel for rel in (*QTI_TELEPHONY_JARS, *QTI_TELEPHONY_APKS) if not tf.path(rel).is_file()]
    if missing_files:
        report.add("qti_ims_and_extphone_dex_linkage", False, missing_files=missing_files)
        return
    base_supers, base_ifaces, base_defs = {}, {}, set()
    product_out = Path(args.product_out)
    boot_jars = [
        product_out / "apex/com.android.art/javalib/core-oj.jar",
        product_out / "system/framework/framework.jar",
        product_out / "system/framework/telephony-common.jar",
        product_out / "system/framework/ims-common.jar",
    ]
    for jar in (*boot_jars, *(tf.path(rel) for rel in QTI_TELEPHONY_JARS)):
        if jar.is_file():
            s, i, d, _ = parse_dex_archive(jar)
            base_supers.update(s)
            base_ifaces.update(i)
            base_defs |= d
    unresolved = {}
    extphone_iface = {(m, p) for c, m, p in base_defs if c == "Lcom/qti/extphone/IExtPhone;"}
    extphone_impl = set()
    for rel in QTI_TELEPHONY_APKS:
        local_s, local_i, local_d, refs = parse_dex_archive(tf.path(rel))
        if rel.endswith("QtiTelephony.apk"):
            extphone_impl = {(m, p) for c, m, p in local_d
                             if c == "Lcom/qti/phone/ExtTelephonyService$1;" and m != "<init>"}
        bad = []
        for cname, mname, mproto in sorted(refs):
            if not cname.startswith(QTI_TELEPHONY_PREFIXES):
                continue
            seen, stack, ok = set(), [cname], False
            while stack:
                cur = stack.pop()
                if not cur or cur in seen:
                    continue
                seen.add(cur)
                if (cur, mname, mproto) in local_d or (cur, mname, mproto) in base_defs:
                    ok = True
                    break
                sup = local_s.get(cur) or base_supers.get(cur)
                stack.append(sup or "Ljava/lang/Object;")
                stack.extend(local_i.get(cur, ()))
                stack.extend(base_ifaces.get(cur, ()))
            if not ok:
                bad.append(f"{cname}->{mname}{mproto}")
        if bad:
            unresolved[rel] = bad
    missing_impl = sorted(f"{m}{p}" for m, p in (extphone_iface - extphone_impl))
    extra_impl = sorted(f"{m}{p}" for m, p in (extphone_impl - extphone_iface))
    report.add("qti_ims_and_extphone_dex_linkage",
               not unresolved and bool(extphone_iface) and not missing_impl and not extra_impl,
               unresolved=unresolved, extphone_missing_in_service=missing_impl,
               extphone_extra_in_service=extra_impl)


def load_staged_gki(rom_dir):
    gki_root = Path(rom_dir) / "kernel/prebuilts/houji-gki"
    sums_path = gki_root / "SHA256SUMS"
    prov_path = gki_root / "provenance.json"
    if not (sums_path.is_file() and prov_path.is_file()):
        return None
    hashes = dict(line.split("  ", 1)[::-1] for line in sums_path.read_text().splitlines() if line.strip())
    prov = json.loads(prov_path.read_text())
    return {"root": gki_root, "hashes": hashes, "provenance": prov}


def retained_stock_provenance(source, gki=None):
    kernel = source["stock_kernel"]["provenance"]
    info = {
        "stock_source_rom": source["baseline"],
        "retained_components": ["vendor_boot dtb", "dtbo prefix", "vendor_ramdisk modules",
                                "vendor_dlkm modules", "vendor blobs"],
        "kernel_release": gki["provenance"]["gki_release"] if gki else kernel["kernel_release"],
        "stock_image_input_sha256": kernel["input_sha256"],
        "module_counts": kernel["module_counts"],
        "dtb_count": kernel["dtb_count"],
        "vendor_repository_commits": {p: source["repository_commits"][p] for p in STOCK_VENDOR_PROJECTS},
        "firmware_partitions_shipped": [],
        "release_gating_on_stock_region_or_oem_postcondition": False,
    }
    if gki:
        prov = gki["provenance"]
        info["gki_upgrade"] = {
            **{k: prov[k] for k in ("gki_release", "gki_branch", "gki_upstream_commit",
                                    "gki_build_mode", "gki_tag", "gki_build_id", "patches") if k in prov},
            "image_sha256": gki["hashes"]["Image"],
        }
    else:
        info["retained_components"] = ["boot kernel Image", *info["retained_components"], "system_dlkm modules"]
    return info


def retained_source_inputs(source):
    return {**{k: v for k, v in source.items() if k != "radio"},
            "lfs_objects": {repo: {k: v for k, v in objects.items() if not k.startswith("radio/")}
                            for repo, objects in source.get("lfs_objects", {}).items()}}


def raw_digest(path, tools, scratch):
    with open(path, "rb") as source:
        sparse = source.read(4) == SPARSE_MAGIC
    if not sparse:
        return sha256_file(path), path.stat().st_size
    raw = scratch / (path.name + ".raw")
    run([tools("simg2img"), path, raw])
    try:
        return sha256_file(raw), raw.stat().st_size
    finally:
        raw.unlink()


def check_images_vs_payload(report, tf, tools, extracted, work):
    scratch = work / "raw"
    scratch.mkdir(exist_ok=True)
    for stem, image in sorted(extracted.items()):
        staged = tf.path(f"IMAGES/{stem}.img")
        if not staged.is_file():
            if stem in CORE_PARTITIONS:
                report.add(f"target_files_image_{stem}", False, error="missing IMAGES entry")
            continue
        digest, size = raw_digest(staged, tools, scratch)
        report.add(f"target_files_image_{stem}_equals_payload",
                   digest == sha256_file(image) and size == image.stat().st_size,
                   sha256=digest, bytes=size)


def avb_info(tools, image):
    text = run([tools("avbtool"), "info_image", "--image", image], env=tools.env())
    field = lambda label: (re.search(rf"^{re.escape(label)}:\s+(.*)$", text, re.M) or [None, None])[1]
    return {"algorithm": field("Algorithm"), "flags": field("Flags"), "rollback_index": field("Rollback Index"),
            "public_key_sha1": field("Public key (sha1)"), "raw": text}


def check_avb(report, args, tools, work, extracted, tf):
    pub_pem = work / "avb_public.pem"
    with open(pub_pem, "wb") as out:
        out.write(subprocess.run(["openssl", "rsa", "-in", args.avb_key, "-pubout"], check=True,
                                 capture_output=True).stdout)
    pub_bin = work / "avb_public.bin"
    run([tools("avbtool"), "extract_public_key", "--key", pub_pem, "--output", pub_bin], env=tools.env())
    key_sha1 = hashlib.sha1(pub_bin.read_bytes()).hexdigest()
    report.add("avb_key_public_digest", True, avb_public_key_sha1=key_sha1,
               avb_public_key_sha256=hashlib.sha256(pub_bin.read_bytes()).hexdigest())
    for stem in STANDALONE_IMAGES:
        image = extracted.get(stem)
        if image is None:
            report.add(f"avb_{stem}", False, error="not in payload")
            continue
        info = avb_info(tools, image)
        detail = {k: info[k] for k in ("algorithm", "flags", "rollback_index", "public_key_sha1")}
        if stem in VBMETA_IMAGES:
            ok = info["algorithm"] == AVB_ALGORITHM and info["public_key_sha1"] == key_sha1
            if stem == "vbmeta":
                ok = ok and info["flags"] == str(AVB_ROOT_FLAGS)
            run([tools("avbtool"), "verify_image", "--image", image, "--key", pub_pem,
                 "--follow_chain_partitions"], env=tools.env())
        else:
            ok = "Footer version" in info["raw"] or "Descriptors" in info["raw"]
        report.add(f"avb_{stem}", ok, **detail)
        staged = tf.path(f"IMAGES/{stem}.img")
        if staged.is_file() and stem in VBMETA_IMAGES:
            report.add(f"avb_target_files_{stem}_equals_payload", sha256_file(staged) == sha256_file(image))

def check_recovery_trust(report, args, tf):
    with zipfile.ZipFile(tf.path(OTA_CERTS_APK_PATH)) as certs:
        trusted = sorted({hashlib.sha256(ssl.PEM_cert_to_DER_cert(certs.read(name).decode())).hexdigest()
                          for name in certs.namelist() if name.endswith(".pem")})
    release = cert_sha256(args.ota_cert)
    report.add("recovery_trusts_only_the_ota_release_certificate", trusted == [release],
               recovery_cert_sha256=trusted, release_cert_sha256=release)


def check_sepolicy(report, tools, tf):
    paths = [tf.path(f"{part}/etc/selinux/precompiled_sepolicy") for part in ("VENDOR", "ODM")]
    policies = [path for path in paths if path.is_file()]
    if not report.add("compiled_device_sepolicy_installed", len(policies) == 1, count=len(policies)):
        return
    policy = policies[0]
    with policy.open("rb") as stream:
        magic = stream.read(4)
    domains = run([tools("sepolicy-analyze"), policy, "permissive"], env=tools.env()).splitlines()
    report.add("selinux_precompiled_policy_has_no_permissive_domains", magic == b"\x8c\xff\x7c\xf9" and not domains,
               permissive_domains=domains, sha256=sha256_file(policy))
    cil_path = tf.path(VENDOR_SEPOLICY_CIL_TF_PATH)
    cil = cil_path.read_text() if cil_path.is_file() else ""
    required_cil = (
        '(genfscon sysfs "/class/qcom-battery" (u object_r vendor_sysfs_battery_supply',
        '(genfscon sysfs "/devices/platform/soc/soc:qcom,pmic_glink/soc:qcom,pmic_glink:qcom,ucsi/typec" (u object_r sysfs_typec',
        "(allow batterysecret vendor_sysfs_battery_supply (file (",
        "(allow batterysecret sysfs_typec_",
    )
    missing_cil = [snippet for snippet in required_cil if snippet not in cil]
    report.add("xiaomi_fastcharge_sepolicy_labels_and_rules", not missing_cil, missing=missing_cil)
    vfc_path = tf.path(VENDOR_FILE_CONTEXTS_TF_PATH)
    vfc = vfc_path.read_text() if vfc_path.is_file() else ""
    sphal_ok = bool(re.search(r"^/\(odm\|vendor\)/lib64/libcamxexternalformatutils\\\.so\s+u:object_r:same_process_hal_file:s0$", vfc, re.M))
    report.add("camera_sphal_odm_file_contexts", sphal_ok)
    atfwd_path = tf.path(VENDOR_ATFWD_SECCOMP_TF_PATH)
    atfwd_lines = {l.strip() for l in atfwd_path.read_text().splitlines()} if atfwd_path.is_file() else set()
    report.add("atfwd_seccomp_allows_lseek", "lseek: 1" in atfwd_lines)


def read_cpio(path, capture=()):
    entries = {}
    with open(path, "rb") as src:
        while True:
            header = src.read(110)
            if len(header) < 110 or header[:6] != b"070701":
                break
            fields = [int(header[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
            mode, size, namesize = fields[1], fields[6], fields[11]
            name = src.read(namesize).rstrip(b"\0").decode()
            src.read((-(110 + namesize)) % 4)
            if name == "TRAILER!!!":
                break
            h, left, kept = hashlib.sha256(), size, bytearray()
            while left:
                block = src.read(min(CHUNK, left))
                if not block:
                    raise ValueError(f"Truncated CPIO member {name!r} in {path}")
                h.update(block)
                if name in capture:
                    kept += block
                left -= len(block)
            src.read((-size) % 4)
            if stat.S_ISREG(mode):
                entries[Path(name).as_posix()] = h.hexdigest()
                if name in capture:
                    entries["bytes:" + name] = bytes(kept)
    return entries


def unpack(tools, image, out):
    shutil.rmtree(out, ignore_errors=True)
    run([tools("unpack_bootimg"), "--boot_img", image, "--out", out], env=tools.env())


def decompress_ramdisk(tools, fragment, out):
    with fragment.open("rb") as stream:
        magic = stream.read(4)
    if magic[:2] == b"\x1f\x8b":
        with open(out, "wb") as dst:
            subprocess.run(["gzip", "-dc", str(fragment)], stdout=dst, check=True)
    elif magic in (b"\x04\x22\x4d\x18", b"\x02\x21\x4c\x18"):
        with open(out, "wb") as dst:
            subprocess.run([tools("lz4"), "-dc", str(fragment)], stdout=dst, check=True)
    elif magic[:2] == b"07":
        shutil.copyfile(fragment, out)
    else:
        raise ValueError(f"Unknown ramdisk compression {magic.hex()} in {fragment.name}")


def _parse_ko_elf(data):
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shstr_off, shstr_sz = struct.unpack_from("<QQ", data, e_shoff + e_shstrndx * e_shentsize + 24)
    shstr = data[shstr_off:shstr_off + shstr_sz]
    by_idx, by_name = [], {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name = struct.unpack_from("<I", data, off)[0]
        sh_offset, sh_size = struct.unpack_from("<QQ", data, off + 24)
        sh_entsize = struct.unpack_from("<Q", data, off + 56)[0]
        name = shstr[sh_name:shstr.index(b"\x00", sh_name)].decode("utf-8", "ignore")
        rec = (name, sh_offset, sh_size, sh_entsize)
        by_idx.append(rec)
        by_name[name] = rec
    return by_idx, by_name


def _verify_gki_kmi_crcs(symvers_path, ko_paths):
    vmlinux_crcs = {}
    for line in symvers_path.read_text().splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            vmlinux_crcs[parts[1]] = int(parts[0], 16)
    mod_crcs = {}
    req_map = []
    for p in ko_paths:
        data = p.read_bytes()
        by_idx, by_name = _parse_ko_elf(data)
        if ".symtab" in by_name and ".strtab" in by_name:
            _, sym_off, sym_sz, entsz = by_name[".symtab"]
            _, str_off, str_sz, _ = by_name[".strtab"]
            strtab = data[str_off:str_off + str_sz]
            for pos in range(sym_off, sym_off + sym_sz, entsz):
                st_name, _, _, st_shndx, st_value, _ = struct.unpack_from("<IBBHQQ", data, pos)
                name = strtab[st_name:strtab.index(b"\x00", st_name)].decode("utf-8", "ignore")
                if name.startswith("__crc_"):
                    if st_shndx == 0xFFF1:
                        mod_crcs.setdefault(name[6:], st_value & 0xFFFFFFFF)
                    elif st_shndx < len(by_idx):
                        mod_crcs.setdefault(name[6:], struct.unpack_from("<I", data, by_idx[st_shndx][1] + st_value)[0])
        if "__versions" in by_name:
            _, off, sz, _ = by_name["__versions"]
            for pos in range(off, off + sz, 64):
                crc = struct.unpack_from("<Q", data, pos)[0] & 0xFFFFFFFF
                sym = data[pos + 8:pos + 64].split(b"\x00", 1)[0].decode("utf-8", "ignore")
                if sym:
                    req_map.append((p.name, sym, crc))
    mismatches, missing = [], []
    for mod, sym, crc in req_map:
        if sym in vmlinux_crcs:
            if vmlinux_crcs[sym] != crc:
                mismatches.append(f"{mod}:{sym}")
        elif sym in mod_crcs:
            if mod_crcs[sym] != crc:
                mismatches.append(f"{mod}:{sym}")
        else:
            missing.append(f"{mod}:{sym}")
    return len(req_map), mismatches, missing


def check_kernel_links(report, args, tools, work, extracted, tf, source, gki=None):
    stock = source["stock_kernel"]["images"]
    boot_dir = work / "unpack_boot"
    unpack(tools, extracted["boot"], boot_dir)
    kernel = boot_dir / "kernel"
    if gki:
        expected_img = gki["root"] / "Image"
        expected_sha = gki["hashes"]["Image"]
        expected_size = expected_img.stat().st_size
    else:
        expected_sha = stock["Image"]["sha256"]
        expected_size = stock["Image"]["bytes"]
    report.add("boot_kernel_equals_retained_stock_image", sha256_file(kernel) == expected_sha
               and kernel.stat().st_size == expected_size, expected_sha256=expected_sha,
               kernel_release=gki["provenance"]["gki_release"] if gki else source["stock_kernel"]["provenance"]["kernel_release"])
    dtbo = stock["dtbo.img"]
    if gki and "dtbo.img" in gki["hashes"]:
        gki_dtbo_sz = (gki["root"] / "dtbo.img").stat().st_size
        report.add("dtbo_prefix_equals_retained_stock_dtbo",
                   sha256_file(extracted["dtbo"], gki_dtbo_sz) == gki["hashes"]["dtbo.img"],
                   dtbo_sha256=gki["hashes"]["dtbo.img"])
    else:
        report.add("dtbo_prefix_equals_retained_stock_dtbo",
                   sha256_file(extracted["dtbo"], dtbo["bytes"]) == dtbo["sha256"], stock_sha256=dtbo["sha256"])
    vendor_dir = work / "unpack_vendor_boot"
    unpack(tools, extracted["vendor_boot"], vendor_dir)
    dtb = vendor_dir / "dtb"
    gki_dtb_keys = [k for k in gki["hashes"] if k.startswith("dtb/") and k.endswith(".dtb")] if gki else []
    if gki_dtb_keys:
        dtb_key = gki_dtb_keys[0]
        report.add("vendor_boot_dtb_equals_retained_stock_dtb",
                   dtb.is_file() and sha256_file(dtb) == gki["hashes"][dtb_key],
                   dtb_key=dtb_key, expected_sha256=gki["hashes"][dtb_key])
    else:
        report.add("vendor_boot_dtb_equals_retained_stock_dtb",
                   dtb.is_file() and sha256_file(dtb) == stock["dtb/stock.dtb"]["sha256"])
    ramdisk_files = {}
    ramdisk_meta = ("lib/modules/modules.load", "lib/modules/modules.blocklist")
    for fragment in sorted(vendor_dir.glob("vendor_ramdisk*")):
        cpio = work / f"{fragment.name}.cpio"
        decompress_ramdisk(tools, fragment, cpio)
        ramdisk_files.update(read_cpio(cpio, ramdisk_meta))
        cpio.unlink()
    for tree, prefix in (("vendor_ramdisk", ""), ("vendor_dlkm", "VENDOR_DLKM/"), ("system_dlkm", "SYSTEM_DLKM/")):
        staged_ko_records = (
            {k[len(tree) + 1:]: {"sha256": v} for k, v in gki["hashes"].items()
             if k.startswith(tree + "/") and k.endswith(".ko")}
            if gki else {}
        )
        if staged_ko_records:
            records = staged_ko_records
        else:
            records = {k[len(tree) + 1:]: v for k, v in stock.items() if k.startswith(tree + "/")}
        bad = []
        for relative, record in records.items():
            if tree == "vendor_ramdisk":
                actual = ramdisk_files.get(relative)
            else:
                path = tf.path(prefix + relative)
                actual = sha256_file(path) if path.is_file() else None
            if actual != record["sha256"]:
                bad.append(relative)
        report.add(f"{tree}_modules_equal_retained_stock", not bad, expected=len(records),
                   mismatched=len(bad), examples=bad[:10])
    if gki:
        symvers = gki["root"] / "vmlinux.symvers"
        stock_root = Path(args.rom_dir) / "vendor/xiaomi/houji/kernel/stock"
        vram_dir = gki["root"] / "vendor_ramdisk" if (gki["root"] / "vendor_ramdisk").is_dir() else stock_root / "vendor_ramdisk"
        vdlkm_dir = gki["root"] / "vendor_dlkm" if (gki["root"] / "vendor_dlkm").is_dir() else stock_root / "vendor_dlkm"
        ko_paths = (sorted((gki["root"] / "system_dlkm").rglob("*.ko"))
                    + sorted(vram_dir.rglob("*.ko"))
                    + sorted(vdlkm_dir.rglob("*.ko")))
        refs, mismatches, missing = _verify_gki_kmi_crcs(symvers, ko_paths)
        report.add("gki_kmi_symbol_crc_parity", not mismatches and not missing and refs > 0,
                   total_symbol_refs=refs, modules=len(ko_paths),
                   mismatches=mismatches[:10], missing=missing[:10])
        kernel_bytes = kernel.read_bytes()
        krel = gki["provenance"]["gki_release"]
        if krel.startswith("6.12."):
            vdlkm_msm_drm = vdlkm_dir / "lib/modules/msm_drm.ko"
            report.add("gki_drm_clone_compat",
                       vdlkm_msm_drm.is_file() and b"failed valid clone check" in kernel_bytes,
                       note="Unmodified GKI 6.12 paired with source-built 6.12 msm_drm.ko CWB clone support")
        else:
            report.add("gki_drm_clone_compat", b"failed valid clone check" not in kernel_bytes,
                       note="Upstream Linux ffb55ddf2685 breaks Qualcomm 6.1.68 msm_drm.ko CWB clone mode on houji")
    kcfg = Path(args.rom_dir) / "device/xiaomi/houji/configs/kernel"
    v_bl_cfg = kcfg / "modules.blocklist.houji"
    s_bl_cfg = kcfg / "system_dlkm.modules.blocklist"
    if v_bl_cfg.is_file() and s_bl_cfg.is_file():
        expected_v_bl = {l.split()[1].replace("-", "_") for l in v_bl_cfg.read_text().splitlines()
                         if l.strip().startswith("blocklist ")}
        expected_s_bl = {l.split()[1].replace("-", "_") for l in s_bl_cfg.read_text().splitlines()
                         if l.strip().startswith("blocklist ")}
        vb_bl_txt = ramdisk_files.get("bytes:lib/modules/modules.blocklist", b"").decode()
        vb_load = {Path(l.strip()).stem.replace("-", "_")
                   for l in ramdisk_files.get("bytes:lib/modules/modules.load", b"").decode().splitlines() if l.strip()}
        vb_bl = {l.split()[1].replace("-", "_") for l in vb_bl_txt.splitlines()
                 if l.strip().startswith("blocklist ")}
        vd_load_p = tf.path("VENDOR_DLKM/lib/modules/modules.load")
        vd_bl_p = tf.path("VENDOR_DLKM/lib/modules/modules.blocklist")
        sd_bl_p = tf.path("VENDOR_DLKM/lib/modules/system_dlkm.modules.blocklist")
        sd_loads = sorted(tf.path("SYSTEM_DLKM/lib/modules").glob("*/modules.load"))
        vd_bl_txt = vd_bl_p.read_text() if vd_bl_p.is_file() else ""
        sd_bl_txt = sd_bl_p.read_text() if sd_bl_p.is_file() else ""
        bad_bl_syntax = []
        for label, txt in (("vendor_boot", vb_bl_txt), ("vendor_dlkm", vd_bl_txt), ("system_dlkm", sd_bl_txt)):
            for idx, raw in enumerate(txt.splitlines(), 1):
                s = raw.strip()
                if not s:
                    continue
                if s.startswith("#"):
                    if "blocklist" in raw.lower():
                        bad_bl_syntax.append(f"{label}:{idx}:comment-contains-blocklist")
                elif not re.fullmatch(r"blocklist [A-Za-z0-9_-]+", s):
                    bad_bl_syntax.append(f"{label}:{idx}:{s}")
        vd_load = {Path(l.strip()).stem.replace("-", "_") for l in vd_load_p.read_text().splitlines()
                   if l.strip()} if vd_load_p.is_file() else {"<missing>"}
        vd_bl = {l.split()[1].replace("-", "_") for l in vd_bl_txt.splitlines()
                 if l.strip().startswith("blocklist ")}
        sd_bl = {l.split()[1].replace("-", "_") for l in sd_bl_txt.splitlines()
                 if l.strip().startswith("blocklist ")}
        sd_load = {Path(l.strip()).stem.replace("-", "_") for p in sd_loads
                   for l in p.read_text().splitlines() if l.strip()} if sd_loads else {"<missing>"}
        leaked = sorted((vb_load & expected_v_bl) | (vd_load & expected_v_bl) | (sd_load & expected_s_bl))
        missing_bl = sorted((expected_v_bl - vb_bl) | (expected_v_bl - vd_bl) | (expected_s_bl - sd_bl))
        tipc_ipc_ok = (({"tipc", "diag"} <= sd_load or {"tipc", "tipc_diag"} <= sd_load)
                       and not ({"tipc", "diag", "tipc_diag"} & (sd_bl | expected_s_bl)))
        report.add("houji_kernel_module_purification",
                   not leaked and not missing_bl and not bad_bl_syntax and tipc_ipc_ok,
                   vendor_blocklisted=len(expected_v_bl), system_dlkm_blocklisted=len(expected_s_bl),
                   tipc_ipc_modules_enabled=tipc_ipc_ok,
                   leaked_in_load=leaked[:10], missing_in_blocklist=missing_bl[:10],
                   bad_blocklist_syntax=bad_bl_syntax[:10])


def check_recovery_binary(report, tools, work, tf, extracted, manifest):
    """The installed recovery (payload) must carry the untrusted-install menu and match target-files."""
    wanted = (RECOVERY_BINARY_PATH, RECOVERY_OTACERTS_PATH,
              RECOVERY_BOOTCTRL_PATH, RECOVERY_BOOTCTRL_RC_PATH, RECOVERY_BOOTCTRL_VINTF_PATH)
    found = {}
    for stem in ("recovery", "vendor_boot"):
        if stem not in extracted:
            continue
        out = work / f"unpack_{stem}_recovery_binary"
        unpack(tools, extracted[stem], out)
        for fragment in sorted(p for p in out.glob("*ramdisk*") if p.is_file() and not p.is_symlink()):
            cpio = work / f"{stem}_{fragment.name}.cpio"
            decompress_ramdisk(tools, fragment, cpio)
            files = read_cpio(cpio, wanted)
            cpio.unlink()
            for name in wanted:
                if "bytes:" + name in files and name not in found:
                    found[name] = (files["bytes:" + name], stem)
    binary = found.get(RECOVERY_BINARY_PATH)
    report.add("payload_recovery_contains_recovery_binary", binary is not None)
    if binary:
        data, stem = binary
        missing = [h.decode() for h in RECOVERY_MENU_HEADERS if h not in data]
        staged = tf.path(RECOVERY_TF_BINARY_PATH)
        report.add("payload_recovery_binary_has_untrusted_install_menu_headers", not missing,
                   missing_headers=missing, found_in_image=stem, sha256=hashlib.sha256(data).hexdigest())
        report.add("payload_recovery_binary_equals_target_files_recovery",
                   staged.is_file() and sha256_file(staged) == hashlib.sha256(data).hexdigest(),
                   target_files_sha256=sha256_file(staged) if staged.is_file() else None)
    certs = found.get(RECOVERY_OTACERTS_PATH)
    staged_certs = tf.path(OTA_CERTS_APK_PATH)
    report.add("payload_recovery_otacerts_equals_target_files_release_only_certs",
               certs is not None and staged_certs.is_file() and
               hashlib.sha256(certs[0]).hexdigest() == sha256_file(staged_certs))
    rec_bc = found.get(RECOVERY_BOOTCTRL_PATH)
    rec_bc_data = rec_bc[0] if rec_bc else b""
    rec_bc_elf = rec_bc_data[:6] == b"\x7fELF\x02\x01" and rec_bc_data[18:20] == b"\xb7\x00"
    report.add("payload_recovery_contains_qti_boot_control_hal",
               rec_bc_elf and RECOVERY_BOOTCTRL_RC_PATH in found and RECOVERY_BOOTCTRL_VINTF_PATH in found,
               found_in_image=rec_bc[1] if rec_bc else None)
    v_bc = tf.path(VENDOR_BOOTCTRL_TF_PATH)
    v_bc_hdr = v_bc.read_bytes()[:20] if v_bc.is_file() else b""
    v_bc_elf = v_bc_hdr[:6] == b"\x7fELF\x02\x01" and v_bc_hdr[18:20] == b"\xb7\x00"
    report.add("vendor_contains_qti_boot_control_hal",
               v_bc_elf and tf.path(VENDOR_BOOTCTRL_RC_TF_PATH).is_file() and
               tf.path(VENDOR_BOOTCTRL_VINTF_TF_PATH).is_file())
    report.artifacts["recovery_source"] = {
        "project": RECOVERY_PROJECT, "manifest_sha": manifest["projects"].get(RECOVERY_PROJECT),
        "recovery_image_sha256": sha256_file(extracted["recovery"]) if "recovery" in extracted else None,
        "bootable_image_sha256": sha256_file(extracted["boot"]) if "boot" in extracted else None}


def probe_apks(tools, apk, platform_sdk):
    badging = run([tools("aapt2"), "dump", "badging", apk])
    package = re.search(r"package: name='([^']+)'", badging)
    shared = re.search(r"sharedUserId='([^']+)'", badging)
    sdk = re.search(r"^targetSdkVersion:'(\d+)'", badging, re.M)
    permissions = sorted(set(re.findall(r"^uses-permission(?:-sdk-23)?: name='([^']+)'", badging, re.M)))
    try:
        certs = run([tools("apksigner"), "verify", "--min-sdk-version", platform_sdk,
                     "--max-sdk-version", platform_sdk, "--print-certs", apk], env=tools.env())
        signature_error = None
    except subprocess.CalledProcessError as error:
        certs, signature_error = "", error.output
    signers = sorted(set(re.findall(r"certificate SHA-256 digest: ([0-9a-f]{64})", certs)))
    return {"package": package[1] if package else None, "shared_user_id": shared[1] if shared else None,
            "signature_error": signature_error,
            "target_sdk": int(sdk[1]) if sdk else None, "permissions": permissions, "signers": signers,
            "debuggable": "application-debuggable" in badging, "test_only": "testOnly='-1'" in badging}


def check_microg_jni(report, tf, apk):
    with zipfile.ZipFile(tf.path(apk)) as archive:
        expected = {}
        for member in archive.namelist():
            if member.startswith(MICROG_JNI_ARCHIVE_ROOT) and member.endswith(".so"):
                with archive.open(member) as stream:
                    expected[MICROG_JNI_ROOT + Path(member).name] = hashlib.file_digest(stream, "sha256").hexdigest()
    installed = {}
    invalid = []
    for name in sorted(n for n in tf.names if n.startswith(MICROG_JNI_ROOT) and n.endswith(".so")):
        with tf.path(name).open("rb") as stream:
            header = stream.read(20)
            if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\xb7\x00":
                invalid.append(name)
        installed[name] = sha256_file(tf.path(name))
    report.add("microg_gmscore_bundled_arm64_libraries", bool(expected) and expected == installed and not invalid,
               expected=expected, installed=installed, invalid_architecture=invalid)


def spoof_permission_paths(package):
    return (f"PRODUCT/etc/permissions/privapp-permissions-{package}.xml",
            f"PRODUCT/etc/default-permissions/default-permissions-{package}.xml")


def requested_spoof_certificate(tools, apk):
    manifest = run([tools("aapt2"), "dump", "xmltree", apk, "--file", "AndroidManifest.xml"])
    metadata = re.search(r'android:name\(\w+\)="fake-signature"[^\n]*\n\s*A: [^\n]*android:value\(\w+\)=@([0-9a-fx]+)', manifest)
    if not metadata:
        return None
    resources = run([tools("aapt2"), "dump", "resources", apk])
    certificate = re.search(rf'^\s*resource {metadata[1]} string/\S+\n\s*\(\) "([0-9a-f]+)"', resources, re.M)
    return certificate[1] if certificate else None


def check_apks(report, args, tools, tf, source):
    release_signers = {cert_sha256(Path(args.keys_dir) / f"{name}.x509.pem"): name for name in SIGNING_KEYS}
    allowed = dict(release_signers)
    test_digest = cert_sha256(Path(args.rom_dir) / "build/make/target/product/security/testkey.x509.pem")
    for name, record in source["apk"].items():
        allowed.setdefault(record["signer_sha256"], "upstream F-Droid" if name == "FDroid" else "upstream microG")
    allowed[VANADIUM_SIGNER] = "GrapheneOS Vanadium"
    for digest in YASR_SIGNERS:
        allowed[digest] = "YAAP YASR upstream"
    microg = {package: source["apk"][name] for name, package in MICROG_PACKAGES.items()}
    apks = sorted(n for n in tf.names if n.endswith(".apk") and n.split("/", 1)[0] in APK_ROOTS)
    platform_sdk = tf.props("SYSTEM/build.prop")["ro.build.version.sdk"]
    report.add("target_files_installed_apks_found", bool(apks), count=len(apks))
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
        probed = list(pool.map(lambda n: (n, probe_apks(tools, tf.path(n), platform_sdk)), apks))
    sdk_markers = {}
    rows, failures = {}, []
    for name, row in probed:
        package = row["package"]
        problems = []
        if not package:
            problems.append("package identity missing")
        if row["signature_error"]:
            problems.append(row["signature_error"])
        if test_digest in row["signers"]:
            problems.append("signed with AOSP test key")
        if row["debuggable"] or row["test_only"]:
            problems.append("debuggable or testOnly")
        if row["shared_user_id"] and GOOGLE_SHARED_USER.match(row["shared_user_id"]):
            problems.append("google shared user id")
        sha = sha256_file(tf.path(name))
        with zipfile.ZipFile(tf.path(name)) as archive:
            markers = sorted(member for member in archive.namelist()
                             if GOOGLE_SDK_MARKER.fullmatch(Path(member).name))
        if markers and name not in (YASR_APK, TALKBACK_APK):
            sdk_markers[name] = markers
        aperture_shim = (name == APERTURE_LENS_APK and package == APERTURE_LENS_ACTIVITY and
                         [release_signers.get(digest) for digest in row["signers"]] == ["releasekey"])
        module = Path(name).stem
        vanadium = (name == f"PRODUCT/app/{module}/{module}.apk" and
                    VANADIUM_APKS.get(module) == (package, sha) and row["signers"] == [VANADIUM_SIGNER])
        yasr = (name == YASR_APK and package == YASR_PACKAGE and sha == YASR_SHA256 and
                row["signers"] == YASR_SIGNERS)
        if package in microg:
            if row["signers"] != [microg[package]["signer_sha256"]]:
                problems.append("microG package without upstream signer")
        elif not vanadium and not yasr:
            if not row["signers"] or not set(row["signers"]) <= release_signers.keys():
                problems.append("not signed by this release")
            if package and GOOGLE_NAMESPACE.match(package) and package not in AOSP_GOOGLE_NAMED and not aperture_shim:
                problems.append("Google/GMS package id")
        foss_setup_wizard = (package == "org.lineageos.setupwizard" and
                             len(row["signers"]) == 1 and release_signers.get(row["signers"][0]) == "platform")
        if GOOGLE_FILE.search(name) and not (foss_setup_wizard or vanadium):
            problems.append("Google prebuilt file name")
        rows[name] = {"package": package, "sha256": sha, "signers": row["signers"],
                      "permissions": row["permissions"], "target_sdk": row["target_sdk"]}
        if problems:
            failures.append({"apk": name, "package": package, "problems": problems})
    report.add("apk_set_signers_permissions_and_gms_free", not failures, failures=failures, apk_count=len(rows))
    report.add("no_play_services_or_firebase_sdk_markers_in_installed_apks", not sdk_markers, matches=sdk_markers)
    report.add("foss_vanadium_preserved", all(
        rows.get(f"PRODUCT/app/{module}/{module}.apk", {}).get("sha256") == expected_sha
        for module, (_, expected_sha) in VANADIUM_APKS.items()), modules=sorted(VANADIUM_APKS))
    spoof_permission = "android.permission.FAKE_PACKAGE_SIGNATURE"
    requested = {}
    for label, package in MICROG_PACKAGES.items():
        record = source["apk"][label]
        matches = [path for path, row in rows.items() if row["package"] == package]
        identity_ok = len(matches) == 1 and rows[matches[0]]["sha256"] == record["sha256"]
        report.add(f"microg_{label}_installed", identity_ok, paths=matches,
                   expected_signer_sha256=record["signer_sha256"])
        if label == "GmsCore" and identity_ok:
            check_microg_jni(report, tf, matches[0])
        if label not in ("GmsCore", "FakeStore"):
            continue
        paths = spoof_permission_paths(package)
        def grants(path):
            root = ElementTree.parse(tf.path(path)).getroot()
            return any(node.get("package") == package and
                       any(p.get("name") == spoof_permission for p in node.findall("permission")) for node in root)
        privileged = identity_ok and matches[0].startswith("PRODUCT/priv-app/")
        report.add(f"microg_{label}_privileged_spoofing_permissions", privileged and all(grants(p) for p in paths),
                   paths=paths)
        if identity_ok:
            requested[label] = requested_spoof_certificate(tools, tf.path(matches[0]))
    source_path = Path(args.rom_dir) / "frameworks/base/services/core/java/com/android/server/pm/ComputerEngine.java"
    framework = source_path.read_text()
    cert = re.search(r'MICROG_REAL_SIGNATURE\s*=\s*new Signature\("([0-9a-f]+)"\)', framework)
    signer = hashlib.sha256(bytes.fromhex(cert[1])).hexdigest() if cert else None
    predicates = ('!p.getPackageName().equals("com.android.vending")',
                  '!p.getPackageName().equals("com.google.android.gms")',
                  'new Signature[]{MICROG_REAL_SIGNATURE}', '!fakeSignature.equals(MICROG_FAKE_SIGNATURE)',
                  'generateFakeSignature(p).ifPresent')
    report.add("framework_has_package_and_signer_pinned_spoofing", signer == microg["com.google.android.gms"]["signer_sha256"]
               and all(predicate in framework for predicate in predicates) and "SYSTEM/framework/services.jar" in tf.names,
               signer_sha256=signer)
    fake_cert = re.search(r'MICROG_FAKE_SIGNATURE\s*=\s*new Signature\("([0-9a-f]+)"\)', framework)
    report.add("microg_requests_only_framework_allowlisted_certificate", bool(fake_cert) and
               set(requested) == {"GmsCore", "FakeStore"} and set(requested.values()) == {fake_cert[1]},
               packages=sorted(requested), fake_certificate_sha256=hashlib.sha256(bytes.fromhex(fake_cert[1])).hexdigest()
               if fake_cert else None)
    sysconfig = ElementTree.parse(tf.path(MICROG_SYSCONFIG)).getroot()
    exemptions = {node.tag for node in sysconfig if node.get("package") == MICROG_PACKAGES["GmsCore"]}
    report.add("microg_system_exemptions_installed",
               {"allow-in-power-save", "allow-in-data-usage-save", "allow-unthrottled-location"} <= exemptions,
               entries=sorted(exemptions))
    for package in ("org.lineageos.aperture", "org.lineageos.aperture.overlay.houji"):
        paths = [path for path, row in rows.items() if row["package"] == package]
        report.add(f"apk_{package}_installed", len(paths) == 1, paths=paths)
    return {"apks": rows, "signer_allowlist": dict(sorted(allowed.items()))}


def check_released_apk_bytes(report, tools, work, tf, extracted, summary):
    packages = set(MICROG_PACKAGES.values()) | {
        "org.lineageos.aperture", "org.lineageos.aperture.overlay.houji",
        EUICC_PACKAGE, ESIM_SWITCHER_PACKAGE, ESIM_OVERLAY_PACKAGE,
    }
    audited_apks = {name: row["sha256"] for name, row in summary.get("apks", {}).items()
                    if row["package"] in packages}
    audited_files = audited_apks | {
        name: sha256_file(tf.path(name)) for name in tf.names
        if name.startswith(MICROG_JNI_ROOT) and name.endswith(".so")
    }
    config_files = [MICROG_SYSCONFIG, EUICC_JNI, EUICC_ALLOWLIST, EUICC_FEATURE_XML, ESIM_SWITCHER_ALLOWLIST]
    for package in (MICROG_PACKAGES["GmsCore"], MICROG_PACKAGES["FakeStore"]):
        config_files.extend(spoof_permission_paths(package))
    audited_files.update((name, sha256_file(tf.path(name))) for name in config_files)
    mismatches = []
    with tempfile.TemporaryDirectory(prefix="image-apks-", dir=work) as scratch:
        scratch = Path(scratch)
        erofs_roots = {}
        for name, expected in sorted(audited_files.items()):
            partition, path = name.split("/", 1)
            part_key = partition.lower()
            img = extracted[part_key]
            if is_erofs_image(img):
                if part_key not in erofs_roots:
                    part_dir = scratch / part_key
                    part_dir.mkdir(parents=True, exist_ok=True)
                    run([tools("fsck.erofs"), f"--extract={part_dir}", "--overwrite", img], env=tools.env())
                    erofs_roots[part_key] = part_dir
                target = resolve_in_extracted_root(erofs_roots[part_key], path)
                if not target.is_file() or sha256_file(target) != expected:
                    mismatches.append(name)
            else:
                dest = scratch / "entry"
                run([tools("debugfs"), "-R", f'dump "/{path}" "{dest}"', img], env=tools.env())
                if not dest.is_file() or sha256_file(dest) != expected:
                    mismatches.append(name)
                dest.unlink(missing_ok=True)
    report.add("microg_aperture_esim_apk_jni_and_config_bytes_in_payload_filesystems",
               len(audited_apks) == len(packages) and not mismatches,
               checked_files=sorted(audited_files), mismatches=mismatches)


def check_build_props(report, args, tf):
    system = tf.props("SYSTEM/build.prop")
    props = {
        "type": system.get("ro.build.type"),
        "tags": system.get("ro.build.tags"),
        "release": system.get("ro.system.build.version.release", system.get("ro.build.version.release")),
        "security_patch": system.get("ro.build.version.security_patch"),
        "fingerprint": system.get("ro.build.fingerprint", system.get("ro.system.build.fingerprint")),
        "device": system.get("ro.product.system.device", system.get("ro.product.device")),
    }
    ok = (props["type"] == "user" and props["tags"] == "release-keys"
          and props["release"] == args.expect_android_release
          and re.fullmatch(r"\d{4}-\d{2}-\d{2}", props["security_patch"] or "") is not None
          and props["device"] == "houji")
    report.add("system_build_is_user_release_keys_android_17_houji", ok, **props)
    for partition in ("VENDOR", "PRODUCT", "SYSTEM_EXT"):
        path = tf.path(f"{partition}/build.prop")
        if path.is_file():
            p = tf.props(f"{partition}/build.prop")
            report.add(f"{partition.lower()}_not_debuggable", p.get("ro.debuggable", "0") == "0"
                       and "test-keys" not in p.get("ro.build.tags", ""), gating=True)
    misc = tf.path("META/misc_info.txt").read_text()
    report.add("target_files_misc_info_avb_enabled", "avb_enable=true" in misc)
    leaked_daemons = sorted(d for d in PRUNED_USERSPACE_DAEMONS if d in tf.names)
    mtd_stub_kept = "VENDOR/lib64/vendor.xiaomi.hardware.aidl.mtdservice-V1-ndk_platform.so" in tf.names
    report.add("userspace_dead_daemons_pruned", not leaked_daemons and mtd_stub_kept,
               leaked_daemons=leaked_daemons, mtd_aidl_stub_retained=mtd_stub_kept)
    prod_prop_path = tf.path("PRODUCT/etc/build.prop") if "PRODUCT/etc/build.prop" in tf.names else tf.path("PRODUCT/build.prop")
    prod_props = tf.props("PRODUCT/etc/build.prop") if prod_prop_path.name == "build.prop" and "PRODUCT/etc/build.prop" in tf.names else (
        tf.props("PRODUCT/build.prop") if tf.path("PRODUCT/build.prop").is_file() else {}
    )
    health_xml = tf.path(VENDOR_HEALTH_VINTF_TF_PATH).read_text() if tf.path(VENDOR_HEALTH_VINTF_TF_PATH).is_file() else ""
    unlock_details = {
        "blur_enabled": system.get("ro.surface_flinger.supports_background_blur") == "1"
                        and prod_props.get("ro.launcher.blur.appLaunch") != "0",
        "ssr_ramdumps_disabled": system.get("persist.vendor.ssr.enable_ramdumps") == "0",
        "mglru_all": system.get("persist.device_config.mglru_native.lru_gen_config") == "all",
        "powershare_installed": "VENDOR/bin/hw/vendor.lineage.powershare-service.default" in tf.names
                                and tf.path(VENDOR_POWERSHARE_VINTF_TF_PATH).is_file(),
        "xiaomi_health_v5_installed": "VENDOR/bin/hw/android.hardware.health-service.xiaomi" in tf.names
                                      and "VENDOR/bin/hw/android.hardware.health-service.qti" not in tf.names
                                      and "<version>5</version>" in health_xml,
    }
    report.add("flagship_hardware_and_ux_unlocks", all(unlock_details.values()), **unlock_details)
    return props


def check_vintf(report, args, tools, tf):
    needed = ["META/kernel_configs.txt", "META/kernel_version.txt"]
    missing = [n for n in needed if n not in tf.names]
    report.add("target_files_has_kernel_vintf_inputs", not missing, missing=missing)
    if missing:
        return
    run([tools("check_target_files_vintf"), args.target_files], env=tools.env())
    report.add("check_target_files_vintf_with_kernel_inputs", True)


def check_apex_keys(report, args, tools, work, tf):
    rom = Path(args.rom_dir)
    entries = {}
    for line in tf.path("META/apexkeys.txt").read_text().splitlines():
        row = dict(token.split("=", 1) for token in shlex.split(line))
        entries[(row["partition"].upper(), row["name"])] = row
    sdk = tf.props("SYSTEM/build.prop")["ro.build.version.sdk"]
    installed = sorted(name for name in tf.names if re.fullmatch(r"[A-Z_]+/apex/[^/]+\.c?apex", name))
    with tempfile.TemporaryDirectory(prefix="apex-", dir=work) as scratch:
        scratch = Path(scratch)

        def probe(name):
            part, _, filename = name.split("/", 2)
            key_entry = entries[part, Path(filename).stem + ".apex"]
            path = tf.path(name)
            image_dir = scratch / part / filename
            image_dir.mkdir(parents=True)
            inner = path
            if path.suffix == ".capex":
                with zipfile.ZipFile(path) as outer:
                    inner = Path(outer.extract("original_apex", image_dir))
            with zipfile.ZipFile(inner) as apex:
                pubkey = apex.read("apex_pubkey")
                payload = Path(apex.extract("apex_payload.img", image_dir))
            try:
                info = avb_info(tools, payload)
                run([tools("avbtool"), "verify_image", "--image", payload], env=tools.env())
                container_signers = []
                for container in dict.fromkeys((path, inner)):
                    cert = run([tools("apksigner"), "verify", "--min-sdk-version", sdk,
                                "--max-sdk-version", sdk, "--print-certs", container], env=tools.env())
                    container_signers.append(re.findall(r"certificate SHA-256 digest: ([0-9a-f]{64})", cert))
                authorized = (hashlib.sha1(pubkey).hexdigest() == info["public_key_sha1"] and
                              all(row and row == container_signers[0] for row in container_signers))
                if key_entry["public_key"] == "PRESIGNED":
                    source = PRESIGNED_APEX_SOURCES.get(name)
                    authorized = authorized and name in PRESIGNED_APEX_SOURCES and (
                        source is None or sha256_file(rom / source) == sha256_file(path))
                else:
                    expected_cert = rom / key_entry["container_certificate"]
                    if key_entry["container_certificate"].startswith("vendor/yaap/signing/keys/"):
                        expected_cert = Path(args.keys_dir) / expected_cert.name
                    authorized = authorized and pubkey == (rom / key_entry["public_key"]).read_bytes() and (
                        container_signers[0] == [cert_sha256(expected_cert)])
                authorized = authorized and (not filename.startswith("com.google.") or filename == WIDEVINE_APEX)
                return name, {"verified": authorized, "payload_public_key_sha256": hashlib.sha256(pubkey).hexdigest(),
                              "container_certificate_sha256": container_signers[0],
                              "key_metadata": {k: key_entry[k] for k in ("public_key", "container_certificate")}}
            finally:
                shutil.rmtree(image_dir)

        def checked(name):
            try:
                return probe(name)
            except (OSError, ValueError, KeyError, zipfile.BadZipFile, subprocess.CalledProcessError) as error:
                return name, {"verified": False, "error": str(error), "output": getattr(error, "output", None)}

        with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
            evidence = dict(pool.map(checked, installed))
    failures = [name for name, row in evidence.items() if not row["verified"]]
    report.add("apex_container_and_payload_signatures_match_build_keys", bool(installed) and not failures,
               count=len(installed), failures=failures,
               proprietary_google_non_gms_drm=[name for name in installed if name.endswith("/" + WIDEVINE_APEX)])
    return evidence


def check_google_modules(report, args, tf):
    info = Path(args.product_out) / "module-info.json"
    if not info.is_file():
        report.add("module_info_has_no_proprietary_google_modules", False, error=f"missing {info}")
        return
    module_paths = json.loads(info.read_text())
    output = "/target/product/houji/"
    installed_files = {top.lower() + "/" + name for top, _, name in
                       (entry.partition("/") for entry in tf.names) if top in APK_ROOTS}
    installed = {name: m for name, m in module_paths.items()
                 if any(output in "/" + p and p.split(output, 1)[1] in installed_files
                        for p in m.get("installed", []))}
    bad = []
    for name, module in sorted(installed.items()):
        paths = module.get("path", [])
        foss_app = (name == "SetupWizard" and paths == ["packages/apps/SetupWizard"]) or (
            name in VANADIUM_APKS and paths == ["external/vanadium"])
        if any(GOOGLE_MODULE_PATH.match(path) for path in paths) or (
                GOOGLE_FILE.search(name + ".apk") and not foss_app):
            bad.append(name)
    report.add("installed_module_provenance_available", bool(installed), count=len(installed))
    lens_paths = installed.get("ApertureLensLauncher", {}).get("path", [])
    report.add("aperture_lens_bridge_compiled_from_foss_source",
               lens_paths == ["packages/apps/Aperture/lens_launcher"], paths=lens_paths)
    report.add("module_info_has_no_proprietary_google_modules", not bad, modules=bad)


def check_bootstrap_images(report, tools, tf, extracted):
    limits = tf.props("META/misc_info.txt")
    records = {}
    for stem, expected_magic in BOOTSTRAP_HEADERS.items():
        image = extracted.get(stem)
        if not image:
            report.add(f"bootstrap_{stem}_header_and_size", False, error="missing from payload")
            continue
        with image.open("rb") as stream:
            magic = stream.read(len(expected_magic))
        size = image.stat().st_size
        configured_size = int(limits[stem + "_size"]) if stem not in VBMETA_IMAGES else None
        report.add(f"bootstrap_{stem}_header_and_size", magic == expected_magic and
                   (configured_size is None or configured_size == size),
                   magic=magic.hex(), bytes=size, configured_partition_bytes=configured_size)
        records[stem] = {"bytes": size, "sha256": sha256_file(image), "magic": magic.hex()}
    super_empty = next(iter(extracted.values())).parent / "super_empty.img"
    super_size = int(limits["super_partition_size"])
    group_size = int(limits["super_qti_dynamic_partitions_group_size"])
    dyn_parts = limits["super_qti_dynamic_partitions_partition_list"].split()
    lp_cmd = [
        tools("lpmake"), "--metadata-size", "65536", "--super-name", limits["super_metadata_device"],
        "--metadata-slots", "3", "--virtual-ab", "--device", f"super:{super_size}",
        "--group", f"qti_dynamic_partitions_a:{group_size}",
        "--group", f"qti_dynamic_partitions_b:{group_size}",
    ]
    for p in dyn_parts:
        lp_cmd += ["--partition", f"{p}_a:readonly:0:qti_dynamic_partitions_a",
                   "--partition", f"{p}_b:readonly:0:qti_dynamic_partitions_b"]
    lp_cmd += ["--output", super_empty]
    run(lp_cmd, env=tools.env())
    with super_empty.open("rb") as stream:
        lp_magic = stream.read(4)
    se_size = super_empty.stat().st_size
    report.add("bootstrap_super_empty_header_and_geometry",
               lp_magic == b"gDla" and se_size > 4096,
               magic=lp_magic.hex(), bytes=se_size, super_partition_bytes=super_size)
    records["super_empty"] = {"bytes": se_size, "sha256": sha256_file(super_empty), "magic": lp_magic.hex()}
    report.artifacts["standalone_images"] = records


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for name in ("rom-dir", "product-out", "host-bin", "source-json", "ota",
                 "target-files", "ota-cert", "avb-key", "keys-dir", "work-dir", "output"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--manifest-file", help="saved output of `repo manifest -r`")
    parser.add_argument("--manifest-command", default="repo manifest -r")
    parser.add_argument("--expect-android-release", default="17")
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()

    work = Path(args.work_dir)
    work.mkdir(parents=True, exist_ok=True)
    tools = Tools(args.host_bin)
    source = json.loads(Path(args.source_json).read_text())
    gki = load_staged_gki(args.rom_dir)
    report = Report()

    manifest = report.guard("repo_manifest", read_manifest, args, report)
    if manifest:
        report.guard("source_pins", check_sources, report, args, source, manifest)
    uapi = report.guard("kernel_source_pins", check_kernel_sources, report, args, manifest) if manifest else None
    tf = report.guard("target_files_open", TargetFiles, args.target_files, work)
    summary = {}
    if tf:
        props = report.guard("build_props", check_build_props, report, args, tf)
        extracted = report.guard("ota", check_ota, report, args, tools, work, tf, work / "payload") or {}
        if extracted:
            report.guard("partitions", check_partitions, report, tf, extracted)
            report.guard("system_init", check_init_aliases, report, tools, work, tf, extracted)
            report.guard("images_vs_payload", check_images_vs_payload, report, tf, tools, extracted, work)
            report.guard("avb", check_avb, report, args, tools, work, extracted, tf)
            report.guard("kernel_links", check_kernel_links, report, args, tools, work, extracted, tf, source, gki)
            report.guard("bootstrap_images", check_bootstrap_images, report, tools, tf, extracted)
        report.guard("vintf", check_vintf, report, args, tools, tf)
        report.guard("sepolicy", check_sepolicy, report, tools, tf)
        if extracted:
            report.guard("recovery_binary", check_recovery_binary, report, tools, work, tf, extracted,
                         manifest or {"projects": {}})
        report.guard("recovery_trust", check_recovery_trust, report, args, tf)
        summary = report.guard("apks", check_apks, report, args, tools, tf, source) or {}
        if summary:
            report.guard("esim", check_esim, report, tools, tf, summary["apks"])
        report.guard("qti_telephony_linkage", check_qti_telephony_linkage, report, args, tf)
        summary["apex"] = report.guard("apex_keys", check_apex_keys, report, args, tools, work, tf) or {}
        if extracted:
            report.guard("payload_apk_bytes", check_released_apk_bytes, report, tools, work, tf, extracted, summary)
        report.guard("google_modules", check_google_modules, report, args, tf)
        summary["build"] = props
    failed = [c["check"] for c in report.checks if c["gating"] and not c["ok"]]
    result = {
        "audit": AUDIT_PROFILE,
        "status": "pass" if not failed else "fail",
        "failed_checks": failed,
        "checks": report.checks,
        "source_manifest": manifest,
        "artifacts": report.artifacts,
        "evidence": summary,
        "verified_source_inputs": retained_source_inputs(source),
        "kernel_uapi_sources": uapi,
        "retained_stock_provenance": retained_stock_provenance(source, gki),
        "physical_device_tests_not_run": list(NOT_RUN),
    }
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"{result['status']}: {len(report.checks)} checks, {len(failed)} failed -> {args.output}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
