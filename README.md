# yaap-houji

Region-agnostic **Bring-Your-Own-Firmware (BYOF)** **YAAP 17 (Android 17, `seventeen`)** ROM adaptation patches, local manifest, 119-check release auditor, and rootless interactive installer for **Xiaomi 14 (`houji` / `houjiin`, Snapdragon 8 Gen 3 `SM8650`)**.

> **Decoupled Kernel Architecture:** This repository focuses strictly on the Android 17 userspace, ROM adaptation, auditing, and flashing layers. For the companion ROM-agnostic kernel stack (`6.12` pure GKI 2.0 with `0` `kernel/common` patches & full OOT DDK sources, or `6.1` LTS), see **[`ninthcj/SM8650-houji`](https://github.com/ninthcj/SM8650-houji)**.

## Highlights

- **Region-Agnostic BYOF (`14` OS Partitions Only)**: Ships `boot`, `dtbo`, `init_boot`, `odm`, `product`, `recovery`, `system`, `system_dlkm`, `system_ext`, `vbmeta`, `vbmeta_system`, `vendor`, `vendor_boot`, `vendor_dlkm` with **zero radio/firmware partitions**. Works across CN (`23127PN0CC`) and Global/EEA/IN (`23127PN0CG`, `houji` / `houjiin`) on a matching HyperOS 3 (`OS3.0.x`) firmware baseline.
- **FOSS-First & Native microG**: Vanilla `vendor/microg` integration, pinned GrapheneOS `Vanadium`, `Aperture` multi-lens camera, `Seedvault` backup, `OpenEUICC` + `XiaomiEsimSwitcher` (enabled on Global SKU, masked on CN SKU), omitting `vendor/google/gms`, `vendor/google/pixel`, `YASR`, `TalkBack`, and `ImsServiceEntitlement`.
- **EROFS (`lz4hc,9`) & Xiaomi Hardware Features**: Read-only dynamic OS partitions built with EROFS + block deduplication, dead vendor daemon pruning, real-time Gaussian blur, `IHealth` V5 with **80% PMIC bypass charging** (`night_charging`) + SOH, **10W Wireless PowerShare**, and **90W fast charge** SELinux wiring.
- **Safety-First Auditor & Installer**: `verify-preflight.py` source gate, 119-check `verify-release.py`, `package-release.py`, interactive physical `--firmware` confirmation in Recovery, and rootless `flash.sh` (`wipe-super` + resumable `sideload`).

> **Note:** Personal engineering repository shared **as-is** (`rootless`, FOSS-first). **Never relock your bootloader** when running custom-signed builds on Xiaomi hardware.

## Repository Layout

- `manifest/houji.xml` — `.repo/local_manifests/houji.xml` pinning YAAP 17, Xiaomi device/vendor/hardware/UAPI, QTI telephony (`LA.QSSI.16.0`), `vendor/microg`, and `Vanadium`.
- `patches/` & `apply-patches.sh` — Clean `git format-patch` series across the 8 adapted Android 17 repositories on branch `yaap-17`.
- `Containerfile` & `.containerignore` — Rootless Podman Ubuntu 24.04 AOSP build environment.
- `verify-preflight.py`, `verify-release.py`, `build-copy-partitions.py`, `package-release.py`, `flash.sh` — Preflight checker, 119-check target-files auditor, signed A/B firmware-alignment zip builder (`copy-partitions-houji.zip`), `dist/` publisher, and interactive rootless installer.

## Reproducing the Build

### 1. Prepare workspace & offline signing keys

Place offline AVB / Android release keys in `../keys/` (shared across ROM & kernel repos, never committed):

```bash
podman build -t localhost/houji-aosp-builder:ubuntu24.04 -f Containerfile .
mkdir -p ../keys yaap dist preflight .ccache
# Generate AOSP releasekey, platform, shared, media, networkstack,
# nfc, bluetooth, sdk_sandbox, avb.pem, and APEX key pairs inside ../keys/
```

### 2. Sync YAAP 17 & apply adaptation patches

```bash
podman run --rm -it --userns=keep-id \
  -v "$(pwd)":/workspace \
  -v "$(pwd)/../keys":/workspace/keys:ro \
  localhost/houji-aosp-builder:ubuntu24.04 bash

cd /workspace/yaap
repo init -u https://github.com/yaap/manifest.git -b seventeen --git-lfs
cp /workspace/manifest/houji.xml .repo/local_manifests/houji.xml
repo sync -c --no-tags --force-sync -j"$(nproc)"
repo forall -c 'git lfs pull' || true

/workspace/apply-patches.sh
python3 /workspace/verify-preflight.py /workspace/yaap
```

### 3. Build, audit & package YAAP 17

```bash
cd /workspace/yaap
source build/envsetup.sh
lunch yaap_houji-cp2a-user
m yaap out/target/product/houji/module-info.json

python3 /workspace/verify-release.py \
  --rom-dir /workspace/yaap \
  --keys-dir /workspace/keys \
  --out-report /workspace/dist/RELEASE_VERIFICATION.json
python3 /workspace/build-copy-partitions.py \
  --keys-dir /workspace/keys \
  --host-out /workspace/yaap/out/host/linux-x86 \
  --output /tmp/copy-partitions-houji.zip
python3 /workspace/package-release.py \
  --product-out /workspace/yaap/out/target/product/houji \
  --images-dir /tmp/verify-work/payload \
  --verification /workspace/dist/RELEASE_VERIFICATION.json \
  --platform-tools /workspace/preflight/platform-tools_r37.0.3-linux.zip \
  --flash-script /workspace/flash.sh \
  --copy-partitions /tmp/copy-partitions-houji.zip \
  --dist /workspace/dist
```

### 4. Pair with `6.12` (or `6.1` LTS) kernel & flash

- Follow [`ninthcj/SM8650-houji`](https://github.com/ninthcj/SM8650-houji) (`6.12` default pure GKI 2.0 stack or `6.1` LTS) pointing `--rom-dir ../yaap-houji/yaap` and `--keys-dir ../keys`, then refresh physical/logical images alongside `./dist/` before flashing with `./dist/flash.sh flash` / `sideload`. First-time installs automatically sideload the signed `copy-partitions-houji.zip` helper before the YAAP OTA zip so inactive-slot firmware matches the user's active HyperOS 3 baseline without bundling proprietary blobs.
- **Linux Host Tip (ASMedia ASM4242 USB4 controllers):** Prefer a native SoC USB-A/USB-C port if ADB disconnects mid-transfer during `adb sideload`.
