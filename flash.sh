#!/usr/bin/env bash
# YAAP 17 first-time installer for Xiaomi 14 (houji / houjiin), bring-your-own-firmware
# (BYOF): the vendor firmware already on the device is yours. HyperOS OS3 is the expected
# baseline; anything else only produces a warning. The bootloader must already be
# unlocked. Rootless. Region is never inferred from any property.
#
# Phase 1  ./flash.sh flash     device identity check over ADB (or a direct, explicitly
#                               confirmed BYOF start from an unlocked bootloader) ->
#                               bootloader checks -> write the 7 boot-chain images to the
#                               ACTIVE slot only.
# Phase 2  ./flash.sh sideload  after you manually format data in recovery and choose
#                               "Apply update -> Apply from ADB": sideload the OTA zip.
#                               Optional --firmware ZIP is sideloaded first, with its own
#                               confirmation, then you re-enter "Apply from ADB".
#
# The 21 firmware partitions (xbl, tz, modem, ...) are never written through fastboot;
# they arrive only inside the OTA payload or the firmware ZIP you supply. The script never
# locks or unlocks the bootloader, never formats anything, never changes vbmeta flags,
# never disables recovery signature verification, and never reboots the device after the
# sideload.

set -Eeuo pipefail
umask 077
unset ANDROID_SERIAL ANDROID_ADB_SERVER_ADDRESS

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly ROOT
readonly ADB="$ROOT/platform-tools/adb"
readonly FASTBOOT="$ROOT/platform-tools/fastboot"
readonly IMG_DIR="$ROOT/images"
readonly SUMS="$ROOT/SHA256SUMS"
readonly VERIFICATION="$ROOT/BUILD_VERIFICATION.json"
readonly COPY_PARTITIONS_REL="copy-partitions-houji.zip"
readonly COPY_PARTITIONS_ZIP="$ROOT/$COPY_PARTITIONS_REL"
if [[ -d "${XDG_STATE_HOME:-$HOME/.local/state}/yaap-houji-flash" && ! -d "${XDG_STATE_HOME:-$HOME/.local/state}/sm8650-houji-flash" ]]; then
    readonly STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/yaap-houji-flash"
else
    readonly STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/sm8650-houji-flash"
fi

# --- Supported identity ----------------------------------------------------------------
# libinit_xiaomi_8650.cpp normalizes the India SKU alias houjiin to houji; both are the
# Xiaomi 14. DEVICE_ALIAS_SET is the exact sorted comma-joined alias set that
# TARGET_OTA_ASSERT_DEVICE must emit as the OTA's pre-device.
readonly -a DEVICE_ALIASES=(houji houjiin)
readonly DEVICE_ALIAS_SET=houji,houjiin
readonly VENDOR_BASELINE_RE='^OS3\.'

# Boot-chain images in write order; vbmeta last so an interrupted run never leaves a
# new vbmeta describing old partitions. super_empty.img is then applied via wipe-super
# to clear stock HyperOS mi_ext / orphaned COW entries so recovery sideload can allocate
# dynamic partitions cleanly. Firmware and userdata are not touched here.
readonly -a FLASH_ORDER=(dtbo vendor_boot boot init_boot recovery vbmeta_system vbmeta)
readonly SUPER_EMPTY_REL="images/super_empty.img"
readonly SUPER_EXPECTED_BYTES=8321499136
readonly LP_GEOMETRY_MAGIC=67446c61
# Existing board policy (BoardConfigCommon.mk: BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS += --flags 3).
# Verified inside the image; never applied or altered at flash time.
readonly VBMETA_FLAGS_POLICY=3

SERIAL=""
DEV_MODE=""
DEV_STATE=""
STATE_FILE=""
LOG_FILE=""
SLOT=""
OTA_ZIP=""
OTA_REL=""
OTA_METADATA=""
FIRMWARE_ZIP=""
SKIP_COPY_PARTITIONS=0

if [[ -t 1 ]]; then
    C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_BLD=$'\e[1m'; C_OFF=$'\e[0m'
else
    C_RED=""; C_GRN=""; C_YEL=""; C_BLD=""; C_OFF=""
fi

info() { printf '%s\n' "$*"; }
step() { printf '\n%s== %s ==%s\n' "$C_BLD" "$*" "$C_OFF"; }
ok()   { printf '%s  ok%s  %s\n' "$C_GRN" "$C_OFF" "$*"; }
warn() { printf '%swarn%s  %s\n' "$C_YEL" "$C_OFF" "$*" >&2; }
die()  { printf '%sSTOP%s  %s\n' "$C_RED" "$C_OFF" "$*" >&2; exit 1; }

trap 'printf "\nInterrupted. Re-run the same phase; completed steps are recorded and every write is re-confirmed.\n" >&2; exit 130' INT TERM

usage() {
    cat <<'EOF'
YAAP 17 first-time installer, Xiaomi 14 (houji / houjiin), bring-your-own-firmware

Usage:
  ./flash.sh verify                  check bundle integrity only (no device access)
  ./flash.sh flash    [-s SERIAL]    phase 1: identity check, bootloader checks, write 7 images
  ./flash.sh copy-partitions [-s SERIAL]
                                     mirror active slot's 28 non-OS firmware partitions to
                                     the inactive slot from recovery "Apply from ADB"
  ./flash.sh sideload [-s SERIAL] [--firmware ZIP] [--skip-copy-partitions]
                                     phase 2: align inactive-slot firmware (copy-partitions),
                                     optionally sideload your own firmware ZIP, then OTA zip
  ./flash.sh status   [-s SERIAL]    show the recorded progress for a device

Requirements
  * Bootloader already unlocked. This script never locks or unlocks it.
  * Device is a Xiaomi 14 (ro.product.device and ro.boot.hardware.sku are houji or
    houjiin) with USB debugging authorized, OR is already in the bootloader (fastboot,
    unlocked, physically connected): then you must confirm a typed BYOF statement,
    because no firmware baseline can be read there.
  * The vendor firmware is yours (BYOF). HyperOS OS3 is expected; a vendor build that
    is not OS3 only produces a warning over ADB. Region is never inferred.
  * An interactive terminal: every write needs a typed confirmation.
  * Bundle layout: platform-tools/{adb,fastboot}, images/ holding the 7 boot-chain
    images plus super_empty.img, copy-partitions-houji.zip, exactly one YAAP-17-*houji*.zip
    whose OTA pre-device is exactly houji,houjiin, and SHA256SUMS covering them all. Only
    the bundled adb/fastboot are used.

Procedure
  1. ./flash.sh flash
       Verifies the device identity over ADB (or asks for the BYOF confirmation in the
       bootloader), reboots to the bootloader, verifies product=houji|houjiin,
       unlocked=yes, is-userspace=no (bootloader, not fastbootd), the active slot and
       every target partition's presence and size, writes only the ACTIVE slot's
       dtbo, vendor_boot, boot, init_boot, recovery, vbmeta_system, vbmeta, and runs
       wipe-super with images/super_empty.img so HyperOS mi_ext/COW entries do not block
       recovery sideload. Firmware and userdata are not touched. The device is never
       rebooted except by your typed confirmation.
  2. ./platform-tools/fastboot reboot recovery    (also offered by the script)
  3. In recovery, by hand:  Factory reset -> Format data / factory reset.
       Back up your data first. This is required for a clean install.
       The script never formats anything.
  4. In recovery, by hand:  Apply update -> Apply from ADB.
  5. ./flash.sh sideload [--firmware FIRMWARE.zip] [--skip-copy-partitions]
       By default, copy-partitions-houji.zip is sent first to mirror your active slot's
       regional OS3 firmware onto the inactive slot (skipping byte-identical partitions)
       so an A/B slot switch never boots stale OEM firmware. Re-enter Apply from ADB
       afterwards. If --firmware ZIP is given, it is sent next (recovery prompts
       "Install untrusted package?" if not release-signed; choose Yes only for matching
       regional firmware, then re-enter Apply from ADB). Finally, YAAP is sideloaded
       into the inactive slot. adb's exit status is NOT proof of success: read the
       recovery screen. The script never reboots the device. Only when recovery reports
       success, choose "Reboot system now" on the phone yourself.

Recovery paths
  * Recovery does not start: hold Power + Volume Down for the bootloader and rerun
    `./flash.sh flash` (repeatable while the device is in the bootloader).
  * The system will not boot after phase 1 and before a successful sideload: that is
    expected (new boot chain on the old system). Finish phase 2, or restore the
    slot with an official fastboot package of your own firmware (not part of this
    bundle).
  * Sideload failed or interrupted: reboot to recovery, Apply from ADB, rerun
    `./flash.sh sideload`. Progress lives in
    ${XDG_STATE_HOME:-~/.local/state}/sm8650-houji-flash/<serial>.state
EOF
}

# --- generic helpers ---------------------------------------------------------------------
require_tty() {
    [[ -t 0 && -t 1 ]] || die "An interactive terminal is required: every write needs a typed confirmation, and there is no non-interactive bypass."
}

# confirm "<exact phrase>" "<what happens>": succeeds only on an exact typed match.
confirm() {
    local phrase=$1 reply
    printf '\n%s%s%s\nType exactly  %s%s%s  to continue; anything else aborts: ' \
        "$C_BLD" "$2" "$C_OFF" "$C_BLD" "$phrase" "$C_OFF"
    IFS= read -r reply || reply=""
    [[ $reply == "$phrase" ]]
}

log() {
    [[ -n $LOG_FILE ]] || return 0
    printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >>"$LOG_FILE"
}

need_tool() {
    command -v "$1" >/dev/null 2>&1 || die "Host tool '$1' is required but not installed."
}

valid_serial() {
    [[ $1 =~ ^[A-Za-z0-9._:-]+$ ]] || die "Refusing unusual device serial '$1'."
}

is_device_alias() {
    local a
    for a in "${DEVICE_ALIASES[@]}"; do [[ $1 == "$a" ]] && return 0; done
    return 1
}

# --- per-serial state (key=value) --------------------------------------------------------
init_state() {
    valid_serial "$SERIAL"
    mkdir -p -- "$STATE_DIR"
    need_tool flock
    exec {STATE_LOCK}>"$STATE_DIR/$SERIAL.lock"
    flock -n "$STATE_LOCK" || die "Another installer is running for $SERIAL."
    STATE_FILE="$STATE_DIR/$SERIAL.state"
    LOG_FILE="$STATE_DIR/$SERIAL.log"
    touch -- "$STATE_FILE" "$LOG_FILE"
}

state_get() { sed -n "s/^$1=//p" "$STATE_FILE" | tail -n 1; }

state_set() {
    local tmp
    tmp=$(mktemp "$STATE_FILE.XXXXXX")
    { grep -v "^$1=" "$STATE_FILE" || true; printf '%s=%s\n' "$1" "$2"; } >"$tmp"
    mv -f -- "$tmp" "$STATE_FILE"
}

state_clear_prefix() {
    local tmp
    tmp=$(mktemp "$STATE_FILE.XXXXXX")
    { grep -v "^$1" "$STATE_FILE" || true; } >"$tmp"
    mv -f -- "$tmp" "$STATE_FILE"
}

# --- offline bundle verification ---------------------------------------------------------
sums_has() {
    awk -v p="$1" '{f=$2; sub(/^\*/,"",f); sub(/^\.\//,"",f); if (f==p) found=1} END{exit !found}' "$SUMS"
}

sums_hash() {
    awk -v p="$1" '{f=$2; sub(/^\*/,"",f); sub(/^\.\//,"",f); if (f==p) {print $1; exit}}' "$SUMS"
}

bundle_digest() { sha256sum -- "$SUMS" | awk '{print $1}'; }

hex_at() { # file offset count -> lowercase hex
    od -An -v -tx1 -j "$2" -N "$3" -- "$1" | tr -d ' \n'
}

# Header magic per image type, as lowercase hex.
image_magic() {
    case $1 in
        boot|init_boot|recovery) echo 414e44524f494421 ;; # "ANDROID!"
        vendor_boot)             echo 564e4452424f4f54 ;; # "VNDRBOOT"
        dtbo)                    echo d7b7ab1e ;;
        vbmeta|vbmeta_system)    echo 41564230 ;;         # "AVB0"
        *) die "Internal error: no magic known for $1." ;;
    esac
}

verify_images() {
    local base img want got flags se_img se_magic
    local -a found=()
    shopt -s nullglob dotglob
    found=("$IMG_DIR"/*)
    shopt -u nullglob dotglob
    [[ ${#found[@]} -eq $((${#FLASH_ORDER[@]} + 1)) ]] ||
        die "images/ must contain exactly the ${#FLASH_ORDER[@]} boot-chain images (${FLASH_ORDER[*]}) plus super_empty.img; found ${#found[@]} entries."
    for base in "${FLASH_ORDER[@]}"; do
        img="$IMG_DIR/$base.img"
        [[ -f $img && ! -L $img ]] || die "Missing or non-regular image: images/$base.img"
        sums_has "images/$base.img" || die "SHA256SUMS has no entry for images/$base.img"
        want=$(image_magic "$base")
        got=$(hex_at "$img" 0 $((${#want} / 2)))
        [[ $got == "$want" ]] || die "images/$base.img has an unexpected header magic ($got, expected $want)."
    done
    se_img="$ROOT/$SUPER_EMPTY_REL"
    [[ -f $se_img && ! -L $se_img ]] || die "Missing or non-regular image: $SUPER_EMPTY_REL"
    sums_has "$SUPER_EMPTY_REL" || die "SHA256SUMS has no entry for $SUPER_EMPTY_REL"
    se_magic=$(hex_at "$se_img" 0 4)
    [[ $se_magic == "$LP_GEOMETRY_MAGIC" ]] ||
        die "$SUPER_EMPTY_REL has unexpected LpMetadata magic ($se_magic, expected $LP_GEOMETRY_MAGIC)."
    # vbmeta header: flags is a big-endian u32 at byte 120.
    flags=$(od -An -v -tu1 -j 120 -N 4 -- "$IMG_DIR/vbmeta.img" | awk '{print $1*16777216 + $2*65536 + $3*256 + $4}')
    [[ $flags == "$VBMETA_FLAGS_POLICY" ]] ||
        die "images/vbmeta.img carries AVB flags $flags; board policy requires $VBMETA_FLAGS_POLICY. Flags are never changed at flash time."
    ok "${#FLASH_ORDER[@]} boot-chain images + super_empty.img present, headers valid, vbmeta flags=$flags (board policy)"
}

zip_list() {
    if command -v unzip >/dev/null 2>&1; then unzip -Z1 -- "$1"
    elif command -v bsdtar >/dev/null 2>&1; then bsdtar -tf "$1"
    else die "Need 'unzip' or 'bsdtar' to inspect the OTA zip."
    fi
}

zip_member() {
    if command -v unzip >/dev/null 2>&1; then unzip -p -- "$1" "$2"
    else bsdtar -xOf "$1" "$2"
    fi
}

ota_meta() { # key
    sed -n "s/^$1=//p" <<<"$OTA_METADATA" | head -n 1
}

verify_ota() {
    local -a zips=()
    local listing member pre type build ts spl got
    shopt -s nullglob
    zips=("$ROOT"/YAAP-17-*houji*.zip)
    shopt -u nullglob
    [[ ${#zips[@]} -eq 1 ]] || die "Expected exactly one YAAP-17-*houji*.zip next to flash.sh; found ${#zips[@]}."
    OTA_ZIP=${zips[0]}
    OTA_REL=$(basename -- "$OTA_ZIP")
    [[ -f $OTA_ZIP && ! -L $OTA_ZIP ]] || die "$OTA_REL is not a regular file."
    sums_has "$OTA_REL" || die "SHA256SUMS has no entry for $OTA_REL"
    [[ $(hex_at "$OTA_ZIP" 0 4) == 504b0304 ]] || die "$OTA_REL is not a ZIP archive."
    listing=$(zip_list "$OTA_ZIP")
    for member in payload.bin payload_properties.txt META-INF/com/android/metadata; do
        grep -qxF -- "$member" <<<"$listing" || die "$OTA_REL lacks $member: not an A/B full OTA."
    done
    OTA_METADATA=$(zip_member "$OTA_ZIP" META-INF/com/android/metadata)
    pre=$(ota_meta pre-device); type=$(ota_meta ota-type); build=$(ota_meta post-build)
    ts=$(ota_meta post-timestamp); spl=$(ota_meta post-security-patch-level)
    # Order-insensitive but exact: a lone 'houji' would make recovery reject a houjiin
    # device; extra devices would widen the assert beyond this release.
    got=$(tr '|,' '\n' <<<"$pre" | sort | paste -sd, -)
    [[ $got == "$DEVICE_ALIAS_SET" ]] ||
        die "OTA pre-device is '$pre'; it must be exactly the alias set '$DEVICE_ALIAS_SET' (TARGET_OTA_ASSERT_DEVICE)."
    [[ $type == AB ]] || die "OTA ota-type is '$type', expected 'AB'."
    [[ -z $(ota_meta pre-build) && -z $(ota_meta pre-build-incremental) ]] || die "OTA is incremental, not full."
    [[ $build == *:user/release-keys ]] || die "OTA post-build '$build' is not a user/release-keys build."
    [[ $ts =~ ^[0-9]+$ ]] || die "OTA metadata has no numeric post-timestamp."
    [[ $spl =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "OTA metadata has no valid post-security-patch-level."
    ok "$OTA_REL: A/B full OTA for $pre, $build, patch $spl"
}

verify_copy_partitions() {
    [[ -f $COPY_PARTITIONS_ZIP && ! -L $COPY_PARTITIONS_ZIP ]] ||
        die "Missing or non-regular copy-partitions zip: $COPY_PARTITIONS_REL"
    sums_has "$COPY_PARTITIONS_REL" || die "SHA256SUMS has no entry for $COPY_PARTITIONS_REL"
    [[ $(hex_at "$COPY_PARTITIONS_ZIP" 0 4) == 504b0304 ]] || die "$COPY_PARTITIONS_REL is not a ZIP archive."
    zip_list "$COPY_PARTITIONS_ZIP" | grep -qxF -- "META-INF/com/google/android/update-binary" ||
        die "$COPY_PARTITIONS_REL lacks META-INF/com/google/android/update-binary."
    ok "$COPY_PARTITIONS_REL: signed A/B firmware slot-alignment helper present"
}

verify_bundle() {
    step "Bundle"
    local t f
    for t in sha256sum od awk sed grep tr sort paste stat timeout mktemp tee date head basename; do need_tool "$t"; done
    [[ -f $SUMS ]] || die "SHA256SUMS is missing."
    [[ -f $VERIFICATION && ! -L $VERIFICATION ]] || die "BUILD_VERIFICATION.json is missing."
    for f in flash.sh BUILD_VERIFICATION.json "$COPY_PARTITIONS_REL"; do
        sums_has "$f" || die "SHA256SUMS has no entry for $f"
    done
    for f in "$ADB" "$FASTBOOT"; do
        [[ -f $f && -x $f && ! -L $f ]] || die "Bundled $(basename -- "$f") is missing or not executable: $f"
        sums_has "platform-tools/$(basename -- "$f")" || die "SHA256SUMS has no entry for platform-tools/$(basename -- "$f")"
    done
    info "Checking every file listed in SHA256SUMS (reads the whole OTA zip)..."
    (cd -- "$ROOT" && sha256sum --check --strict --quiet SHA256SUMS) ||
        die "SHA256SUMS verification failed; do not flash from a modified or incomplete bundle."
    ok "SHA256SUMS verified"
    verify_images
    verify_copy_partitions
    verify_ota
    info "adb:      $("$ADB" version | head -n 1)"
    info "fastboot: $("$FASTBOOT" --version | head -n 1)"
}

# --- device discovery --------------------------------------------------------------------
list_adb() {
    "$ADB" devices 2>/dev/null | awk -F'\t' 'NF==2 && $1!~/^\*/ {print $1 "\tadb\t" $2}'
}

list_fb() {
    timeout 15 "$FASTBOOT" devices 2>/dev/null | awk 'NF>=2 {print $1 "\tfastboot\t" $2}'
}

# resolve_device <transport...>: sets SERIAL, DEV_MODE (adb|fastboot), DEV_STATE.
resolve_device() {
    local -a cands=() hits=()
    local line t
    for t in "$@"; do
        while IFS= read -r line; do
            [[ -z $line ]] || cands+=("$line")
        done < <(if [[ $t == adb ]]; then list_adb; else list_fb; fi)
    done
    for line in "${cands[@]}"; do
        if [[ -z $SERIAL || ${line%%$'\t'*} == "$SERIAL" ]]; then hits+=("$line"); fi
    done
    [[ ${#hits[@]} -gt 0 ]] ||
        die "No device${SERIAL:+ with serial $SERIAL} found over: $*. Check the cable, USB debugging authorization and udev permissions."
    if [[ ${#hits[@]} -gt 1 ]]; then
        printf '  %s\n' "${hits[@]}" >&2
        die "More than one candidate device. Connect only the target phone or pass -s SERIAL."
    fi
    IFS=$'\t' read -r SERIAL DEV_MODE DEV_STATE <<<"${hits[0]}"
    valid_serial "$SERIAL"
}

# --- device identity over ADB ------------------------------------------------------------
adb_prop() { "$ADB" -s "$SERIAL" shell getprop "$1" 2>/dev/null | tr -d '\r'; }

# begin_install_state <basis: adb|byof> <slot> <utc> <fingerprint>: a fresh install record.
begin_install_state() {
    state_set SERIAL "$SERIAL"
    state_set BUNDLE_SHA256 "$(bundle_digest)"
    state_set BASELINE "$1"
    state_set BASELINE_SLOT "$2"
    state_set BASELINE_BUILD_UTC "$3"
    state_set BASELINE_FINGERPRINT "$4"
    state_set FLASH_DONE 0
    state_set COPY_PARTITIONS_ATTESTED 0
    state_set SIDELOAD_STARTED 0
    state_set INSTALL_CONFIRMED 0
    state_set FIRMWARE_SHA256 ""
    state_clear_prefix FLASHED_
}

identity_check() {
    step "Device identity over ADB (serial $SERIAL)"
    [[ $DEV_STATE == device ]] ||
        die "ADB state is '$DEV_STATE', not an authorized 'device'. Unlock the phone, accept the USB debugging prompt and rerun."
    local model name dev sku hwc vinc sinc minc fp slot utc spl vspl locked
    local -a fails=()
    model=$(adb_prop ro.product.model);          name=$(adb_prop ro.product.name)
    dev=$(adb_prop ro.product.device);           sku=$(adb_prop ro.boot.hardware.sku)
    hwc=$(adb_prop ro.boot.hwc);                 vinc=$(adb_prop ro.vendor.build.version.incremental)
    sinc=$(adb_prop ro.build.version.incremental); minc=$(adb_prop ro.mi.os.version.incremental)
    fp=$(adb_prop ro.build.fingerprint);         slot=$(adb_prop ro.boot.slot_suffix)
    utc=$(adb_prop ro.build.date.utc);           spl=$(adb_prop ro.build.version.security_patch)
    vspl=$(adb_prop ro.vendor.build.security_patch); locked=$(adb_prop ro.boot.flash.locked)

    if is_device_alias "$dev"; then ok "ro.product.device = $dev"
    else fails+=("ro.product.device: got '$dev', expected one of ${DEVICE_ALIASES[*]}"); fi
    if [[ -z $sku ]]; then warn "Boot SKU is unavailable; the physical bootloader product check is still required."
    elif is_device_alias "$sku"; then ok "ro.boot.hardware.sku = $sku"
    else fails+=("ro.boot.hardware.sku: got '$sku', expected one of ${DEVICE_ALIASES[*]}"); fi
    [[ $slot == _a || $slot == _b ]] || fails+=("ro.boot.slot_suffix: got '$slot', expected _a or _b")
    [[ $utc =~ ^[0-9]+$ ]] || fails+=("ro.build.date.utc: got '$utc', expected a number")
    [[ $spl =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || fails+=("ro.build.version.security_patch: got '$spl', expected YYYY-MM-DD")
    [[ $locked != 1 ]] || fails+=("ro.boot.flash.locked=1: the bootloader is locked; this script never unlocks it")
    if [[ ${#fails[@]} -gt 0 ]]; then
        printf '  - %s\n' "${fails[@]}" >&2
        die "Device is not a supported Xiaomi 14 (${DEVICE_ALIASES[*]}) with an unlocked bootloader; nothing was changed."
    fi
    [[ $("$ADB" -s "$SERIAL" get-serialno | tr -d '\r') == "$SERIAL" ]] || die "adb get-serialno does not match $SERIAL."

    # BYOF: model, name, hwc and the build are reported for you to read, never matched
    # and never used to infer a region.
    info "  reported (informational): model='$model' name='$name' hwc='$hwc'"
    info "  reported (informational): fingerprint='$fp' incremental='$sinc'"
    if [[ $vinc =~ $VENDOR_BASELINE_RE ]]; then
        ok "ro.vendor.build.version.incremental = $vinc (OS3)"
    else
        warn "ro.vendor.build.version.incremental is '${vinc:-<not reported>}', not an OS3 build. The vendor firmware is yours; this release was built against OS3 and nothing here can check compatibility."
    fi
    if [[ -n $minc && ! $minc =~ $VENDOR_BASELINE_RE ]]; then
        warn "ro.mi.os.version.incremental is '$minc', not an OS3 build."
    fi

    # Cross-OS stock combinations (user-supplied firmware vs this OTA) are not blockable
    # here: the timestamp/SPL comparison is advisory only; the bootloader's AVB rollback
    # index and recovery remain the real gates.
    local ota_ts ota_spl
    ota_ts=$(ota_meta post-timestamp); ota_spl=$(ota_meta post-security-patch-level)
    (( ota_ts > utc )) || warn "OTA post-timestamp $ota_ts is not newer than the installed build ($utc). Cross-OS stock is allowed; the bootloader enforces anti-rollback."
    [[ ! $ota_spl < $spl ]] || warn "OTA security patch $ota_spl is older than the installed $spl."
    if [[ $vspl =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ && $ota_spl < $vspl ]]; then
        warn "OTA security patch $ota_spl is older than the installed vendor patch $vspl."
    fi

    SLOT=${slot#_}
    begin_install_state adb "$SLOT" "$utc" "$fp"
    log "identity verified over adb serial=$SERIAL slot=$SLOT utc=$utc patch=$spl vendor_incremental=$vinc fp=$fp"
    ok "Device identity verified; active slot _$SLOT"
}

# --- bootloader phase --------------------------------------------------------------------
FB_ERR=""
# fb_var <name>: prints the value; non-zero when the bootloader gives no answer.
fb_var() {
    local out val
    if ! out=$(timeout 30 "$FASTBOOT" -s "$SERIAL" getvar "$1" 2>&1); then FB_ERR=$out; return 1; fi
    val=$(tr -d '\r' <<<"$out" | sed 's/^(bootloader) //' |
        awk -v k="$1: " 'index($0, k) == 1 {print substr($0, length(k) + 1); exit}')
    [[ -n $val ]] || { FB_ERR=$out; return 1; }
    printf '%s' "$val"
}

need_var() { # name purpose -> value, or stop
    local v
    v=$(fb_var "$1") || die "Bootloader gave no answer for '$1' ($2): ${FB_ERR//$'\n'/ | }. Refusing to continue without evidence."
    printf '%s' "$v"
}

wait_for_fastboot() {
    info "Waiting for $SERIAL in the bootloader (up to 120 s)..."
    timeout 120 "$FASTBOOT" -s "$SERIAL" getvar product >/dev/null 2>&1 && return 0
    die "Device $SERIAL did not appear in fastboot."
}

fastboot_phase() {
    step "Bootloader checks (serial $SERIAL)"
    local v part base size limit img_bytes cur baseline product
    local -a targets=() lines=()

    [[ $(state_get INSTALL_CONFIRMED) != 1 ]] ||
        die "An install is already recorded as complete for $SERIAL; refusing to flash again. To reinstall, boot the system and rerun ./flash.sh flash so the identity is checked over ADB."
    [[ $(state_get SIDELOAD_STARTED) != 1 ]] || die "Sideload has started; return to recovery and resume sideload, not flashing."
    baseline=$(state_get BASELINE)
    if [[ -n $baseline ]]; then
        [[ $(state_get BUNDLE_SHA256) == "$(bundle_digest)" ]] ||
            die "SHA256SUMS changed since the baseline was recorded; rerun from the system over ADB (or from a clean state) with this bundle."
    fi

    v=$(need_var serialno "device identity");  [[ $v == "$SERIAL" ]] || die "Bootloader serialno '$v' differs from the selected serial '$SERIAL'."
    product=$(need_var product "device model")
    is_device_alias "$product" || die "Bootloader product is '$product', expected one of ${DEVICE_ALIASES[*]}."
    v=$(need_var is-userspace "bootloader vs fastbootd")
    [[ $v == no ]] || die "Device is in fastbootd (is-userspace=$v). Reboot to the bootloader (Power + Volume Down, or 'adb reboot bootloader')."
    v=$(need_var unlocked "bootloader lock state")
    [[ $v == yes ]] || die "Bootloader reports unlocked='$v'. This script never unlocks it; unlock through Xiaomi's official process first."
    v=$(need_var slot-count "A/B layout");     [[ $v == 2 ]] || die "slot-count is '$v', expected 2."
    cur=$(need_var current-slot "active slot"); cur=${cur#_}
    [[ $cur == a || $cur == b ]] || die "current-slot is '$cur', expected a or b."
    if [[ -n $baseline ]]; then
        [[ $cur == "$(state_get BASELINE_SLOT)" ]] ||
            die "Active slot '$cur' differs from the slot recorded earlier ('$(state_get BASELINE_SLOT)'): device state changed since the identity check."
    fi
    SLOT=$cur
    ok "serialno=$SERIAL product=$product unlocked=yes is-userspace=no current-slot=$SLOT"
    if v=$(fb_var anti); then
        info "  Xiaomi anti-rollback index reported by the bootloader: $v (informational: no firmware is written)"
        state_set BOOTLOADER_ANTI "$v"
    else
        warn "Bootloader reports no 'anti' value; firmware anti-rollback cannot be cross-checked here."
    fi

    if [[ -z $baseline ]]; then
        cat <<EOF

${C_BLD}Direct bootloader start (BYOF)${C_OFF}
  Nothing was verified over ADB, so this script cannot read your installed system:
    * the vendor firmware version, its region and whether it is OS3 are unknown;
    * whether this release is older than what is installed (rollback) is NOT checked;
    * only the bootloader answers above were checked: product, unlocked, slot, sizes.
  The vendor firmware on the device is yours. This release was built against HyperOS OS3.
EOF
        confirm "BYOF $SERIAL" \
"Confirm $SERIAL is your unlocked Xiaomi 14 (houji/houjiin). Matching regional HyperOS 3 firmware must be present on the slot that will boot YAAP, or supplied separately before the OTA. The ROM does not install firmware." ||
            die "Not confirmed; nothing was written."
        begin_install_state byof "$SLOT" "" ""
        log "byof baseline accepted serial=$SERIAL slot=$SLOT product=$product"
    fi

    for base in "${FLASH_ORDER[@]}"; do
        part="${base}_${SLOT}"
        v=$(need_var "has-slot:$base" "slot support of $base")
        [[ $v == yes ]] || die "$base is not an A/B partition on this device (has-slot=$v)."
        size=$(need_var "partition-size:$part" "presence and size of $part")
        [[ $size =~ ^0x[0-9a-fA-F]+$ ]] || die "Unparseable partition-size for $part: '$size'."
        limit=$((size))
        img_bytes=$(stat -c %s -- "$IMG_DIR/$base.img")
        (( img_bytes > 0 && img_bytes <= limit )) ||
            die "images/$base.img is $img_bytes bytes but partition $part holds only $limit."
        targets+=("$part")
        lines+=("$(printf '  %-18s -> %-17s %11d of %-11d bytes  %s' "images/$base.img" "$part" "$img_bytes" "$limit" "$(sums_hash "images/$base.img")")")
    done
    # Every write must be inside the active slot; there is no second slot in this list.
    for part in "${targets[@]}"; do [[ $part == *_"$SLOT" ]] || die "Internal error: $part is not in slot $SLOT."; done
    local super_hex super_limit se_bytes
    super_hex=$(need_var "partition-size:super" "presence and size of super")
    [[ $super_hex =~ ^0x[0-9a-fA-F]+$ ]] || die "Unparseable partition-size for super: '$super_hex'."
    super_limit=$((super_hex))
    (( super_limit == SUPER_EXPECTED_BYTES )) ||
        die "super partition is $super_limit bytes, expected $SUPER_EXPECTED_BYTES."
    se_bytes=$(stat -c %s -- "$ROOT/$SUPER_EMPTY_REL")
    lines+=("$(printf '  %-18s -> %-17s %11d metadata -> %-11d  %s' "$SUPER_EMPTY_REL" "super (wipe-super)" "$se_bytes" "$super_limit" "$(sums_hash "$SUPER_EMPTY_REL")")")
    ok "All ${#targets[@]} slot-$SLOT boot partitions + super ($super_limit bytes) verified"

    printf '\n%s\n' "Planned writes:"
    printf '%s\n' "${lines[@]}"
    confirm "FLASH $SERIAL slot $SLOT" \
"About to WRITE the ${#targets[@]} boot partitions above on device $SERIAL (slot $SLOT) and reset the shared super dynamic partition table via wipe-super for clean recovery sideload. Firmware and userdata are not touched." ||
        die "Not confirmed; nothing was written."

    state_set FLASH_DONE 0
    state_clear_prefix FLASHED_
    for base in "${FLASH_ORDER[@]}"; do
        part="${base}_${SLOT}"
        info "fastboot flash $part images/$base.img"
        log "fastboot flash $part"
        "$FASTBOOT" -s "$SERIAL" flash "$part" "$IMG_DIR/$base.img" 2>&1 | tee -a "$LOG_FILE" ||
            die "Flashing $part failed. Do not boot the system. Fix the cause and rerun ./flash.sh flash (repeatable while the device stays in the bootloader)."
        state_set "FLASHED_$base" 1
    done
    info "fastboot wipe-super $SUPER_EMPTY_REL"
    log "fastboot wipe-super $SUPER_EMPTY_REL"
    "$FASTBOOT" -s "$SERIAL" wipe-super "$ROOT/$SUPER_EMPTY_REL" 2>&1 | tee -a "$LOG_FILE" ||
        die "wipe-super failed. Do not boot the system. Fix the cause and rerun ./flash.sh flash."
    state_set "FLASHED_super_empty" 1
    state_set FLASH_DONE 1
    state_set FLASH_SLOT "$SLOT"
    state_set OTA_SHA256 "$(sums_hash "$OTA_REL")"
    log "flash complete slot=$SLOT"
    ok "All ${#targets[@]} boot images written to slot $SLOT and super partition table reset"
    print_recovery_steps

    if confirm "RECOVERY $SERIAL" "Optional: run 'fastboot reboot recovery' now (changes no data)."; then
        "$FASTBOOT" -s "$SERIAL" reboot recovery
    else
        info "Skipped. Run it yourself:  $FASTBOOT -s $SERIAL reboot recovery"
    fi
}

print_recovery_steps() {
    cat <<EOF

${C_BLD}Next, by hand in recovery${C_OFF}
  1. Factory reset -> Format data / factory reset.   (required; never done by this script)
  2. Apply update -> Apply from ADB.
  3. On this computer:  ./flash.sh sideload -s $SERIAL
EOF
}

# --- phases ------------------------------------------------------------------------------
cmd_flash() {
    verify_bundle
    resolve_device adb fastboot
    init_state
    log "flash start mode=$DEV_MODE state=$DEV_STATE"
    if [[ $DEV_MODE == adb ]]; then
        identity_check
        confirm "REBOOT $SERIAL" "Reboot $SERIAL into the bootloader (nothing is written yet)." || die "Not confirmed."
        "$ADB" -s "$SERIAL" reboot bootloader
        wait_for_fastboot
    else
        info "Device is already in fastboot; continuing with the bootloader checks."
    fi
    fastboot_phase
}

# adb_state_of_serial: prints the adb state of $SERIAL, or nothing when it is absent.
adb_state_of_serial() {
    list_adb | awk -F'\t' -v s="$SERIAL" '$1 == s {print $3; exit}'
}

wait_for_sideload_state() {
    local waited=0
    info "Waiting up to 300 s for $SERIAL to show 'Apply from ADB' again..."
    while (( waited < 300 )); do
        [[ $(adb_state_of_serial) == sideload ]] && return 0
        sleep 2; waited=$((waited + 2))
    done
    die "$SERIAL is not in sideload state. In recovery choose Apply update -> Apply from ADB and rerun ./flash.sh sideload (without --firmware if the firmware already installed)."
}

# verify_firmware_zip: any structurally valid ZIP. Whether it fits this device or region
# is not knowable here; recovery's own signature verification stays the gate.
verify_firmware_zip() {
    [[ -f $FIRMWARE_ZIP && ! -L $FIRMWARE_ZIP && -r $FIRMWARE_ZIP ]] || die "--firmware '$FIRMWARE_ZIP' is not a readable regular file."
    FIRMWARE_ZIP=$(readlink -f -- "$FIRMWARE_ZIP")
    [[ $FIRMWARE_ZIP != "$OTA_ZIP" ]] || die "--firmware must not be the OTA zip itself."
    [[ $(hex_at "$FIRMWARE_ZIP" 0 4) == 504b0304 ]] || die "--firmware '$FIRMWARE_ZIP' is not a ZIP archive."
    if command -v unzip >/dev/null 2>&1; then
        unzip -tqq -- "$FIRMWARE_ZIP" >/dev/null 2>&1 || die "--firmware '$FIRMWARE_ZIP' failed the ZIP integrity test."
    else
        [[ -n $(zip_list "$FIRMWARE_ZIP" 2>/dev/null) ]] || die "--firmware '$FIRMWARE_ZIP' failed the ZIP listing."
    fi
    ok "firmware ZIP is structurally valid: $FIRMWARE_ZIP"
}

# sideload_zip <zip>: runs adb sideload and returns its exit status. No flag is passed
# that could weaken recovery's signature verification.
sideload_zip() {
    local rc=0
    log "sideload $1"
    "$ADB" -s "$SERIAL" sideload "$1" || rc=$?
    log "adb sideload exit=$rc"
    return "$rc"
}

sideload_firmware() {
    local fw_hash rc=0
    fw_hash=$(sha256sum -- "$FIRMWARE_ZIP" | awk '{print $1}')
    step "Firmware sideload (serial $SERIAL)"
    cat <<EOF
  firmware: $FIRMWARE_ZIP
  sha256:   $fw_hash
  This ZIP is yours. This script cannot tell whether it matches your device, its
  region or this release. If it is not signed by this release's key, recovery shows
  "Signature verification failed" and "Install untrusted package?" with items
  No / Yes. That prompt is EXPECTED for stock firmware: choose Yes on the phone
  yourself to continue. Choosing No aborts. The script cannot see or answer it.
EOF
    confirm "FIRMWARE $SERIAL" "Sideload YOUR firmware ZIP above to $SERIAL now. The OTA is NOT sent in this step." || die "Not confirmed; nothing was sideloaded."
    state_set SIDELOAD_STARTED 1
    state_set INSTALL_CONFIRMED 0
    state_set FIRMWARE_SHA256 "$fw_hash"
    state_set FIRMWARE_ATTESTED 0
    sideload_zip "$FIRMWARE_ZIP" || rc=$?
    if (( rc != 0 )); then
        die "adb sideload of the firmware ZIP exited with status $rc (see the phone's recovery screen: the package may have been rejected). Stopped; the OTA was not sideloaded. Fix the cause, return to Apply from ADB and rerun. If recovery actually reported success, rerun ./flash.sh sideload without --firmware."
    fi
    cat <<EOF

${C_BLD}adb sideload exited with status 0. That is NOT proof that recovery accepted the firmware.${C_OFF}
Read the phone's recovery screen. After you answered the untrusted-package prompt
(if it appeared), recovery must report the install as completed successfully, with
no error and no "Installation aborted". The script will NOT reboot the device.
EOF
    confirm "FIRMWARE-OK $SERIAL" "Type this ONLY if the recovery screen itself reported success for the firmware ZIP; it is recorded as your attestation." ||
        die "Firmware not attested; stopped before the OTA. Do not reboot into the system. Return to Apply from ADB and rerun."
    state_set FIRMWARE_ATTESTED 1
    log "firmware attested by operator sha256=$fw_hash"
    cat <<EOF

${C_BLD}Now, by hand in recovery${C_OFF}: re-enter  Apply update -> Apply from ADB.
EOF
    wait_for_sideload_state
}

sideload_copy_partitions() {
    local rc=0 cp_hash
    cp_hash=$(sums_hash "$COPY_PARTITIONS_REL")
    step "A/B firmware slot alignment (serial $SERIAL)"
    cat <<EOF
  helper: $COPY_PARTITIONS_REL
  sha256: $cp_hash
  Mirrors the active slot's 28 non-OS slotted firmware / boot-LUN partitions to the
  inactive slot (skipping byte-identical partitions; leaves 7 OS boot partitions,
  super, userdata, persist, metadata, and RF calibration untouched).
EOF
    confirm "COPY-PARTITIONS $SERIAL" "Mirror active-slot firmware to inactive slot on $SERIAL via $COPY_PARTITIONS_REL now." ||
        die "Not confirmed; nothing was sideloaded."
    state_set COPY_PARTITIONS_ATTESTED 0
    state_set SIDELOAD_STARTED 1
    sideload_zip "$COPY_PARTITIONS_ZIP" || rc=$?
    if (( rc != 0 )); then
        die "adb sideload of $COPY_PARTITIONS_REL exited with status $rc (check recovery screen). Stopped before YAAP OTA."
    fi
    cat <<EOF

${C_BLD}adb sideload exited with status 0. Read the recovery screen.${C_OFF}
Recovery must show "Done (...): ... copied, ... already matched." with no error and no
"Installation aborted".
EOF
    confirm "COPY-OK $SERIAL" "Type this ONLY if recovery reported $COPY_PARTITIONS_REL completed successfully." ||
        die "Slot alignment not attested; stopped. Re-enter Apply from ADB and rerun."
    state_set COPY_PARTITIONS_ATTESTED 1
    log "copy-partitions attested by operator sha256=$cp_hash"
}

cmd_copy_partitions() {
    verify_bundle
    resolve_device adb
    init_state
    [[ $DEV_STATE == sideload ]] ||
        die "ADB state of $SERIAL is '$DEV_STATE', not 'sideload'. In recovery choose Apply update -> Apply from ADB and rerun."
    sideload_copy_partitions
    info "Done. Re-enter Apply update -> Apply from ADB on the phone before sideloading YAAP."
}

cmd_sideload() {
    verify_bundle
    resolve_device adb
    init_state
    [[ $(state_get FLASH_DONE) == 1 ]] || die "No completed 'flash' phase is recorded for $SERIAL. Run ./flash.sh flash first."
    [[ $(state_get INSTALL_CONFIRMED) != 1 ]] || die "This OTA install is already recorded as complete."
    [[ $(state_get BUNDLE_SHA256) == "$(bundle_digest)" ]] || die "SHA256SUMS changed since the images were flashed; use the original bundle."
    [[ $(state_get OTA_SHA256) == "$(sums_hash "$OTA_REL")" ]] || die "The OTA zip differs from the one recorded at flash time."
    [[ $DEV_STATE == sideload ]] ||
        die "ADB state of $SERIAL is '$DEV_STATE', not 'sideload'. In recovery: Factory reset -> Format data, then Apply update -> Apply from ADB; rerun afterwards."
    if (( ! SKIP_COPY_PARTITIONS )) && [[ $(state_get COPY_PARTITIONS_ATTESTED) != 1 ]]; then
        sideload_copy_partitions
        cat <<EOF

${C_BLD}Now, by hand in recovery${C_OFF}: re-enter  Apply update -> Apply from ADB.
EOF
        wait_for_sideload_state
    fi
    [[ -z $FIRMWARE_ZIP ]] || { verify_firmware_zip; sideload_firmware; }
    step "Sideload (serial $SERIAL)"
    cat <<EOF
  OTA:    $OTA_REL
  sha256: $(sums_hash "$OTA_REL")
  Before continuing you must have done, by hand in recovery:
    * Factory reset -> Format data / factory reset   (never done by this script)
    * Apply update -> Apply from ADB
EOF
    confirm "SIDELOAD $SERIAL" "Data is formatted and the phone shows 'Apply from ADB'. Sideload $OTA_REL to $SERIAL." || die "Not confirmed."
    state_set SIDELOAD_STARTED 1
    state_set INSTALL_CONFIRMED 0
    local rc=0
    sideload_zip "$OTA_ZIP" || rc=$?
    cat <<EOF

${C_BLD}adb sideload exited with status $rc. That is NOT proof of a successful install.${C_OFF}
Read the phone's recovery screen. It must report the install as completed
successfully, with no error and no "Installation aborted". The script will NOT
reboot the device.
EOF
    if confirm "INSTALL-OK $SERIAL" "Type this ONLY if the recovery screen itself reported success; it is recorded as your attestation."; then
        state_set INSTALL_CONFIRMED 1
        log "install attested by operator"
        info "Recorded. Now choose 'Reboot system now' on the phone yourself; first boot can take several minutes."
    else
        info "Nothing recorded. Do not reboot into the system until recovery reports success."
        info "If the install failed: reboot to recovery, Apply from ADB, rerun ./flash.sh sideload."
        exit 1
    fi
}

cmd_status() {
    resolve_device adb fastboot
    init_state
    info "State file: $STATE_FILE"
    cat -- "$STATE_FILE"
}

main() {
    local cmd=${1:-}
    [[ -n $cmd ]] || { usage; exit 2; }
    shift
    while (($#)); do
        case $1 in
            -s|--serial) [[ $# -ge 2 ]] || die "$1 needs a value."; SERIAL=$2; shift 2 ;;
            --serial=*)  SERIAL=${1#--serial=}; shift ;;
            --firmware)  [[ $# -ge 2 ]] || die "$1 needs a value."; FIRMWARE_ZIP=$2; shift 2 ;;
            --firmware=*) FIRMWARE_ZIP=${1#--firmware=}; shift ;;
            --skip-copy-partitions) SKIP_COPY_PARTITIONS=1; shift ;;
            -h|--help)   usage; exit 0 ;;
            *) die "Unknown argument: $1 (see --help)." ;;
        esac
    done
    [[ -z $SERIAL ]] || valid_serial "$SERIAL"
    [[ -z $FIRMWARE_ZIP || $cmd == sideload ]] || die "--firmware is only valid with the sideload command."
    (( ! SKIP_COPY_PARTITIONS )) || [[ $cmd == sideload ]] || die "--skip-copy-partitions is only valid with the sideload command."
    case $cmd in
        verify)          verify_bundle ;;
        flash)           require_tty; cmd_flash ;;
        copy-partitions) require_tty; cmd_copy_partitions ;;
        sideload)        require_tty; cmd_sideload ;;
        status)          cmd_status ;;
        -h|--help|help)  usage ;;
        *) usage; exit 2 ;;
    esac
}

main "$@"
