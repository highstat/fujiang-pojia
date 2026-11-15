#!/usr/bin/env bash
# Rebuild, align and sign a patched Android APK.
#
# Usage:
#   ./build-and-sign.sh <decoded-dir> <output.apk> [keystore]
#
# Order matters: rebuild, then align, then sign. Signing before alignment
# invalidates the alignment, and editing a signed APK invalidates the
# signature.
set -euo pipefail

DECODED_DIR="${1:?usage: build-and-sign.sh <decoded-dir> <output.apk> [keystore]}"
OUTPUT_APK="${2:?usage: build-and-sign.sh <decoded-dir> <output.apk> [keystore]}"
KEYSTORE="${3:-${ANDROID_KEYSTORE:-$HOME/.android/debug.keystore}}"
KEY_ALIAS="${ANDROID_KEY_ALIAS:-androiddebugkey}"
STORE_PASS="${ANDROID_STORE_PASS:-android}"
KEY_PASS="${ANDROID_KEY_PASS:-android}"

command -v apktool >/dev/null || { echo "apktool is not installed" >&2; exit 1; }
command -v zipalign >/dev/null || {
  echo "zipalign is not on PATH — it ships with the Android SDK build-tools" >&2
  exit 1
}
command -v apksigner >/dev/null || {
  echo "apksigner is not on PATH — it ships with the Android SDK build-tools" >&2
  exit 1
}

if [ ! -f "$KEYSTORE" ]; then
  echo "keystore not found: $KEYSTORE" >&2
  echo "create one with:" >&2
  echo "  keytool -genkeypair -v -keystore $KEYSTORE -alias $KEY_ALIAS \\" >&2
  echo "          -keyalg RSA -keysize 2048 -validity 10000 \\" >&2
  echo "          -dname 'CN=Dev, O=Dev, C=US'" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

UNSIGNED="$WORK_DIR/unsigned.apk"
ALIGNED="$WORK_DIR/aligned.apk"

echo "==> rebuilding from $DECODED_DIR"
apktool b "$DECODED_DIR" -o "$UNSIGNED"

echo "==> aligning (page-aligned native libraries)"
zipalign -P 16 -f 4 "$UNSIGNED" "$ALIGNED"

echo "==> signing with $KEYSTORE"
export REA_STORE_PASS="$STORE_PASS"
export REA_SIGNING_KEY_PASS="$KEY_PASS"
apksigner sign \
  --ks "$KEYSTORE" \
  --ks-key-alias "$KEY_ALIAS" \
  --ks-pass env:REA_STORE_PASS \
  --key-pass env:REA_SIGNING_KEY_PASS \
  --v1-signing-enabled true \
  --v2-signing-enabled true \
  --v3-signing-enabled true \
  --out "$OUTPUT_APK" \
  "$ALIGNED"

echo "==> verifying"
apksigner verify --verbose --print-certs "$OUTPUT_APK"
zipalign -c -P 16 -v 4 "$OUTPUT_APK"

echo "==> done: $OUTPUT_APK"
