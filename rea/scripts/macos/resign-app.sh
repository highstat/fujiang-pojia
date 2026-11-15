#!/usr/bin/env bash
# Re-sign a modified macOS app bundle.
#
# Usage:
#   ./resign-app.sh <path/to/Foo.app> [entitlements.plist]
#
# The signature is invalid after any edit to a Mach-O, and the kernel kills
# the process. Sign nested code first, then the bundle.
set -euo pipefail

APP="${1:?usage: resign-app.sh <path/to/Foo.app> [entitlements.plist]}"
ENTITLEMENTS="${2:-}"

command -v codesign >/dev/null || { echo "codesign is not available" >&2; exit 1; }
[ -d "$APP" ] || { echo "not a directory: $APP" >&2; exit 1; }
[ -z "$ENTITLEMENTS" ] || [ -f "$ENTITLEMENTS" ] || { echo "entitlements file is missing" >&2; exit 1; }
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

if [ -z "$ENTITLEMENTS" ]; then
  ENTITLEMENTS="$WORK_DIR/original.plist"
  if codesign -d --entitlements :- "$APP" >"$ENTITLEMENTS" 2>/dev/null && [ -s "$ENTITLEMENTS" ]; then
    echo "==> extracted the original entitlements to $ENTITLEMENTS"
  else
    echo "==> no entitlements found, signing without them"
    ENTITLEMENTS=""
  fi
fi

echo "==> removing the existing signature"
rm -rf "$APP/Contents/_CodeSignature"
find "$APP" -type d -name '_CodeSignature' -prune -exec rm -rf {} + 2>/dev/null || true

echo "==> signing nested code (frameworks, plugins, XPC services, helpers)"
while IFS= read -r -d '' item; do
  [ -n "$item" ] || continue
  [ "$item" != "$APP" ] || continue
  if [ -f "$item" ]; then
    case "$(file -b "$item")" in *Mach-O*) ;; *) continue ;; esac
  else
    case "$item" in *.framework|*.appex|*.xpc|*.bundle|*.app) ;; *) continue ;; esac
  fi
  echo "    $item"
  if codesign -d --entitlements :- "$item" >"$WORK_DIR/nested.plist" 2>/dev/null && [ -s "$WORK_DIR/nested.plist" ]; then
    codesign --force --sign - --entitlements "$WORK_DIR/nested.plist" "$item"
  else
    codesign --force --sign - "$item"
  fi
done < <(
  find "$APP" -depth \( -type f -o -type d \) -print0
)

echo "==> signing the bundle"
if [ -n "$ENTITLEMENTS" ] && [ -f "$ENTITLEMENTS" ]; then
  codesign --force --sign - --entitlements "$ENTITLEMENTS" "$APP"
else
  codesign --force --sign - "$APP"
fi

echo "==> verifying"
codesign -v --deep --strict --verbose=2 "$APP"

echo "==> done: $APP"
echo "    note: an ad-hoc signature is not trusted by Gatekeeper."
echo "    for a locally built app: xattr -dr com.apple.quarantine \"$APP\""
