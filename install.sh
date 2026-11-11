#!/bin/sh
set -eu
bundle_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
if ! command -v node >/dev/null 2>&1; then
  printf '%s\n' 'Node.js 20 or newer is required. Install it, then run this installer again.' >&2
  exit 1
fi
exec node "$bundle_dir/scripts/install.mjs" "$@"
