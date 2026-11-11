#!/bin/sh
set -eu
bundle_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec /bin/sh "$bundle_dir/install.sh" opencode "$@"
