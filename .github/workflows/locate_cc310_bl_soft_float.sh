#!/usr/bin/env bash
# .github/workflows/locate_cc310_bl_soft_float.sh

set -euo pipefail

ROOT="${NRFXLIB_DIR:-${GITHUB_WORKSPACE:-$PWD}/third_party/nrfxlib}"
[ -d "$ROOT" ] || { echo "FATAL: nrfxlib not found at $ROOT" >&2; exit 1; }

paths="$(find "$ROOT" -type f -name 'libnrf_cc310_bl*.a' 2>/dev/null | grep '/soft-float/' | sort -u || true)"

if [ -z "$paths" ]; then
  echo "FATAL: no libnrf_cc310_bl*.a (soft-float) found under $ROOT" >&2
  find "$ROOT" -type f -name 'libnrf_cc310_bl*.a' 2>/dev/null | sort -u || true
  exit 1
fi

printf '%s\n' "$paths"

{
  echo 'cc310_bl_paths<<EOF'
  printf '%s\n' "$paths"
  echo 'EOF'
} >> "${GITHUB_OUTPUT:-/dev/null}"
