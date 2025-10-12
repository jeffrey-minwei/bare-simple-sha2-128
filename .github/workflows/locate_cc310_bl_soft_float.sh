#!/usr/bin/env bash

# .github/workflows/locate_cc310_bl_soft_float.sh
set -Eeuo pipefail

ROOT="${NRFXLIB_DIR:-${GITHUB_WORKSPACE:-$PWD}/third_party/nrfxlib}"
[[ -d "$ROOT" ]] || { echo "FATAL: nrfxlib not found at $ROOT" >&2; exit 1; }

mapfile -t paths < <(find "$ROOT" -type f -path '*/soft-float/*' -name 'libnrf_cc310_bl*.a' -print | sort -u)

[[ ${#paths[@]} -gt 0 ]] || { echo "FATAL: no libnrf_cc310_bl*.a (soft-float) found under $ROOT" >&2; exit 1; }

printf '%s\n' "${paths[@]}"

{
  echo 'cc310_bl_paths<<EOF'
  printf '%s\n' "${paths[@]}"
  echo 'EOF'
} >> "${GITHUB_OUTPUT:-/dev/null}"
