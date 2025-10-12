#!/usr/bin/env bash
# .github/workflows/find_cc31x_files.sh
set -Eeuo pipefail

ROOT="${NRFXLIB_DIR:-${GITHUB_WORKSPACE:-$PWD}/third_party/nrfxlib}"
[[ -d "$ROOT" ]] || { echo "FATAL: nrfxlib not found at $ROOT"; exit 1; }

mapfile -t HITS < <(find "$ROOT" -type f \
  \( -iname '*cc31[02]*.c' -o -iname '*cc31[02]*.h' -o -ipath '*/cc31[02]/*.c' -o -ipath '*/cc31[02]/*.h' \) \
  | sort)

[[ "${#HITS[@]}" -gt 0 ]] || { echo "FATAL: No CC310/CC312 .c/.h files under $ROOT"; exit 1; }
printf 'FOUND: %s\n' "${HITS[@]}"
