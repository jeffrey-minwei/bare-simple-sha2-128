#!/usr/bin/env bash

set -Eeuo pipefail
BASE="third_party/nrfxlib/crypto/nrf_cc3xx_platform/lib"
SUB="cortex-m33/hard-float/no-interrupts"
mapfile -t MATCHES < <(find "$BASE" -type f -path "*/$SUB/libnrf_cc3xx_platform_*.a" | sort -V)
if [ ${#MATCHES[@]} -eq 0 ]; then
echo "ERROR: not found: $BASE/**/$SUB/libnrf_cc3xx_platform_*.a" >&2
echo "Available candidates:" >&2
find "$BASE" -type f -name 'libnrf_cc3xx_platform_*.a' | sort -V >&2 || true
exit 1
fi
LIB_PLAT="${MATCHES[-1]}"
echo "Using: $LIB_PLAT"
echo "LIB_PLAT=$LIB_PLAT" >> "$GITHUB_ENV"
