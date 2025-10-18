#!/usr/bin/env bash
# Write a concise job summary about cache & toolchain
set -Eeuo pipefail

ARM_DIR="${ARM_DIR:-${RUNNER_TOOL_CACHE:-$HOME/.cache}/arm-gnu-toolchain-${ARM_VER}}"
PRE_HIT="${PRE_HIT:-}"
POST_HIT="${POST_HIT:-}"
BACKEND="${BACKEND:-}"

hit_word() { [[ "$1" == "true" ]] && echo "HIT" || echo "MISS"; }

{
  echo "## Build summary"
  echo
  echo "### Arm GNU Toolchain"
  echo "- Version: ${ARM_VER:-unknown}"
  echo "- Install dir: ${ARM_DIR}"
  [[ -n "$PRE_HIT"  ]] && echo "- Cache (restore): $(hit_word "$PRE_HIT")"
  [[ -n "$POST_HIT" ]] && echo "- Cache (post-lookup): $(hit_word "$POST_HIT")"

  if command -v arm-none-eabi-gcc >/dev/null 2>&1; then
    echo "- Compiler: $(arm-none-eabi-gcc -dumpversion) [$(arm-none-eabi-gcc -dumpmachine)]"
  elif command -v aarch64-none-linux-gnu-gcc >/dev/null 2>&1; then
    echo "- Compiler: $(aarch64-none-linux-gnu-gcc -dumpversion) [$(aarch64-none-linux-gnu-gcc -dumpmachine)]"
  fi

  [[ -n "$BACKEND" ]] && echo "- Backend: ${BACKEND}"

  if [[ -f app.elf ]]; then
    echo
    echo "### Output size (app.elf)"
    echo '```'
    (arm-none-eabi-size -A app.elf 2>/dev/null || size -A app.elf || true)
    echo '```'
  fi
} >> "${GITHUB_STEP_SUMMARY:-/dev/stdout}"
