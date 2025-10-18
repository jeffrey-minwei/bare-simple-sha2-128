#!/usr/bin/env bash
# Write a concise job summary about cache & toolchain
set -Eeuo pipefail

ARM_DIR="${ARM_DIR:-${RUNNER_TOOL_CACHE:-$HOME/.cache}/arm-gnu-toolchain-${ARM_VER}}"
PRE_HIT="${PRE_HIT:-}"
POST_HIT="${POST_HIT:-}"
BACKEND="${BACKEND:-}"

hit_word() { [[ "$1" == "true" ]] && echo "HIT" || echo "MISS"; }

# Config (override in ci.yml env: ELF_GLOBS, HEX_GLOBS)
ELF_GLOBS="${ELF_GLOBS:-"*.elf **/*.elf"}"
HEX_GLOBS="${HEX_GLOBS:-"*.hex **/*.hex"}"

# Expand globs safely (supports **)
shopt -s nullglob globstar

# Collect files
ELF_FILES=()
for pat in $ELF_GLOBS; do
  for f in $pat; do [[ -f "$f" ]] && ELF_FILES+=("$f"); done
done
HEX_FILES=()
for pat in $HEX_GLOBS; do
  for f in $pat; do [[ -f "$f" ]] && HEX_FILES+=("$f"); done
done

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

  if ((${#ELF_FILES[@]})); then
    echo
    echo "### ELF sizes"
    for f in "${ELF_FILES[@]}"; do
      echo "#### Output size ($f)"
      echo '```'
      (arm-none-eabi-size -A "$f" 2>/dev/null || size -A "$f" || true)
      echo '```'
    done
  fi

  if ((${#HEX_FILES[@]})); then
    echo
    echo "### HEX artifacts"
    for f in "${HEX_FILES[@]}"; do
      # show file size; wc -c is portable enough
      bytes=$(wc -c <"$f" | tr -d ' ')
      echo "- $f (${bytes} bytes)"
    done
  fi

} >> "${GITHUB_STEP_SUMMARY:-/dev/stdout}"
