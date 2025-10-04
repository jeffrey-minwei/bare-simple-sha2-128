#!/usr/bin/env bash
set -euo pipefail

cmd="${1:-}"

if [[ "$cmd" == "resolve" ]]; then
  if git ls-tree -r --name-only HEAD | grep -qx "third_party/mbedtls"; then
    MODE=submodule
    SHA="$(git ls-tree HEAD third_party/mbedtls | awk '{print $3}')"
  else
    MODE=remote
    # 要鎖定分支就把 HEAD 改成 refs/heads/v3.6
    SHA="$(git ls-remote https://github.com/Mbed-TLS/mbedtls HEAD | awk '{print $1}')"
  fi
  echo "mode=$MODE" >> "$GITHUB_OUTPUT"
  echo "sha=$SHA"   >> "$GITHUB_OUTPUT"
  exit 0
fi

if [[ "$cmd" == "prepare" ]]; then
  MODE="${MODE:-remote}"
  SHA="${SHA:?missing SHA}"
  if [[ "$MODE" == "submodule" ]]; then
    git submodule update --init --depth=1 third_party/mbedtls
    git -C third_party/mbedtls fetch --depth=1 origin "$SHA"
    git -C third_party/mbedtls checkout "$SHA"
  else
    rm -rf third_party/mbedtls
    git init third_party/mbedtls
    git -C third_party/mbedtls remote add origin https://github.com/Mbed-TLS/mbedtls
    git -C third_party/mbedtls fetch --depth=1 origin "$SHA"
    git -C third_party/mbedtls checkout "$SHA"
  fi
  git -C third_party/mbedtls -c advice.detachedHead=false checkout -q "$SHA"
  test -f third_party/mbedtls/include/mbedtls/version.h

  exit 0
fi

echo "usage: $0 {resolve|prepare}" >&2
exit 2
