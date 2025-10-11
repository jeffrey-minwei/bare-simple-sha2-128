#!/usr/bin/env bash
set -Eeuo pipefail

d="third_party/mbedtls/library"

# 預期：沒有任何 .a；若目錄不存在也視為通過
if [ -d "$d" ]; then
  bad=0
  for f in libmbedcrypto.a libmbedtls.a libmbedx509.a; do
    if [ -f "$d/$f" ]; then
      echo "UNEXPECTED: $d/$f exists"
      bad=1
    fi
  done
  if [ "$bad" -eq 1 ]; then
    echo "Listing for debug:"
    ls -l "$d"/*.a || true
    exit 1
  fi
  echo "OK: no prebuilt mbedtls static libs under $d"
else
  echo "OK: $d does not exist (expected)"
fi
