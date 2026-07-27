#!/usr/bin/env bash
set -euo pipefail

version="${1:-0.1.0}"
dst="${2:-android/out}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dst_abs="${repo_root}/${dst}"

mkdir -p "${dst_abs}/tlsclient/include"
mkdir -p "${dst_abs}/tlsclient/lib/arm64-v8a"
mkdir -p "${dst_abs}/tlsclient/lib/armeabi-v7a"

cp -f "${repo_root}/src/tlsclient.h" "${dst_abs}/tlsclient/include/"
cp -f "${repo_root}/android/obj/local/arm64-v8a/libtlsclient.a" "${dst_abs}/tlsclient/lib/arm64-v8a/"
cp -f "${repo_root}/android/obj/local/armeabi-v7a/libtlsclient.a" "${dst_abs}/tlsclient/lib/armeabi-v7a/"
cp -f "${repo_root}/android/module.mk" "${dst_abs}/tlsclient/Android.mk"
cp -f "${repo_root}/README.md" "${dst_abs}/tlsclient/"

cd "${dst_abs}"
rm -f "tlsclient-${version}.tar"
tar -cf "tlsclient-${version}.tar" tlsclient
