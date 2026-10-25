#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/php-8.5.11"

APXS=$(command -v apxs)
PREFIX="$PWD/../php-install-nofilter"

CFLAGS="-O2 -g -fno-omit-frame-pointer -fno-stack-protector" \
./configure \
  --prefix="$PREFIX" \
  --with-apxs2="$APXS" \
  --disable-all \
  --enable-session \
  --enable-cli \
  --disable-cgi \
  --disable-phpdbg \
  --disable-zts \
  --without-pear \
  --with-config-file-path="$PREFIX/lib" \
  --with-config-file-scan-dir="$PREFIX/lib/conf.d" \
  CFLAGS="-O2 -g -fno-omit-frame-pointer -fno-stack-protector"

make clean
make -j"$(nproc)"
mkdir -p "$PREFIX/modules" "$PREFIX/lib" "$PREFIX/bin"
cp -v libs/libphp.so "$PREFIX/modules/libphp.so"
cp -v sapi/cli/php "$PREFIX/bin/php"
