#!/usr/bin/env bash
# Local nginx + PHP-FPM lab for the persistent-SAPI php2shell chain.
# Authorized lab use only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="$ROOT/lab/fpm"
RUNTIME="$LAB/runtime/php-8.5.11"
VERSION="8.5.11"

if [[ "${1:-}" == "--down" ]]; then
    python3 "$ROOT/fpm_labs.py" down --only "$VERSION"
    exit 0
fi

if [[ -z "${PHP_FPM:-}" ]]; then
    if command -v php-fpm >/dev/null 2>&1; then
        PHP_FPM="$(command -v php-fpm)"
    else
        php_root="$(nix build --no-link --print-out-paths nixpkgs#php85 2>/dev/null | tail -1)"
        PHP_FPM="$php_root/bin/php-fpm"
    fi
fi
if [[ -z "${NGINX_BIN:-}" ]]; then
    if command -v nginx >/dev/null 2>&1; then
        NGINX_BIN="$(command -v nginx)"
    else
        nginx_root="$(nix build --no-link --print-out-paths nixpkgs#nginx 2>/dev/null | tail -1)"
        NGINX_BIN="$nginx_root/bin/nginx"
    fi
fi
if [[ ! -x "$PHP_FPM" ]]; then
    echo "missing php-fpm: $PHP_FPM" >&2
    exit 1
fi
if [[ ! -x "$NGINX_BIN" ]]; then
    echo "missing nginx: $NGINX_BIN" >&2
    exit 1
fi

mkdir -p "$LAB/runtime/php-8.5.11/sbin" "$LAB/runtime/nginx/sbin"
ln -sfn "$PHP_FPM" "$LAB/runtime/php-8.5.11/sbin/php-fpm"
ln -sfn "$NGINX_BIN" "$LAB/runtime/nginx/sbin/nginx"
if [[ ! -e "$LAB/runtime/nginx/conf" ]]; then
    # Nix nginx's conf directory contains fastcgi_params and mime.types.
    nginx_conf="$(dirname "$(dirname "$(readlink -f "$NGINX_BIN")")")/conf"
    ln -sfn "$nginx_conf" "$LAB/runtime/nginx/conf"
fi

# fpm_labs.py renders the two pools and the nginx server blocks, then starts
# both daemons. Ports: chain :8556 -> fpm :8556, builder :8557 -> fpm :8557.
python3 "$ROOT/fpm_labs.py" down --only "$VERSION" >/dev/null 2>&1 || true
python3 "$ROOT/fpm_labs.py" up --only "$VERSION"

cat <<EOF

nginx+FPM lab:
  chain:   http://127.0.0.1:8556/app.php
  builder: http://127.0.0.1:8557/app.php
  profile: $ROOT/profiles/fpm/$VERSION-fpm.json

Run the chain (local maps for ASLR bases):
  python3 "$ROOT/fpm_exploit.py" \\
    --base http://127.0.0.1:8556 --builder http://127.0.0.1:8557 \\
    --version $VERSION --profile "$ROOT/profiles/fpm/$VERSION-fpm.json" \\
    --command 'id>out/p1' --proof-file out/p1 \\
    no-oracle --local-bases

Stop:
  bash "$ROOT/lab/start-nginx-fpm.sh" --down
EOF
