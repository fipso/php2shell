#!/usr/bin/env bash
# Stock php:8.4.26-apache lab for the default-config pure-HTTP chain.
#
# The image and its MPM config are untouched: MaxRequestWorkers=150,
# php.ini-production, display_errors=Off, memory_limit=128M, post_max_size=8M.
# The only target-side addition is the trivial echo page and the proof mount.
#
# usage:
#   bash lab/start-pure-8426.sh          # start
#   bash lab/start-pure-8426.sh --down   # stop
#
# Engine: Docker if usable, otherwise rootless Podman.
# Env: IMAGE, NAME, PORT, OUT.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(dirname "$HERE")
IMAGE=${IMAGE:-php:8.4.26-apache}
NAME=${NAME:-p2s-pure-8426}
PORT=${PORT:-18110}
OUT=${OUT:-$REPO/out/pure-8426}

engine=()
if [ -n "${CONTAINER_ENGINE:-}" ]; then
    read -r -a engine <<<"$CONTAINER_ENGINE"
elif docker info >/dev/null 2>&1; then
    engine=(docker)
elif command -v podman >/dev/null 2>&1; then
    engine=(podman)
elif [ -n "${PODMAN:-}" ] && [ -x "$PODMAN" ]; then
    engine=("$PODMAN")
else
    echo "need a usable Docker daemon or Podman" >&2
    exit 1
fi

if [ "${1:-}" = "--down" ]; then
    "${engine[@]}" rm -f "$NAME" >/dev/null 2>&1 || true
    echo "removed $NAME"
    exit 0
fi

if [ ! -f "$HERE/pure/www/index.php" ]; then
    echo "missing $HERE/pure/www/index.php" >&2
    exit 1
fi

mkdir -p "$OUT"
chmod 0777 "$OUT" 2>/dev/null || true
"${engine[@]}" rm -f "$NAME" >/dev/null 2>&1 || true

"${engine[@]}" run -d --name "$NAME" \
    -p "127.0.0.1:${PORT}:80" \
    -v "$HERE/pure/www:/var/www/html:ro" \
    -v "$OUT:/out" \
    "$IMAGE" /bin/sh -c \
    'cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini;
     chown -R www-data:www-data /out;
     exec apache2-foreground' >/dev/null

for _ in $(seq 1 80); do
    if curl -fsS --max-time 1 "http://127.0.0.1:${PORT}/index.php" >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done
if ! curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/index.php" >/dev/null 2>&1; then
    echo "target failed to serve HTTP" >&2
    "${engine[@]}" logs --tail 80 "$NAME" >&2 || true
    exit 1
fi

echo "target: http://127.0.0.1:${PORT}/index.php"
echo "image:  $IMAGE"
echo "proof:  $OUT/p1"
echo "config: stock php.ini-production; official MPM (150 workers)"
"${engine[@]}" exec "$NAME" sh -c \
  'php -i 2>/dev/null | grep -E "^(display_errors|memory_limit|post_max_size|session.save_path)"; grep -v "^#" /etc/apache2/mods-enabled/mpm_prefork.conf | sed "/^$/d"' || true
