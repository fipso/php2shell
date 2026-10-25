#!/usr/bin/env bash
# Local PHP CLI built-in server lab for the persistent-SAPI php2shell chain.
#
# The chain server is supervised because zif_system aborts the worker after
# the proof command runs. The supervisor must not replace itself with PHP, or
# the restart disappears.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="$ROOT/lab/fpm"
WEBROOT="$LAB/webroot"
INI="$LAB/php.ini"
BASE="$LAB/runtime/php-8.5.11"
CLI="$BASE/cli"
SESSION="$CLI/session"
CHAIN_PORT="${P2S_CLI_CHAIN_PORT:-18098}"
BUILDER_PORT="${P2S_CLI_BUILDER_PORT:-18099}"

stop() {
    for name in chain-supervisor chain builder; do
        if [[ -f "$CLI/$name.pid" ]]; then
            kill "$(cat "$CLI/$name.pid")" 2>/dev/null || true
            rm -f "$CLI/$name.pid"
        fi
    done
    # Children are in their own process group; be narrow about the ports.
    pkill -f -- "-S 127.0.0.1:$CHAIN_PORT" 2>/dev/null || true
    pkill -f -- "-S 127.0.0.1:$BUILDER_PORT" 2>/dev/null || true
}

if [[ "${1:-}" == "--down" ]]; then
    stop
    echo "PHP CLI lab stopped"
    exit 0
fi

if [[ -z "${PHP_CLI:-}" ]]; then
    if command -v php >/dev/null 2>&1; then
        PHP_CLI="$(command -v php)"
    else
        php_root="$(nix build --no-link --print-out-paths nixpkgs#php85 2>/dev/null | tail -1)"
        PHP_CLI="$php_root/bin/php"
    fi
fi
if [[ ! -x "$PHP_CLI" ]]; then
    echo "missing php: $PHP_CLI" >&2
    exit 1
fi

mkdir -p "$SESSION" "$CLI" "$WEBROOT/out"
stop
: >"$CLI/chain.log"
: >"$CLI/builder.log"

common=(
    -c "$INI"
    -d "session.save_path=$SESSION"
    -d "session.use_strict_mode=Off"
    -d "session.use_only_cookies=On"
    -d "session.upload_progress.enabled=On"
    -d "auto_globals_jit=0"
    -d "post_max_size=128M"
    -d "upload_max_filesize=128M"
    -d "display_errors=On"
    -d "display_startup_errors=On"
)

# Builder: 64M, keeps upload-progress session files (cleanup Off).
(
    cd "$WEBROOT"
    exec "$PHP_CLI" "${common[@]}" \
        -d memory_limit=64M \
        -d session.upload_progress.cleanup=Off \
        -S "127.0.0.1:$BUILDER_PORT" -t .
) >>"$CLI/builder.log" 2>&1 &
echo $! >"$CLI/builder.pid"

# Chain supervisor: 8M, cleanup On. The loop remains the parent, PHP is the
# replaceable child, so a post-command abort is restarted.
setsid bash -c '
    ROOT="$1"; WEBROOT="$2"; PHP_CLI="$3"; CLI="$4"; PORT="$5"; shift 5
    while true; do
        (
            cd "$WEBROOT" || exit 1
            exec "$PHP_CLI" "$@" -d memory_limit=8M \
                -d session.upload_progress.cleanup=On \
                -S "127.0.0.1:$PORT" -t .
        ) >>"$CLI/chain.log" 2>&1 &
        child=$!
        echo "$child" >"$CLI/chain.pid"
        wait "$child" || true
        sleep 0.1
    done
' _ "$ROOT" "$WEBROOT" "$PHP_CLI" "$CLI" "$CHAIN_PORT" \
    "${common[@]}" </dev/null >/dev/null 2>&1 &
echo $! >"$CLI/chain-supervisor.pid"

for _ in $(seq 1 100); do
    if curl -fsS --max-time 1 "http://127.0.0.1:$CHAIN_PORT/index.php" >/dev/null 2>&1 &&
       curl -fsS --max-time 1 "http://127.0.0.1:$BUILDER_PORT/index.php" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

if ! curl -fsS --max-time 2 "http://127.0.0.1:$CHAIN_PORT/index.php" >/dev/null 2>&1; then
    echo "PHP CLI chain failed to start; log:" >&2
    tail -40 "$CLI/chain.log" >&2 || true
    exit 1
fi
if ! curl -fsS --max-time 2 "http://127.0.0.1:$BUILDER_PORT/index.php" >/dev/null 2>&1; then
    echo "PHP CLI builder failed to start; log:" >&2
    tail -40 "$CLI/builder.log" >&2 || true
    exit 1
fi

pid="$(cat "$CLI/chain.pid" 2>/dev/null || true)"
cat <<EOF

PHP CLI built-in server lab:
  chain:   http://127.0.0.1:$CHAIN_PORT/app.php  (pid $pid, supervised)
  builder: http://127.0.0.1:$BUILDER_PORT/app.php
  profile: $ROOT/profiles/fpm/php-8.5.11-cli.json

Run the chain (local maps for ASLR bases):
  python3 "$ROOT/fpm_exploit.py" \\
    --base http://127.0.0.1:$CHAIN_PORT \\
    --builder http://127.0.0.1:$BUILDER_PORT \\
    --version 8.5.11 --profile "$ROOT/profiles/fpm/php-8.5.11-cli.json" \\
    --pid "\$(cat "$CLI/chain.pid")" \\
    --command 'id>out/cli-p1' --proof-file out/cli-p1 \\
    no-oracle --local-bases

Stop:
  bash "$ROOT/lab/start-php-cli.sh" --down
EOF
