#!/usr/bin/env bash
set -euo pipefail
dir="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$dir/sessions" "$dir/www"

if [[ ! -f "$dir/libphp-nts.so" ]]; then
    echo "missing $dir/libphp-nts.so; run build-php-nts.sh and copy the module" >&2
    exit 1
fi

if [[ -f "$dir/httpd-session.pid" ]] && kill -0 "$(cat "$dir/httpd-session.pid")" 2>/dev/null; then
    echo "already running: $(cat "$dir/httpd-session.pid")"
    exit 0
fi

httpd=/nix/store/yail3prbsk5v6rc212830bf3zl1j6zgj-apache-httpd-2.4.69/bin/httpd
launcher=(setarch "$(uname -m)" -R)
if [[ "${LAB_ASLR:-0}" == "1" ]]; then
    launcher=()
fi
: > "$dir/httpd-session-console.log"
nohup "${launcher[@]}" "$httpd" -DFOREGROUND -f "$dir/httpd-session.conf" \
    >"$dir/httpd-session-console.log" 2>&1 &
echo $! > "$dir/httpd-session.pid"

for _ in $(seq 1 50); do
    if curl -fsS --max-time 1 http://127.0.0.1:18091/index.php >/dev/null 2>&1; then
        echo "started pid $(cat "$dir/httpd-session.pid")"
        exit 0
    fi
    sleep 0.1
done
echo "start failed"
cat "$dir/httpd-session-console.log" "$dir/httpd-session-error.log" 2>/dev/null || true
exit 1
