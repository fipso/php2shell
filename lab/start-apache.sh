#!/usr/bin/env bash
set -euo pipefail
dir="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$dir/sessions" "$dir/www"

if [[ -f "$dir/httpd.pid" ]] && kill -0 "$(cat "$dir/httpd.pid")" 2>/dev/null; then
    echo "already running: $(cat "$dir/httpd.pid")"
    exit 0
fi

httpd=/nix/store/yail3prbsk5v6rc212830bf3zl1j6zgj-apache-httpd-2.4.69/bin/httpd
launcher=(setarch "$(uname -m)" -R)
if [[ "${LAB_ASLR:-0}" == "1" ]]; then
    launcher=()
fi
: > "$dir/httpd-console.log"
nohup "${launcher[@]}" "$httpd" -X -f "$dir/httpd.conf" \
    >"$dir/httpd-console.log" 2>&1 &
echo $! > "$dir/httpd.pid"

for _ in $(seq 1 50); do
    if curl -fsS --max-time 1 http://127.0.0.1:18088/index.php >/dev/null 2>&1; then
        echo "started pid $(cat "$dir/httpd.pid")"
        exit 0
    fi
    sleep 0.1
done
echo "start failed"
cat "$dir/httpd-console.log" "$dir/httpd-error.log" 2>/dev/null || true
exit 1
