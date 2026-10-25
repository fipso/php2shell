# php2shell lab

Built by DeepSeek V4 Flash.

This is a lab-only setup for educational research against PHP 8.5.11 mod_php. The vulnerable module and configuration are intentionally unsafe.

Do not run this against systems you do not own or have explicit authorization to test. Keep the lab isolated and do not expose it to an untrusted network.

## Targets

- `bash lab/start-apache.sh` — urlencoded mode, no-filter build, port 18088.
- `bash lab/start-apache-filter.sh` — filter-enabled build, port 18089.
- `bash lab/start-apache-default.sh` — filter-enabled default-ish limits, port 18090.

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
