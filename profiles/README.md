# PHP2Shell profiles

Profiles are per-build, not per-version strings. A profile is usable for the
RCE chain only when it has:

- `libphp.zif_system`, `libphp.zval_ptr_dtor`, `libphp.htdata`
- stage 1 index and forged-block length
- stage 2 array index and value length
- stage 3 pads and carrier flag
- an OOM body size and target configuration

`catalog.json` contains the known public profiles. Individual `*.json`
profiles override a catalog entry with the same `name`; `calibrate_session.py
--out profiles/foo.json` can add one.

## Status

| Build | Arch | Profile state |
|---|---|---|
| PHP 8.5.11 | x86_64 | verified RCE, official `php:8.5.11-apache`, 8M |
| PHP 8.5.11 | aarch64 | verified RCE (public profile) |
| PHP 8.4.26 | x86_64 | verified RCE at 8M and 128M |
| PHP 8.5.10 | aarch64 | verified RCE |
| PHP 8.4.25 | aarch64 | verified RCE; probabilistic stage 3 |
| PHP 8.3.35 | aarch64 | stage 1/2 only |
| PHP 8.3.33 WordPress | aarch64 | stage 1/2 only |
| PHP 8.5.0 | aarch64 | stage 1/2 only |
| PHP 8.3.0 / 8.2.34 | aarch64 | calibration failed |
| PHP 8.1 / 8.0 / 7.4 | aarch64 | offsets only |

Unknown builds must be calibrated. An offset entry without `htdata` and stage
parameters is not an RCE profile; the fingerprint tool will mark it
incompatible for automatic execution.

## Sources and trust

Offsets and heap parameters in this catalog come from the public devploit
PHP2Shell profile set:

```text
https://github.com/devploit/php2shell/tree/main/profiles
```

The 8.5.11 x86_64 entry was additionally exercised in this lab:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

ASLR changes every address; only the relative offsets and heap parameters are
stored. `measured` examples in the public profiles are not runtime constants.

## Adding a profile

1. Get the exact target image/build and architecture.
2. Extract `zif_system`, `zval_ptr_dtor`, and the stage-3 carrier offset from
   that libphp.
3. Run `calibrate_session.py` against an authorized one-worker lab.
4. Require a real proof before setting `"rce": true`.
5. Add the JSON file and rerun `python3 fingerprint.py --list-profiles`.

Do not copy an offset from one distro/build to another just because the PHP
version matches.

Persistent-SAPI (nginx/FPM and CLI-server) profiles live in
`profiles/fpm/`; see its README and `fpm_exploit.py`. They are kept separate
from the Apache mod_php catalog.
