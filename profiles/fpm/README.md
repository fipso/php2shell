# Persistent-SAPI profiles

These profiles target `fpm` (nginx/PHP-FPM) or `cli-server` (PHP built-in
server). They are separate from the Apache `mod_php` profiles in
`profiles/catalog.json` and are used by `fpm_exploit.py`.

The 8.2-8.4 profiles and the FPM chain implementation are derived from
[`devploit/php2shell`](https://github.com/devploit/php2shell), MIT licensed.
The `8.5.11-fpm.json` and `php-8.5.11-cli.json` reclaim geometries were
calibrated and verified in this workspace against the local NixOS PHP 8.5.11
nginx+FPM and built-in-server labs. Their HTTP leak fields remain
uncalibrated; use `--local-bases` only on a disposable local lab, or supply
`--chunk/--pie`/a newly calibrated profile.

A verified persistent profile needs `sapi`, `libphp.zif_system`,
`fpm.basic_globals`, `fpm.reclaim_pads`, `fpm.reclaim_size`, and at least one
`fpm.no_oracle.candidates` pair. `rce` and `verified` must both be true.

All persistent profiles are marked `build_specific`. Automatic selection uses
them only when the exact image/build is known; pass `--profile` to force one
after confirming the symbols and heap geometry. The local NixOS 8.5.11 FPM and
CLI profiles are additionally marked `local_only` and must always be selected
explicitly.
