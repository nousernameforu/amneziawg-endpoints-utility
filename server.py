#!/usr/bin/env python3
"""
awg-endpoints — local web editor for the AmneziaWG `endpoints` section of a
sing-box config.

Reads/writes:
  /etc/sing-box/config.json      the real sing-box config (only `endpoints` is
                                 rewritten; every other section is preserved
                                 byte-for-byte in structure and order)
  /etc/sing-box/awg-vault.json   sidecar owned by this app: peer private keys,
                                 server public key, peer names, client defaults

Stdlib only. Bind to localhost unless you know what you are doing.
"""

import argparse
import base64
import io
import json
import os
import posixpath
import re
import shlex
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

APP_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(APP_DIR, "static")
MAX_BODY = 8 * 1024 * 1024

# --------------------------------------------------------------------------
# X25519 (RFC 7748) — pure Python so the tool has no pip dependencies.
# Not constant-time; acceptable for local key generation on a box you own.
# --------------------------------------------------------------------------

_P = 2 ** 255 - 19
_A24 = 121665


def _cswap(swap, a, b):
    dummy = (-swap) & (a ^ b)
    return a ^ dummy, b ^ dummy


def _x25519(k_bytes, u_bytes):
    k = bytearray(k_bytes)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(bytes(k), "little")
    u = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)

    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = kt

        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = pow(da + cb, 2, _P)
        z3 = x1 * pow(da - cb, 2, _P) % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P

    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)
    return ((x2 * pow(z2, _P - 2, _P)) % _P).to_bytes(32, "little")


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _unb64(s):
    raw = base64.b64decode(s, validate=True)
    if len(raw) != 32:
        raise ValueError("key must decode to 32 bytes, got %d" % len(raw))
    return raw


def gen_private_key():
    k = bytearray(os.urandom(32))
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return _b64(bytes(k))


def public_from_private(priv_b64):
    return _b64(_x25519(_unb64(priv_b64), b"\x09" + b"\x00" * 31))


def gen_psk():
    return _b64(os.urandom(32))


# --------------------------------------------------------------------------
# config.json handling
# --------------------------------------------------------------------------

ENDPOINT_KEY_ORDER = [
    "type", "tag", "address", "private_key", "listen_port", "mtu",
    "jc", "jmin", "jmax",
    "s1", "s2", "s3", "s4",
    "h1", "h2", "h3", "h4",
    "i1", "i2", "i3", "i4", "i5",
    "peers",
]
PEER_KEY_ORDER = [
    "public_key", "pre_shared_key", "allowed_ips",
    "address", "port", "persistent_keepalive_interval", "reserved",
]


def _reorder(d, order):
    if not isinstance(d, dict):
        return d
    out = {k: d[k] for k in order if k in d}
    for k, v in d.items():          # anything we don't know about survives
        if k not in out:
            out[k] = v
    return out


def canonicalize(config):
    """Put AmneziaWG endpoints into the conventional key order. Non-wireguard
    endpoints and all other config sections are left exactly as they were."""
    eps = config.get("endpoints")
    if not isinstance(eps, list):
        return config
    new = []
    for ep in eps:
        if isinstance(ep, dict) and ep.get("type") == "wireguard":
            ep = _reorder(ep, ENDPOINT_KEY_ORDER)
            if isinstance(ep.get("peers"), list):
                ep["peers"] = [_reorder(p, PEER_KEY_ORDER) for p in ep["peers"]]
        new.append(ep)
    config["endpoints"] = new
    return config


def read_json(path, default):
    if not os.path.exists(path):
        return default, False
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh), True


def write_json(path, data, keep_backups, mode=None):
    """Timestamped backup, then atomic replace. Returns backup path or None."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    backup = None

    if os.path.exists(path):
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = "%s.bak-%s" % (path, stamp)
        n = 1
        while os.path.exists(backup):
            backup = "%s.bak-%s.%d" % (path, stamp, n)
            n += 1
        with open(path, "rb") as src, open(backup, "wb") as dst:
            dst.write(src.read())
        _prune_backups(path, keep_backups)
        if mode is None:
            mode = os.stat(path).st_mode & 0o7777

    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".awgtmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return backup


def _prune_backups(path, keep):
    if keep <= 0:
        return
    directory = os.path.dirname(os.path.abspath(path)) or "."
    base = os.path.basename(path) + ".bak-"
    found = sorted(
        (f for f in os.listdir(directory) if f.startswith(base)),
        reverse=True,
    )
    for stale in found[keep:]:
        try:
            os.unlink(os.path.join(directory, stale))
        except OSError:
            pass


EMPTY_VAULT = {"version": 1, "endpoints": {}}


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "awg-endpoints"
    protocol_version = "HTTP/1.1"

    # -- plumbing ---------------------------------------------------------

    def log_message(self, fmt, *args):
        sys.stderr.write("%s  %s\n" % (self.log_date_time_string(), fmt % args))

    def _send(self, code, body, ctype, extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False), "application/json")

    def _fail(self, code, msg):
        self._json(code, {"error": msg})

    def _body(self):
        """Always consumes the whole body — leaving bytes in the stream would
        desync the next request on a keep-alive connection."""
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY:
            raise ValueError("request body too large")
        raw = self.rfile.read(length)
        if not raw.strip():
            return {}
        return json.loads(raw.decode("utf-8"))

    # -- routes -----------------------------------------------------------

    def do_GET(self):
        path = urlparse(self.path).path
        try:
            if path == "/api/state":
                return self.api_state()
            if path.startswith("/api/"):
                return self._fail(404, "no such endpoint")
            return self.serve_static(path)
        except Exception as exc:                      # noqa: BLE001
            self._fail(500, "%s: %s" % (type(exc).__name__, exc))

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            body = self._body()       # drained before anything can go wrong
        except Exception as exc:                      # noqa: BLE001
            self.close_connection = True
            return self._fail(400, "bad request body: %s" % exc)
        try:
            if path == "/api/save":
                return self.api_save(body)
            if path == "/api/keypair":
                return self.api_keypair(body)
            if path == "/api/psk":
                return self._json(200, {"pre_shared_key": gen_psk()})
            if path == "/api/restart":
                return self.api_restart()
            if path == "/api/bundle":
                return self.api_bundle(body)
            return self._fail(404, "no such endpoint")
        except Exception as exc:                      # noqa: BLE001
            self._fail(400, "%s: %s" % (type(exc).__name__, exc))

    # -- static -----------------------------------------------------------

    def serve_static(self, path):
        if path == "/":
            path = "/index.html"
        clean = posixpath.normpath(path).lstrip("/")
        target = os.path.join(STATIC_DIR, clean)
        if not os.path.abspath(target).startswith(STATIC_DIR + os.sep):
            return self._fail(403, "forbidden")
        if not os.path.isfile(target):
            return self._fail(404, "not found")
        with open(target, "rb") as fh:
            data = fh.read()
        ctype = MIME.get(os.path.splitext(target)[1], "application/octet-stream")
        self._send(200, data, ctype)

    # -- api --------------------------------------------------------------

    def api_state(self):
        opts = self.server.opts
        errors = []
        try:
            config, cfg_exists = read_json(opts.config, {"endpoints": []})
        except json.JSONDecodeError as exc:
            return self._fail(500, "config.json is not valid JSON: %s" % exc)
        try:
            vault, vault_exists = read_json(opts.vault, json.loads(json.dumps(EMPTY_VAULT)))
        except json.JSONDecodeError as exc:
            vault, vault_exists = json.loads(json.dumps(EMPTY_VAULT)), True
            errors.append("vault is not valid JSON, starting empty: %s" % exc)

        if not isinstance(config.get("endpoints"), list):
            config["endpoints"] = []
        if not isinstance(vault.get("endpoints"), dict):
            vault["endpoints"] = {}

        self._json(200, {
            "config": config,
            "vault": vault,
            "meta": {
                "config_path": os.path.abspath(opts.config),
                "vault_path": os.path.abspath(opts.vault),
                "config_exists": cfg_exists,
                "vault_exists": vault_exists,
                "read_only": opts.read_only,
                "restart_enabled": bool(opts.restart_cmd),
                "restart_cmd": opts.restart_cmd or "",
                "errors": errors,
            },
        })

    def api_save(self, body):
        opts = self.server.opts
        if opts.read_only:
            return self._fail(403, "server started with --read-only")
        config = body.get("config")
        vault = body.get("vault")
        if not isinstance(config, dict):
            return self._fail(400, "missing 'config' object")
        if not isinstance(config.get("endpoints"), list):
            return self._fail(400, "config.endpoints must be a list")
        if not isinstance(vault, dict):
            vault = json.loads(json.dumps(EMPTY_VAULT))

        cfg_backup = write_json(opts.config, canonicalize(config), opts.keep_backups)
        vault_backup = write_json(opts.vault, vault, opts.keep_backups, mode=0o600)
        self._json(200, {
            "ok": True,
            "config_backup": cfg_backup,
            "vault_backup": vault_backup,
            "saved_at": datetime.now().isoformat(timespec="seconds"),
        })

    def api_keypair(self, body):
        priv = (body.get("private_key") or "").strip()
        if priv:
            try:
                pub = public_from_private(priv)
            except Exception as exc:                  # noqa: BLE001
                return self._fail(400, "invalid private key: %s" % exc)
        else:
            priv = gen_private_key()
            pub = public_from_private(priv)
        self._json(200, {"private_key": priv, "public_key": pub})

    def api_restart(self):
        opts = self.server.opts
        if opts.read_only:
            return self._fail(403, "server started with --read-only")
        if not opts.restart_cmd:
            return self._fail(403, "restart not enabled (start with --restart-cmd)")
        proc = subprocess.run(
            shlex.split(opts.restart_cmd),
            capture_output=True, text=True, timeout=60,
        )
        self._json(200 if proc.returncode == 0 else 500, {
            "ok": proc.returncode == 0,
            "code": proc.returncode,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-4000:],
        })

    def api_bundle(self, body):
        """Zip up whatever text files the frontend hands us (peer .conf files)."""
        files = body.get("files")
        if not isinstance(files, list) or not files:
            return self._fail(400, "expected non-empty 'files' list")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for item in files:
                name = str(item.get("name") or "").strip()
                if not name or "/" in name or "\\" in name or name.startswith("."):
                    return self._fail(400, "bad filename: %r" % name)
                zf.writestr(name, str(item.get("content") or ""))
        data = buf.getvalue()
        self._send(200, data, "application/zip", {
            "Content-Disposition": 'attachment; filename="awg-clients.zip"',
        })


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="/etc/sing-box/config.json",
                    help="path to the sing-box config (default: %(default)s)")
    ap.add_argument("--vault", default="/etc/sing-box/awg-vault.json",
                    help="path to the key sidecar (default: %(default)s)")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default: %(default)s)")
    ap.add_argument("--port", type=int, default=8787,
                    help="bind port (default: %(default)s)")
    ap.add_argument("--keep-backups", type=int, default=10,
                    help="how many timestamped backups to retain (default: %(default)s)")
    ap.add_argument("--read-only", action="store_true",
                    help="serve the editor but refuse to write anything")
    ap.add_argument("--restart-cmd", default="",
                    help="enable the Restart button, e.g. 'systemctl restart sing-box'")
    opts = ap.parse_args(argv)

    if not os.path.isdir(STATIC_DIR):
        sys.exit("missing static/ directory next to server.py")

    httpd = ThreadingHTTPServer((opts.host, opts.port), Handler)
    httpd.opts = opts
    print("awg-endpoints on http://%s:%d" % (opts.host, opts.port))
    print("  config : %s" % os.path.abspath(opts.config))
    print("  vault  : %s" % os.path.abspath(opts.vault))
    if opts.read_only:
        print("  mode   : READ-ONLY")
    if opts.restart_cmd:
        print("  restart: %s" % opts.restart_cmd)
    if opts.host not in ("127.0.0.1", "::1", "localhost"):
        print("  WARNING: bound to a non-loopback address; this app has no auth.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
