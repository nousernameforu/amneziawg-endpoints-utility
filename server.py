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
import getpass
import hashlib
import hmac
import io
import json
import os
import posixpath
import shlex
import ssl
import subprocess
import sys
import tempfile
import threading
import time
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


# --------------------------------------------------------------------------
# JSONC — sing-box accepts comments, so we must too, and must not eat them.
# --------------------------------------------------------------------------

def strip_jsonc(text):
    """Blank out // and /* */ comments and trailing commas by overwriting them
    with spaces. The result is the same length as the input, so offsets found in
    it point at the same characters in the original — which is what lets us
    splice the endpoints array back without disturbing anything else. Newlines
    survive so parse errors keep their line numbers.

    Returns (clean, had_comments)."""
    out = []
    had_comments = False
    i, n = 0, len(text)
    in_str = esc = False

    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "#" or (c == "/" and i + 1 < n and text[i + 1] == "/"):
            # '#' is not JSONC, but it is never valid JSON outside a string
            # either, so accepting it costs nothing and people type it.
            had_comments = True
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
            continue
        if c == "/" and i + 1 < n:
            if text[i + 1] == "*":
                had_comments = True
                j = text.find("*/", i + 2)
                if j < 0:
                    raise ValueError("unterminated /* comment")
                end = j + 2
                out.append("".join("\n" if ch == "\n" else " " for ch in text[i:end]))
                i = end
                continue
        out.append(c)
        i += 1

    return _drop_trailing_commas("".join(out)), had_comments


def _drop_trailing_commas(text):
    out = []
    i, n = 0, len(text)
    in_str = esc = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
        elif c == ",":
            j = i + 1
            while j < n and text[j].isspace():
                j += 1
            if j < n and text[j] in "}]":
                out.append(" ")             # blank it, preserving length
                i += 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def parse_jsonc(text):
    clean, had_comments = strip_jsonc(text)
    return json.loads(clean), had_comments


def _skip_string(text, i):
    """text[i] is the opening quote; returns the index after the closing one."""
    i += 1
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == '"':
            return i + 1
        i += 1
    raise ValueError("unterminated string")


def _span_of_value(text, i):
    """text[i] opens a { or [; returns the index just past its match."""
    opener = text[i]
    closer = "}" if opener == "{" else "]"
    depth = 0
    while i < len(text):
        c = text[i]
        if c == '"':
            i = _skip_string(text, i)
            continue
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise ValueError("unbalanced %s" % opener)


def find_top_level_key(text, key):
    """Locate a key in the outermost object. Returns (value_start, value_end,
    line_indent) or None. Comments must already be stripped."""
    i, n = 0, len(text)
    depth = 0
    while i < n:
        c = text[i]
        if c == '"':
            start = i
            end = _skip_string(text, i)
            if depth == 1:
                name = json.loads(text[start:end])
                j = end
                while j < n and text[j].isspace():
                    j += 1
                if j < n and text[j] == ":" and name == key:
                    j += 1
                    while j < n and text[j].isspace():
                        j += 1
                    if j < n and text[j] in "[{":
                        line_start = text.rfind("\n", 0, start) + 1
                        indent = len(text[line_start:start]) - len(text[line_start:start].lstrip())
                        return start, _span_of_value(text, j), indent
            i = end
            continue
        if c in "{[":
            depth += 1
        elif c in "}]":
            depth -= 1
        i += 1
    return None


def splice_endpoints(original, config):
    """Rewrite only the endpoints array inside the original text, so comments
    everywhere else survive. Returns None when it cannot be done safely."""
    clean, _ = strip_jsonc(original)
    found = find_top_level_key(clean, "endpoints")
    if not found:
        return None
    key_start, value_end, indent = found

    # The stripped text is the same length as the original, so offsets carry over.
    colon = original.find(":", key_start)
    if colon < 0:
        return None
    value_start = colon + 1
    while value_start < len(original) and original[value_start].isspace():
        value_start += 1

    pad = " " * indent
    body = json.dumps(config.get("endpoints", []), indent=2, ensure_ascii=False)
    body = ("\n" + pad).join(body.split("\n"))
    return original[:value_start] + body + original[value_end:]


def read_json(path, default):
    if not os.path.exists(path):
        return default, False, False
    with open(path, "r", encoding="utf-8") as fh:
        data, had_comments = parse_jsonc(fh.read())
    return data, True, had_comments


def write_config(path, config, keep_backups):
    """Write config.json, keeping comments outside the endpoints array intact.

    Falls back to a plain re-serialisation when the file has no endpoints key,
    or when the spliced text does not parse back to exactly what we intended.
    Returns (backup_path, comments_preserved).
    """
    text = None
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            original = fh.read()
        try:
            candidate = splice_endpoints(original, config)
            if candidate is not None and parse_jsonc(candidate)[0] == config:
                text = candidate
        except Exception:                              # noqa: BLE001
            text = None                                # fall through to rewrite
    if text is None:
        return write_json(path, config, keep_backups), False
    return write_json(path, config, keep_backups, text=text), True


def write_json(path, data, keep_backups, mode=None, text=None):
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

    if text is None:
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
# Basic auth
# --------------------------------------------------------------------------

PBKDF2_ITERS = 240_000
REALM = "awg-endpoints"


def hash_password(password):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS)
    return "pbkdf2_sha256$%d$%s$%s" % (PBKDF2_ITERS, _b64(salt), _b64(dk))


def verify_password(password, stored):
    """Constant-time check against either a pbkdf2 string or a literal password."""
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, iters, salt_b64, hash_b64 = stored.split("$", 3)
            dk = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"),
                base64.b64decode(salt_b64), int(iters),
            )
        except Exception:                              # noqa: BLE001
            return False
        return hmac.compare_digest(_b64(dk), hash_b64)
    return hmac.compare_digest(password, stored)


def load_credentials(opts):
    """Returns (user, secret) or None.

    Precedence: --auth, then a password_file, then AWG_AUTH in the environment,
    then auth.user/auth.password from the config file.
    """
    raw = None
    if opts.auth:
        raw = opts.auth
    elif opts.auth_file:
        with open(opts.auth_file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    raw = line
                    break
        if raw is None:
            raise SystemExit("no credentials found in %s" % opts.auth_file)
    elif os.environ.get("AWG_AUTH"):
        raw = os.environ["AWG_AUTH"]
    elif opts.file_auth_user or opts.file_auth_password:
        if not (opts.file_auth_user and opts.file_auth_password):
            raise SystemExit(
                "%s: auth.user and auth.password must both be set" % opts.settings_path)
        return opts.file_auth_user, opts.file_auth_password

    if raw is None:
        return None
    user, sep, secret = raw.partition(":")
    if not sep or not user or not secret:
        raise SystemExit("credentials must look like 'user:password'")
    return user, secret


class Throttle:
    """Crude per-IP delay so a wrong password is not free to retry."""

    def __init__(self):
        self._fails = {}
        self._lock = threading.Lock()

    def penalty(self, ip):
        with self._lock:
            count, _ = self._fails.get(ip, (0, 0.0))
        return min(count, 8) * 0.25

    def record_failure(self, ip):
        with self._lock:
            count, _ = self._fails.get(ip, (0, 0.0))
            self._fails[ip] = (count + 1, time.time())

    def reset(self, ip):
        with self._lock:
            self._fails.pop(ip, None)


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

    # -- auth -------------------------------------------------------------

    def _client_ip(self):
        return self.client_address[0] if self.client_address else "?"

    def _authorized(self):
        creds = self.server.creds
        if creds is None:
            return True
        user, secret = creds
        header = self.headers.get("Authorization") or ""
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
        except Exception:                              # noqa: BLE001
            return False
        got_user, sep, got_pass = decoded.partition(":")
        if not sep:
            return False
        # Evaluate both halves so timing does not reveal which one was wrong.
        user_ok = hmac.compare_digest(got_user, user)
        pass_ok = verify_password(got_pass, secret)
        return user_ok and pass_ok

    def _require_auth(self):
        """True when the request may proceed; otherwise sends 401."""
        ip = self._client_ip()
        delay = self.server.throttle.penalty(ip)
        if delay:
            time.sleep(delay)
        if self._authorized():
            self.server.throttle.reset(ip)
            return True
        self.server.throttle.record_failure(ip)
        self.log_message("auth failure from %s", ip)
        self._send(401, json.dumps({"error": "authentication required"}),
                   "application/json",
                   {"WWW-Authenticate": 'Basic realm="%s", charset="UTF-8"' % REALM})
        return False

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
        if not self._require_auth():
            return
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
            body = self._body()       # drained first, or a 401 desyncs keep-alive
        except Exception as exc:                      # noqa: BLE001
            self.close_connection = True
            return self._fail(400, "bad request body: %s" % exc)
        if not self._require_auth():
            return
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
            config, cfg_exists, cfg_comments = read_json(opts.config, {"endpoints": []})
        except (json.JSONDecodeError, ValueError) as exc:
            return self._fail(500, "config.json does not parse: %s" % exc)
        try:
            vault, vault_exists, _ = read_json(opts.vault, json.loads(json.dumps(EMPTY_VAULT)))
        except (json.JSONDecodeError, ValueError) as exc:
            vault, vault_exists = json.loads(json.dumps(EMPTY_VAULT)), True
            errors.append("vault does not parse, starting empty: %s" % exc)

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
                "config_has_comments": cfg_comments,
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

        cfg_backup, comments_kept = write_config(
            opts.config, canonicalize(config), opts.keep_backups)
        vault_backup = write_json(opts.vault, vault, opts.keep_backups, mode=0o600)
        self._json(200, {
            "ok": True,
            "config_backup": cfg_backup,
            "vault_backup": vault_backup,
            "comments_preserved": comments_kept,
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


DEFAULT_CONFIG_FILE = "/etc/awg-endpoints/config.json"

VAULT_LOCATION_WARNING = """
  WARNING: the vault sits in %s, the same directory as the sing-box
           config. If sing-box is started with -C on that directory it loads
           every *.json in it, will try to parse the vault as configuration,
           and will fail to start. Move the vault somewhere else, e.g.
           /var/lib/awg-endpoints/vault.json."""

SETTING_DEFAULTS = {
    "sing_box_config": "/etc/sing-box/config.json",
    # Deliberately NOT inside /etc/sing-box: sing-box is often started with
    # -C /etc/sing-box, which merges every *.json file in that directory. A
    # vault sitting there gets parsed as config and kills the daemon on boot.
    "vault": "/var/lib/awg-endpoints/vault.json",
    "host": "127.0.0.1",
    "port": 8787,
    "keep_backups": 10,
    "read_only": False,
    "restart_cmd": "",
    "allow_insecure": False,
    "auth": {"user": "", "password": "", "password_file": ""},
    "tls": {"cert": "", "key": ""},
}


def load_settings(path, required):
    """Read the app's own config file. Returns {} when it is absent and was not
    asked for explicitly."""
    if not os.path.exists(path):
        if required:
            raise SystemExit("config file not found: %s" % path)
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data, _ = parse_jsonc(fh.read())
    except (ValueError, json.JSONDecodeError) as exc:
        raise SystemExit("%s does not parse: %s" % (path, exc))
    if not isinstance(data, dict):
        raise SystemExit("%s must contain a JSON object" % path)

    # Typos in a config file that are silently ignored are a bad afternoon.
    unknown = [k for k in data if k not in SETTING_DEFAULTS]
    if unknown:
        raise SystemExit("%s: unknown setting(s) %s\nvalid settings: %s" % (
            path, ", ".join(sorted(unknown)), ", ".join(sorted(SETTING_DEFAULTS))))
    for section in ("auth", "tls"):
        if section in data:
            if not isinstance(data[section], dict):
                raise SystemExit("%s: '%s' must be an object" % (path, section))
            bad = [k for k in data[section] if k not in SETTING_DEFAULTS[section]]
            if bad:
                raise SystemExit("%s: unknown %s setting(s) %s" % (
                    path, section, ", ".join(sorted(bad))))
    return data


def build_options(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-c", "--config", default=None, metavar="PATH",
                    help="this app's config file (default: %s)" % DEFAULT_CONFIG_FILE)
    ap.add_argument("--sing-box-config", dest="sing_box_config", default=None,
                    help="path to the sing-box config")
    ap.add_argument("--vault", default=None, help="path to the key sidecar")
    ap.add_argument("--host", default=None, help="bind address")
    ap.add_argument("--port", type=int, default=None, help="bind port")
    ap.add_argument("--keep-backups", type=int, default=None,
                    help="how many timestamped backups to retain")
    ap.add_argument("--read-only", action="store_true", default=None,
                    help="serve the editor but refuse to write anything")
    ap.add_argument("--restart-cmd", default=None,
                    help="enable the Restart button, e.g. 'systemctl restart sing-box'")
    ap.add_argument("--auth", default=None,
                    help="HTTP basic auth as 'user:password'; the password may be a "
                         "pbkdf2 string from --hash-password")
    ap.add_argument("--auth-file", default=None,
                    help="read 'user:password' from the first non-comment line of a file")
    ap.add_argument("--hash-password", action="store_true",
                    help="prompt for a password, print a pbkdf2 string, exit")
    ap.add_argument("--check", action="store_true",
                    help="validate the config file and exit")
    ap.add_argument("--tls-cert", default=None, help="PEM certificate, enables HTTPS")
    ap.add_argument("--tls-key", default=None, help="PEM private key for --tls-cert")
    ap.add_argument("--allow-insecure", action="store_true", default=None,
                    help="permit binding a non-loopback address without auth")
    args = ap.parse_args(argv)

    if args.hash_password:
        return args, None

    settings = load_settings(args.config or DEFAULT_CONFIG_FILE, args.config is not None)
    file_auth = settings.get("auth", {})
    file_tls = settings.get("tls", {})

    def pick(name, cli_value, section=None):
        """Command line beats the config file beats the built-in default."""
        if cli_value is not None:
            return cli_value
        if section:
            return section.get(name, SETTING_DEFAULTS[
                "auth" if section is file_auth else "tls"][name])
        return settings.get(name, SETTING_DEFAULTS[name])

    opts = argparse.Namespace(
        settings_path=args.config or DEFAULT_CONFIG_FILE,
        config=pick("sing_box_config", args.sing_box_config),
        vault=pick("vault", args.vault),
        host=pick("host", args.host),
        port=int(pick("port", args.port)),
        keep_backups=int(pick("keep_backups", args.keep_backups)),
        read_only=bool(pick("read_only", args.read_only)),
        restart_cmd=pick("restart_cmd", args.restart_cmd),
        allow_insecure=bool(pick("allow_insecure", args.allow_insecure)),
        tls_cert=pick("cert", args.tls_cert, file_tls),
        tls_key=pick("key", args.tls_key, file_tls),
        auth=args.auth,
        auth_file=pick("password_file", args.auth_file, file_auth),
        file_auth_user=file_auth.get("user", ""),
        file_auth_password=file_auth.get("password", ""),
        hash_password=False,
    )
    return args, opts


def main(argv=None):
    args, opts = build_options(argv)

    if args.hash_password:
        if sys.stdin.isatty():
            pw = getpass.getpass("password: ")
            if pw != getpass.getpass("again: "):
                sys.exit("passwords do not match")
        else:
            pw = sys.stdin.readline().rstrip("\n")    # scriptable: echo pw | ...
        if not pw:
            sys.exit("empty password")
        print(hash_password(pw))
        return

    if not os.path.isdir(STATIC_DIR):
        sys.exit("missing static/ directory next to server.py")
    if bool(opts.tls_cert) != bool(opts.tls_key):
        sys.exit("tls.cert and tls.key must be given together")

    creds = load_credentials(opts)

    # sing-box is commonly run as `sing-box run -C /etc/sing-box`, which loads
    # every *.json in that directory. A vault living there would be parsed as
    # config and take the daemon down on its next restart.
    vault_warning = os.path.dirname(os.path.abspath(opts.vault)) == \
        os.path.dirname(os.path.abspath(opts.config))

    if args.check:
        print("%s: ok" % opts.settings_path)
        print("  listen : %s:%d" % (opts.host, opts.port))
        print("  config : %s" % opts.config)
        print("  vault  : %s" % opts.vault)
        print("  auth   : %s" % ("user '%s'" % creds[0] if creds else "NONE"))
        print("  restart: %s" % (opts.restart_cmd or "disabled"))
        for label, path in (("sing_box_config", opts.config), ("vault", opts.vault)):
            if not os.path.exists(path):
                print("  note   : %s does not exist yet (%s)" % (label, path))
        if vault_warning:
            print(VAULT_LOCATION_WARNING % os.path.dirname(os.path.abspath(opts.vault)))
        return
    loopback = opts.host in ("127.0.0.1", "::1", "localhost")
    if not loopback and creds is None and not opts.allow_insecure:
        sys.exit(
            "refusing to bind %s without authentication.\n"
            "Every private key in the vault would be readable by anything that can\n"
            "reach the port. Set auth.user and auth.password in %s, or pass\n"
            "--allow-insecure if the port is already restricted by other means."
            % (opts.host, opts.settings_path)
        )

    httpd = ThreadingHTTPServer((opts.host, opts.port), Handler)
    httpd.opts = opts
    httpd.creds = creds
    httpd.throttle = Throttle()

    scheme = "http"
    if opts.tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(opts.tls_cert, opts.tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"

    print("awg-endpoints on %s://%s:%d" % (scheme, opts.host, opts.port))
    print("  settings: %s%s" % (
        opts.settings_path,
        "" if os.path.exists(opts.settings_path) else " (absent, using defaults)"))
    print("  config : %s" % os.path.abspath(opts.config))
    print("  vault  : %s" % os.path.abspath(opts.vault))
    print("  auth   : %s" % ("basic, user '%s'" % creds[0] if creds else "NONE"))
    if opts.read_only:
        print("  mode   : READ-ONLY")
    if opts.restart_cmd:
        print("  restart: %s" % opts.restart_cmd)
    if not loopback and scheme == "http" and creds:
        print("  WARNING: basic auth over plain HTTP sends the password in every")
        print("           request. Fine inside the tunnel, not on an open network.")
    if creds is None:
        print("  WARNING: no authentication; keep this on loopback.")
    if vault_warning:
        print(VAULT_LOCATION_WARNING % os.path.dirname(os.path.abspath(opts.vault)))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
