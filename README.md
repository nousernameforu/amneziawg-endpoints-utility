# amneziawg-endpoints-utility

A small local web app for generating AmneziaWG client configs from the
`endpoints` section of a sing-box `config.json`.

The client `.conf` files are the point. Adding a client is one click: it gets a
fresh X25519 keypair, a preshared key, the next free IPv4/IPv6 pair from the
interface subnets and a name. The server endpoint itself is editable, but lives
in a collapsed panel out of the way.

## Installing

```bash
sudo ./install.sh
```

It asks for an admin password and whether the app may restart sing-box, then
sets everything up and starts the service. Non-interactive:

```bash
printf 'my-password\n' | sudo ./install.sh --password - --port 8080 --yes
```

Re-running updates an existing install in place. `sudo ./uninstall.sh` removes
it, deliberately leaving the vault and your sing-box config alone (`--purge-vault`
if you really mean it — those client keys have no other copy).

| what | where |
| --- | --- |
| app | `/opt/awg-endpoints` |
| **configuration** | `/etc/awg-endpoints/config.json`, `0640 root:awg-endpoints` |
| vault | `/var/lib/awg-endpoints/vault.json`, `0600` |
| backups | `/var/backups/awg-endpoints/`, `0600` |
| unit | `/etc/systemd/system/awg-endpoints.service` |

## Configuration

Everything lives in `/etc/awg-endpoints/config.json`. The unit passes that path
and nothing else, so changing the port, the bind address or the password means
editing that file — never the unit:

```bash
sudoedit /etc/awg-endpoints/config.json
sudo systemctl restart awg-endpoints
```

It is JSONC, so it keeps its comments. Check it before restarting:

```bash
sudo -u awg-endpoints python3 /opt/awg-endpoints/server.py \
     --config /etc/awg-endpoints/config.json --check
```

| setting | default | |
| --- | --- | --- |
| `sing_box_config` | `/etc/sing-box/config.json` | the file being edited |
| `vault` | `/var/lib/awg-endpoints/vault.json` | peer private keys, `0600` |
| `host` / `port` | `127.0.0.1` / `8787` | where to listen |
| `auth.user` | `admin` | web UI login |
| `auth.password` | — | pbkdf2 string, or a literal password |
| `auth.password_file` | — | read `user:password` from elsewhere instead |
| `keep_backups` | `10` | timestamped copies of `config.json` |
| `backup_dir` | `/var/backups/awg-endpoints` | where those copies go |
| `temp_dir` | system temp | scratch space for the pre-write check |
| `validate.enabled` | `true` | run `sing-box check` before writing |
| `validate.binary` | `sing-box` | which binary to run |
| `validate.mode` | `auto` | `auto`, `file` or `directory` staging |
| `validate.timeout` | `30` | seconds before giving up |
| `validate.strict` | `true` | a failed check blocks the save |
| `read_only` | `false` | serve the editor, refuse to write |
| `restart_cmd` | — | command behind the Restart button |
| `language` | `en` | default UI language |
| `tls.cert` / `tls.key` | — | serve HTTPS |
| `allow_insecure` | `false` | permit a non-loopback bind with no auth |

Unknown keys are a startup error rather than being silently ignored, so a typo
fails loudly instead of quietly leaving a setting at its default. Command line
flags still work and override the file.

Generate a password hash with:

```bash
python3 /opt/awg-endpoints/server.py --hash-password
```

## Language

Ships with English and Russian. `install.sh` asks which to use as the default,
or takes `--language ru`; it is stored as `language` in the config file.

Each browser can override that with the picker in the header, and the choice is
remembered locally — so the server default is what a new visitor sees, not a
lock. Order of preference: the picker's remembered choice, then `language` from
the config, then the browser's own `Accept-Language` if it matches a shipped
locale, then English.

### Adding a language

Drop a file in `static/i18n/`. Copy `en.json`, translate the values, set `_name`
to the language's name in itself (it goes straight into the picker) and `_code`
to match the filename. The server enumerates that directory at request time, so
nothing else needs changing.

Keys missing from a locale fall back to English rather than showing raw key
names, so a partial translation is usable from the first string. To check one:

```bash
python3 - <<'EOF'
import json, glob
en = json.load(open('static/i18n/en.json', encoding='utf-8'))
for f in glob.glob('static/i18n/*.json'):
    d = json.load(open(f, encoding='utf-8'))
    missing = [k for k in en if k not in d]
    print(f, 'missing:', missing or 'nothing')
EOF
```

Note that config keys (`jc`, `s1`, `allowed_ips`, `PersistentKeepalive` …) are
deliberately **not** translated — they are the literal names in the files being
edited, and translating them would make the UI harder to map onto sing-box's
documentation, not easier. Generated `.conf` files are unaffected by the UI
language.

### Which user does it run as

A dedicated system user, `awg-endpoints`. Not root.

The app holds every client's private key and rewrites a file the daemon loads,
so it is the last thing that should have the run of the machine — as its own
user, a bug or an auth bypass costs you sing-box's config, not the box. The unit
adds `ProtectSystem=strict`, an empty capability set, a syscall filter and
`ReadWritePaths` limited to `/etc/sing-box`.

Writing `config.json` atomically means creating a temp file and renaming over the
target, which needs write permission on the **directory**, not the file. So the
installer sets `/etc/sing-box` to `2770 root:awg-endpoints` — setgid, so new files
stay in the group. If your sing-box itself runs as some non-root user, the
installer warns you and prints the `usermod` needed to keep it working.

### The Restart button

Off unless you pass `--with-restart`, because it costs something. Restarting a
unit needs privilege the service user does not have, so the installer adds a
sudoers rule scoped to exactly one command:

```
awg-endpoints ALL=(root) NOPASSWD: /usr/bin/systemctl restart sing-box.service
```

and validates it with `visudo -c` before installing it. sudo is setuid, so
`NoNewPrivileges` has to come off for it to work — a real, if narrow, weakening
of the sandbox. Without the flag you keep the tighter sandbox and restart
sing-box yourself. If you would rather not use sudo at all, a polkit rule
granting `org.freedesktop.systemd1.manage-units` for that one unit achieves the
same thing over D-Bus and keeps `NoNewPrivileges=yes`.

## Running it by hand

```bash
python3 server.py
```

No dependencies — Python 3.8+ stdlib only. With no `--config`, it looks for
`/etc/awg-endpoints/config.json` and falls back to built-in defaults if that is
absent, so it runs out of a git checkout with no setup.

Every setting in the table above has a matching flag, which overrides the file:
`--sing-box-config`, `--vault`, `--host`, `--port`, `--keep-backups`,
`--read-only`, `--restart-cmd`, `--auth user:pass`, `--auth-file`, `--tls-cert`,
`--tls-key`, `--allow-insecure`.

> **Note:** `--config` means *this app's* config file. The sing-box config is
> `--sing-box-config`. It used to be the other way round — if you have a command
> line from an earlier version, that is the flag that moved.

Try it against a copy first:

```bash
python3 server.py --sing-box-config ./sample-config.json --vault ./sample-vault.json --port 8787
```

## Authentication

HTTP basic auth, configured under `auth` in the config file. Off by default,
which is why the server refuses to bind anything but loopback until it is set.

`install.sh` sets this up for you. By hand, hash the password and put it in
`auth.password`:

```bash
python3 server.py --hash-password        # prompts twice, prints a pbkdf2 string
```

A literal password works too, but the hash is better: the config file is
readable by the service user. `--auth user:password` exists for quick runs and
puts the password in the process list, so do not use it for a service.
`auth.password_file` (or `--auth-file`) reads `user:secret` from the first
non-comment line of another file, and `AWG_AUTH=user:password` in the environment
also works.

Credentials are compared with `hmac.compare_digest`, both halves are always
evaluated so timing doesn't leak which one was wrong, and repeated failures from
one IP earn a growing delay.

Basic auth sends the password on every request, so it is only as private as the
transport. Inside the tunnel that's fine. On anything else, add `--tls-cert` and
`--tls-key`.

## Where the keys live

`config.json` only ever receives what sing-box needs: the server private key and
each peer's **public** key, preshared key and allowed IPs. It is written as plain
JSON with no comments and no extra fields, so the daemon can't trip over it.

Everything else goes in the sidecar (`/var/lib/awg-endpoints/vault.json`), which
this app owns. It deliberately does **not** live in `/etc/sing-box`: sing-box is
often started with `-C /etc/sing-box`, which loads every `*.json` in that
directory, and it would try to parse the vault as configuration and refuse to
start. The installer refuses to put it there, and `--check` warns if you point it
there by hand.

If a stale `/etc/sing-box/awg-vault.json` is lying around from an earlier attempt,
delete it — sing-box in `-C` mode will keep failing on it.

```json
{
  "version": 1,
  "endpoints": {
    "awg-server": {
      "server_public_key": "…",
      "client": { "endpoint_host": "vpn.example.com", "dns": "…", "i1": "…" },
      "peers": { "<peer public key>": { "name": "phone", "private_key": "…" } }
    }
  }
}
```

Peers are matched between the two files by public key. The sidecar holds every
client's private key, so **back it up and keep it at mode 0600** — losing it means
you can't reissue a `.conf` without rekeying that client.

A peer that exists in `config.json` but has no sidecar entry still shows up; it
just can't produce a `.conf` until you paste its private key in or hit *Rekey*.

## Server vs client packet templates

`i1`–`i5` in the sing-box block describe what the **server** emits. Client configs
need their own, so the *Client template* panel has a separate `I1`–`I5` that is
written to every generated `.conf` and never to `config.json`.

`jc`, `jmin`, `jmax`, `s1`–`s4` and `h1`–`h4` are shared — they are copied to the
`.conf` as-is, header ranges included.

## Comments

sing-box reads JSON with comments, so this app does too: `//` line comments,
`/* */` blocks, `#` line comments and trailing commas all parse.

Note that `#` is not part of JSONC — `//` and `/* */` are. It is accepted here
because a bare `#` is never valid JSON anyway, so reading it costs nothing. That
leniency is this app's, though, not sing-box's: if you use `#`, confirm sing-box
itself still loads the file before relying on it.

They also survive a save. Rather than re-serialising the whole file, the writer
locates the `endpoints` array in the original text and splices the new one into
its place, leaving every other byte — comments included — untouched. The result is
parsed and compared against what was intended before it is written; if anything
does not match, the writer falls back to a plain full rewrite instead of risking a
mangled config.

The one thing that does not survive is a comment **inside** the `endpoints` array,
since that array is regenerated from the editor's model. Put notes about a peer in
its sidecar name instead. A `JSONC` pill appears in the header when the file has
comments, and the save toast tells you if a full rewrite happened.

## Saving

Every save goes through the same sequence:

1. **Render** the new `config.json` text — splicing the endpoints array into the
   original so comments elsewhere survive.
2. **Check it with sing-box**, before anything on disk is touched.
3. **Back up** the current file to `/var/backups/awg-endpoints/`.
4. **Replace** atomically via `os.replace`.

Only the `endpoints` array is rebuilt; every other section keeps its structure,
order and comments. Backups beyond `keep_backups` are pruned, oldest first, and
written `0600` — they contain the server private key.

### The pre-write check

The candidate is written to a throwaway directory and handed to
`sing-box check`. If sing-box refuses it, **nothing is written** and its exact
output comes back to the browser. This is what stops the editor from ever
handing the daemon a config it cannot load.

The staging mirrors how sing-box actually loads your config. In `auto` mode, if
other `*.json` files sit next to `config.json` — which is how
`sing-box run -C /etc/sing-box` works — their copies are staged alongside the
candidate and the whole directory is checked. That matters: a config that passes
on its own can still fail once merged, for instance if a sibling file declares a
duplicate outbound tag. Checking the file alone would miss it.

The scratch directory is the system temp by default. Under systemd that is a
private `/tmp` belonging to this service (`PrivateTmp=yes`), which is where a
candidate full of private keys should be staged; it is `0700` and removed
afterwards either way. Set `temp_dir` to move it.

`validate.strict` decides what a failure means. `true` (the default) blocks the
save. `false` saves anyway and shows the complaint as a warning — useful if
something *else* in your config directory is already broken and would otherwise
block every save you make. Set `validate.enabled` to `false` to skip the check
entirely; the installer warns at install time if it cannot find the binary.

Changes do not reach the running daemon until sing-box reloads. Start with
`--restart-cmd 'systemctl restart sing-box'` to get a Restart button.

## Validation

The Server endpoint panel lists problems, with a count in the header bar:
malformed keys or CIDRs, `jmin >= jmax`, `s1 + 56 == s2`, `h1`–`h4` that overlap or
sit below 5, duplicate peer addresses or public keys, address pairs outside the
interface subnets, and packet templates that don't parse. Errors are red, warnings
amber. Nothing blocks saving — it's advisory.

## Reaching it only through sing-box

The goal: the app answers connections that arrived through a tunnel, and is
invisible to everything else.

The safety property comes from the bind address, not from firewall rules. Keep the
app on `127.0.0.1` and it is unreachable from the public interface no matter what
you get wrong in the routing — sing-box becomes the only way in, because it is the
only thing that can dial loopback.

### 1. Run the app on loopback with auth

```bash
sudo ./install.sh --host 127.0.0.1 --port 8787
```

Confirm it works locally before touching sing-box:

```bash
curl -si -u admin:yourpassword http://127.0.0.1:8787/api/state | head -1
```

Ready-made snippets live in [`examples/`](examples):

| file | |
| --- | --- |
| `00-isolate-the-mechanism.json` | standalone throwaway config that tests the redirect with no tunnel involved |
| `01-route-additions.json` | the real rules, sing-box 1.11+ syntax |
| `02-route-additions-legacy.json` | the same for pre-1.11 bases |

Start with `00`. It answers "does destination-override work in my build at all",
which is the question underneath most of the ways this goes wrong.

### 2. Add route rules that redirect tunnel traffic to it

Proxy inbounds (hysteria2, vmess, trojan…) carry a hostname, so match a domain
you invent. Packet tunnels (wireguard/amneziawg) carry IP packets, so match the
tunnel address and port. Put these **first** in `route.rules`:

```json
{
  "route": {
    "rules": [
      {
        "inbound": ["hy2-in"],
        "domain": ["awg-admin.internal"],
        "action": "route",
        "outbound": "direct",
        "override_address": "127.0.0.1",
        "override_port": 8787
      },
      {
        "network": ["tcp"],
        "source_ip_cidr": ["10.3.2.2/32"],
        "ip_cidr": ["10.3.2.1/32"],
        "port": [80],
        "action": "route",
        "outbound": "direct",
        "override_address": "127.0.0.1",
        "override_port": 8787
      }
    ],
    "final": "direct"
  }
}
```

`source_ip_cidr` is the real access control on the VPN side: narrowing it to one
admin peer means no other client can even reach the login prompt.

That is sing-box 1.11+ syntax. On older bases the overrides live on the outbound
instead — declare a dedicated direct outbound carrying `override_address` and
`override_port`, and have the rule point at its tag. Check `sing-box version`.

### 3. Use it

- over hy2: `http://awg-admin.internal/` with the proxy configured
- over awg: `http://10.3.2.1/`

### When it does not work

`Martian packet dropped with loopback source address` means the connection is
being dialed *inside* a tunnel's userspace netstack rather than from the host, so
`127.0.0.1` is unreachable by definition. That happens when your rule did not
match and `route.final` sent the connection into a tunnel instead. Check, in
order:

1. Is the rule first, and does `outbound` name a plain `direct` that is not
   detoured through an endpoint?
2. Set `"log": { "level": "debug" }` and watch which rule actually matches.
3. Still stuck? Give the endpoint `"system": true`. That creates a real kernel
   interface owning `10.3.2.1`, removing gVisor from the path entirely — then
   bind the app with `--host 10.3.2.1` and drop the second rule altogether.

If you would rather not use loopback at all, bind the app to a dummy interface
address (`ip link add awgadmin type dummy`, `ip addr add 172.31.255.1/32 dev
awgadmin`) and override to that instead. Host-local, but not martian.

### Why not just bind the tunnel address

Because it only works with `"system": true`. Without it sing-box terminates the
tunnel in its own userspace stack, the host never sees packets addressed to
`10.3.2.1`, and binding there gets you a socket nothing can reach. The loopback +
route rule setup above works either way, which is why it is the default advice
here.

Whatever you choose, `--auth` must be on before the app listens anywhere but
loopback — the server refuses to start otherwise. Anything that can reach the port
can read every client private key in the vault.
