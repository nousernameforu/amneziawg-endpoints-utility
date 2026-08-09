# amneziawg-endpoints-utility

A small local web app for generating AmneziaWG client configs from the
`endpoints` section of a sing-box `config.json`.

The client `.conf` files are the point. Adding a client is one click: it gets a
fresh X25519 keypair, a preshared key, the next free IPv4/IPv6 pair from the
interface subnets and a name. The server endpoint itself is editable, but lives
in a collapsed panel out of the way.

## Running

```bash
python3 server.py
```

No dependencies — Python 3.8+ stdlib only. Defaults:

| flag | default | meaning |
| --- | --- | --- |
| `--config` | `/etc/sing-box/config.json` | the sing-box config |
| `--vault` | `/etc/sing-box/awg-vault.json` | key sidecar, written `0600` |
| `--host` | `127.0.0.1` | bind address |
| `--port` | `8787` | bind port |
| `--keep-backups` | `10` | timestamped backups to retain |
| `--read-only` | off | serve the editor but refuse to write |
| `--restart-cmd` | off | enables the Restart button, e.g. `'systemctl restart sing-box'` |

Try it against a copy first:

```bash
python3 server.py --config ./sample-config.json --vault ./sample-vault.json --port 8787
```

## Where the keys live

`config.json` only ever receives what sing-box needs: the server private key and
each peer's **public** key, preshared key and allowed IPs. It is written as plain
JSON with no comments and no extra fields, so the daemon can't trip over it.

Everything else goes in the sidecar (`awg-vault.json`), which this app owns:

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

## Saving

Save writes both files: the existing `config.json` is copied to
`config.json.bak-YYYYmmdd-HHMMSS` first, then replaced atomically via
`os.replace`. Only the `endpoints` array is rebuilt; every other section keeps its
structure and order. Old backups beyond `--keep-backups` are pruned.

Changes do not reach the running daemon until sing-box reloads. Start with
`--restart-cmd 'systemctl restart sing-box'` to get a Restart button.

## Validation

The Server endpoint panel lists problems, with a count in the header bar:
malformed keys or CIDRs, `jmin >= jmax`, `s1 + 56 == s2`, `h1`–`h4` that overlap or
sit below 5, duplicate peer addresses or public keys, address pairs outside the
interface subnets, and packet templates that don't parse. Errors are red, warnings
amber. Nothing blocks saving — it's advisory.

## Exposure

The app has **no authentication**. It binds to loopback by default; keep it there
and reach it over the tunnel (SSH forward, or bind to the VPN-side address only
once access is restricted to connected clients). Anything that can reach the port
can read every private key.
