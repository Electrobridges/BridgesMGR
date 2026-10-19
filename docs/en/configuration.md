# Configuration

Everything lives in `/etc/ovpn-web/config.yaml`, owned by `root:ovpnweb` with
mode `0640`. The commented template is
[deploy/config.ejemplo.yaml](../../deploy/config.ejemplo.yaml).

Two processes with **different privileges** read it: the panel (as `ovpnweb`)
and the helper (as root). That is why the file belongs to root and `ovpnweb` can
only read it: it is what stops a compromised panel from rewriting the paths the
helper is going to use as root.

After any change: `sudo systemctl restart ovpn-web`.

> A key mistyped is **not** ignored: loading fails with
> `Claves desconocidas en 'openvpn': satus_path` and the service does not start.
> That is on purpose — a typo that sneaks in as a default value is a failure
> that shows up weeks later.

## `servidor`

| Key | Default | What it is |
|---|---|---|
| `host_bind` | `127.0.0.1` | IP the panel listens on. Set it to the LAN IP. **Do not use `0.0.0.0`** if the machine has a leg on the internet |
| `puerto` | `55443` | The panel's HTTPS port |
| `tls_cert` | `/etc/ovpn-web/tls/cert.pem` | The panel's certificate (the installer generates it) |
| `tls_key` | `/etc/ovpn-web/tls/key.pem` | Private key of the certificate |

## `openvpn`

| Key | Default | What it is |
|---|---|---|
| `log_path` | `/var/log/openvpn/openvpn.log` | Log the viewer shows. It must match your `log-append` |
| `status_path` | `/var/log/openvpn/status.log` | Must match the `status` line in your `server.conf`. If you put `status /var/log/openvpn/status.log`, it goes **without** the `openvpn-` prefix |
| `mgmt_host` | `127.0.0.1` | Management interface. Literally `127.0.0.1`: `localhost` may resolve to IPv6 |
| `mgmt_port` | `7505` | Management port |
| `easyrsa_path` | `/etc/openvpn/easy-rsa` | EasyRSA directory; `pki/` is inside it |
| `servicio` | `openvpn@server` | systemd unit queried for the status |

## `cliente_ovpn`

Data the `.ovpn` downloaded from the panel is built with.

| Key | Default | What it is |
|---|---|---|
| `remote_host` | *(empty)* | Address through which clients reach the VPN **from outside**: the public IP or the dynamic hostname. **It is not the panel's IP** — that is the most common mistake |
| `remote_puerto` | `1194` | The VPN port |
| `proto` | `udp` | `udp` or `tcp`, same as in `server.conf` |
| `cipher` | `AES-256-CBC` | Must match the server |
| `tls_crypt` | `/etc/openvpn/tls-crypt.key` | Path to the `tls-crypt` key to embed in the profile. Leave it empty if you do not use tls-crypt |
| `tls_crypt_v2` | *(empty)* | tls-crypt-v2 **server** key. With it, each `.ovpn` carries its own client key and `tls_crypt` stops being used. Do not set it by hand: `deploy/migrar-tls-crypt-v2.sh` sets it, and it also changes the `server.conf` |
| `dns` | *(empty list)* | DNS servers pushed to the client, e.g. `["1.1.1.1", "9.9.9.9"]` |

## `seguridad`

| Key | Default | What it is |
|---|---|---|
| `helper` | `/usr/local/sbin/ovpn-web-helper` | Path to the privileged helper. It must match **exactly** the one in `/etc/sudoers.d/ovpnweb` |
| `usar_sudo` | `true` | Invoke the helper through sudo. It is only set to `false` for tests outside the server |
| `db_path` | `/var/lib/ovpn-web/ovpn-web.db` | SQLite with accounts, sessions, audit log and VPN events |
| `respaldos_dir` | *(empty)* | Where copies of the database are kept. Empty = `<db_path dir>/respaldos`. It is here and not in the panel so that whoever compromises it cannot send database copies to a path of their own; if you change it, add the path to the unit's `ReadWritePaths` |
| `duracion_sesion_min` | `60` | Minutes a session is valid for |
| `max_intentos_login` | `5` | Failed attempts before locking |
| `bloqueo_login_min` | `15` | Minutes of lockout. It is counted per user **+ IP**, so a third party cannot lock the admin out |
| `cookie_segura` | `true` | Sets `Secure` on the session cookie. Only disable it if you serve the panel over plain HTTP, which is not recommended |
| `metricas_token` | *(empty)* | Token for Prometheus to read `/metrics` with `Authorization: Bearer <token>`. Empty = the endpoint does not exist. Generate one with `openssl rand -hex 32` |

Example `scrape_config` for Prometheus (the panel's certificate is
self-signed):

```yaml
- job_name: bridgesmgr
  scheme: https
  tls_config: { insecure_skip_verify: true }
  authorization: { credentials: "<metricas_token>" }
  static_configs: [{ targets: ["192.168.1.192:55443"] }]
```

## What is configured from the panel

Not everything lives in this file. What is an operational decision rather than a
deployment one is kept in the database and changed from the web:

| Where | What |
|---|---|
| **Clientes VPN → Políticas** (VPN clients → Policies) | Temporary access, schedule, maximum session length, monthly quota, fixed IP and allowed destinations, two-step verification |
| **Clientes VPN** (VPN clients) | Maximum session length for everyone |
| **Seguridad** (Security) | Automatic IP blocking: threshold, window, duration and allowlist |

Policies need two lines in the `server.conf` (servers set up by
`deploy/instalar-openvpn.sh` already have them):

```
script-security 2
client-connect /usr/local/lib/ovpn-web/client-connect
```

And two-step verification needs these, with OpenVPN running under the group the
installer creates:

```
group ovpnweb-vpn
auth-user-pass-verify /usr/local/lib/ovpn-web/verificar-totp via-file
auth-user-pass-optional
auth-gen-token 0
```

To use fixed IPs, the dynamic pool cannot take up the whole network:
`server 10.8.0.0 255.255.255.0 nopool` plus `ifconfig-pool 10.8.0.2 10.8.0.191`
leaves `.192` to `.254` for fixed IPs. The **Seguridad** (*Security*) page
reviews all of this and says which line is missing.

## Configuration for development

Locally there is no `/etc/ovpn-web/`, so the environment variable is used:

```bash
cp deploy/config.ejemplo.yaml config.local.yaml   # y ajústalo
OVPN_WEB_CONFIG=config.local.yaml python -m app.servidor
```

The search order is: explicit argument → `OVPN_WEB_CONFIG` →
`/etc/ovpn-web/config.yaml`.

`config.yaml` and `config.local.yaml` are in `.gitignore`: they hold the real
paths and addresses of your server.