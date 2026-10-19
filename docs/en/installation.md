# Installation

## Requirements

- Debian 11+ or Ubuntu 20.04+ (with systemd and `apt`)
- Python 3.9 or later
- Root access for the installation

OpenVPN is **not** a prior requirement: if you do not have it, the installer
offers to set it up. If you already have it, it does not touch it.

## Installing

```bash
git clone https://github.com/Electrobridges/BridgesMGR.git
cd BridgesMGR
sudo bash deploy/install.sh
```

The first thing it does is check whether an OpenVPN server is set up. If not, it
asks whether to set one up and calls
[`deploy/instalar-openvpn.sh`](#setting-up-the-openvpn-server). All the
questions land there, at the beginning, and not five minutes in.

After that, and this has not changed:

1. Installs the system dependencies (`python3-venv`, `openssl`, `curl`…).
2. Creates the `ovpnweb` system user, with no shell and no home directory, and
   adds it to the `adm` group so it can read the OpenVPN logs.
3. Copies the application to `/opt/ovpn-web` and creates its virtual
   environment.
4. Installs the privileged helper at `/usr/local/sbin/ovpn-web-helper` (0750,
   root:root).
5. Downloads HTMX and **verifies its SHA-256** against `deploy/htmx.sha256`,
   which is versioned in the repository. If it does not match, it aborts. And if
   the file is missing, **it also aborts**: HTMX is served from the panel itself,
   so the CSP treats it as trustworthy, and a tampered file would be JavaScript
   running with the administrator's session. Accepting whatever a CDN returns
   without comparing is not the default; to upgrade deliberately there is
   `--htmx-confiar`.
6. Puts the sample configuration at `/etc/ovpn-web/config.yaml`
   (root:ovpnweb 0640) if it is not already there. If it is, **it does not
   overwrite it**. And if it has just set up the VPN, it fills it in with what
   that script decided, instead of asking you to copy it from a screen to a
   file.
7. Generates a self-signed TLS certificate for the LAN IP, valid for 10 years.
8. Validates the sudo rule with `visudo -c` before installing it, and registers
   the service with systemd.

Options:

| Option | What it is for |
|---|---|
| `--sin-openvpn` | Do not offer to set anything up. You already have a server, or you will do it separately |
| `--con-openvpn` | Set it up without asking |
| `--salida lan\|todo` | Passed through to `instalar-openvpn.sh` as-is |
| `--host <target>` | Likewise: how clients reach the VPN |
| `--si` | Ask nothing (unattended installation) |

## Setting up the OpenVPN server

```bash
sudo bash deploy/instalar-openvpn.sh --salida lan --host vpn.ejemplo.com
```

It can be run on its own, and it is idempotent: if it finds a PKI it keeps it,
and if it finds a `server.conf` it **does not touch it** and tells you what the
panel needs.

It only asks what it cannot guess — what a client should be able to reach — and
detects the rest: outbound interface, local network and public IP. It shows a
summary and waits for confirmation before touching anything.

### What it leaves in place

| | |
|---|---|
| PKI | `/etc/openvpn/easy-rsa`, `secp384r1` elliptic curve |
| Configuration | `/etc/openvpn/server/server.conf` |
| `tls-crypt` key | `/etc/openvpn/tls-crypt.key` |
| Status | `/var/log/openvpn/status.log`, v3 format |
| Log | `/var/log/openvpn/openvpn.log` |
| Management | `127.0.0.1:7505` |
| Unit | `openvpn-server@server` |

It uses an elliptic curve instead of RSA for two reasons: it avoids generating
the Diffie-Hellman parameters, which are the minutes an OpenVPN installation
takes, and the resulting key is stronger. It requires OpenVPN 2.4 or later, from
2018.

### The two scopes

- **`--salida lan`** (split tunnel): the server's local network route is pushed
  to the client and nothing else. Its internet traffic still leaves through its
  own connection. This is the "get into the office from outside" case.
- **`--salida todo`** (full tunnel): `redirect-gateway`, the client goes out to
  the internet through the server, and DNS is pushed. It turns the server into
  everyone's exit.

### What it does to the server's network

Without this the VPN comes up and clients connect, but they do not route
anywhere, so it is on by default. With `--sin-red` nothing is touched and the
script prints the exact commands.

- Enables IP forwarding in `/etc/sysctl.d/99-ovpn-web-forward.conf`.
- Installs a NAT rule in its **own nftables table** (`ip ovpnweb`), loaded by
  the `ovpn-web-nat.service` unit. A separate table on purpose: you can see whose
  it is, and removing it does not take anyone else's rules with it.
- If `ufw` is active, it adds the port and the forwarding in its own language.
  NAT and forwarding filtering hang off different hooks, so the table above is
  not enough when ufw is involved.

### Other options

| Option | Default |
|---|---|
| `--puerto <n>` | `1194` |
| `--proto udp\|tcp` | `udp` |
| `--red <CIDR>` | `10.8.0.0/24` |
| `--iface <name>` | Detected from the default route |
| `--red-lan <CIDR>` | Detected from the outbound interface |
| `--dns <a> <b>` | `9.9.9.9`, `149.112.112.112` |
| `--sin-arrancar` | Leave everything written without enabling the unit |

## If you already had an OpenVPN server

The installer respects it and does not change a single line. In return you have
to adjust several things by hand, and so as not to go in blind there is the
checker:

```bash
sudo bash deploy/comprobar-servidor.sh
```

**Read only**: it does not install, write or restart anything, so it can be run
in production with clients connected. It compares your `server.conf` against
what `/etc/ovpn-web/config.yaml` says, sorts the findings into critical issues
and warnings, and gives the exact command to fix each one. `install.sh` calls it
by itself only when it detects that your OpenVPN already existed.

Two of its checks exist because they are the ones that fail without saying
anything:

- **That the user OpenVPN drops privileges to can really read the CRL.** It does
  not infer it from the permissions: it tries. The directory containing it also
  has to be traversable, and that detail is missed by looking at the file mode
  alone.
- **That the CRL is not expired.** An expired CRL makes OpenVPN reject *all*
  connections, not just the revoked ones, and the symptom points nowhere near
  the CRL.

The `server.conf` you already have must contain the following, or the panel will
see nothing:

```conf
management 127.0.0.1 7505
status /var/log/openvpn/status.log
status-version 3
log-append /var/log/openvpn/openvpn.log
crl-verify /etc/openvpn/easy-rsa/pki/crl.pem
```

Details that matter:

- **`status-version 3`**: OpenVPN 2.5.x writes that format separated by TAB and
  it is the one the panel understands best. It also reads the old format (v1),
  but with v3 you get the real and virtual IP separately, without ambiguity.
- **`management 127.0.0.1`**, not `localhost`: it may resolve to IPv6 and
  OpenVPN's management only listens on IPv4.
- **`crl-verify`** is what makes revoking mean anything. Without that line,
  revoking a certificate does not stop the client from connecting.

And in `/etc/ovpn-web/config.yaml` you have to adjust the paths to yours,
especially `openvpn.servicio`: on Debian two unit names coexist that are not
interchangeable — `openvpn-server@server` reads
`/etc/openvpn/server/server.conf` and `openvpn@server` reads
`/etc/openvpn/server.conf`. Check which one you have with
`systemctl list-units 'openvpn*'`.

After touching the `server.conf`: `sudo systemctl restart openvpn-server@server`.

## The three steps that are left

The installer leaves the service registered but **stopped**, and with no account
created. That is deliberate: a panel that starts on its own with a default user
is a compromised panel waiting for someone to find it.

```bash
# 1. Repasa la configuración
sudo nano /etc/ovpn-web/config.yaml
```

If the installer set up the VPN, this is already filled in and just needs a
review — above all `cliente_ovpn.remote_host`, which is how clients will
arrive, and it is only detected properly if the machine has internet access.

If the OpenVPN server already existed, you have to review at least
`servidor.host_bind`, `openvpn.status_path`, `openvpn.servicio` and
`cliente_ovpn.remote_host`. See [configuration.md](configuration.md).

```bash
# 2. Crea la primera cuenta: será el superusuario de la instalación
cd /opt/ovpn-web
sudo -u ovpnweb venv/bin/python -m app.cli crear-usuario tu_usuario --rol admin

# 3. Arranca
sudo systemctl start ovpn-web
sudo systemctl status ovpn-web
```

Open `https://YOUR_IP:55443`. The browser will warn that the certificate is
self-signed: that is expected, accept the exception.

## Panel accounts

```bash
cd /opt/ovpn-web
sudo -u ovpnweb venv/bin/python -m app.cli listar-usuarios
sudo -u ovpnweb venv/bin/python -m app.cli crear-usuario soporte --rol supervisor
sudo -u ovpnweb venv/bin/python -m app.cli cambiar-password tu_usuario
```

Three roles, in hierarchy:

| Role | What they can do |
|---|---|
| `superusuario` | Everything an admin can. On top of that it is **untouchable**: nobody can change its role, deactivate it, delete it, or touch its password or second factor |
| `admin` | Create, revoke, restore, disconnect, download profiles and manage accounts, including other admins' |
| `supervisor` | Read only: panel, connections, clients, logs and audit log. They do not get into *Usuarios* or *Configuración* |

The superusuario **is not granted**: it is the first account created in the
installation, whatever role was asked for. `--rol superusuario` does not exist,
and from the panel nobody can give it to themselves or take it away.

Handing it over is possible, but only from the server:

```bash
sudo -u ovpnweb venv/bin/python -m app.cli designar-superusuario otra_cuenta
```

It asks for confirmation, demotes the previous one to admin, closes the sessions
of both accounts and is audited.

Nobody can change their own role, superusuario included: anyone who demoted
themselves by mistake would be locked out of the page where you could fix it.

### Two-step verification

Each user enables it from **Mi cuenta** (*My account*, `/perfil`), with the
phone's authenticator app. For those in charge — superusuario and admins — it is
optional; for `supervisor` accounts it can be required from *Usuarios* or from
the CLI:

```bash
sudo -u ovpnweb venv/bin/python -m app.cli politica-totp              # consultar
sudo -u ovpnweb venv/bin/python -m app.cli politica-totp --exigir si

# Si alguien pierde el móvil y se queda fuera:
sudo -u ovpnweb venv/bin/python -m app.cli totp-restablecer tu_usuario
```

The detail is in [security.md](security.md#two-step-verification-totp).

## Updating

```bash
cd BridgesMGR
git pull
sudo bash deploy/install.sh
```

There is no need to restart anything by hand: if the panel was running, the
installer restarts it and checks that it comes back. The database
(`/var/lib/ovpn-web/`), the configuration and the TLS certificate are kept.
Repeating it is always safe.

How an update is protected:

- **The new version is prepared alongside** (`/opt/ovpn-web/app.nuevo`), it is
  checked that it imports with the freshly installed dependencies and that the
  current `config.yaml` suits it, and **only then** does it replace the one
  running. If any of that fails, the running panel has not been touched.
- **If the panel does not start with the new code, it goes back to the previous
  version by itself**, shows the last lines of its log and leaves the failed one
  at `/opt/ovpn-web/app.fallida` so you can look at it. The one before the last
  update is at `/opt/ovpn-web/app.anterior`.
- **No network does not stop it for what is not needed**: if apt does not answer
  but the packages are already there, or the HTMX CDN is down and the one you
  have matches the hash, it carries on and warns you.
- **Two installations at once do not tread on each other**: the second refuses
  to start.

### If something fails

The installer stops saying which step it was on, which line, with which command
and what to look at, and at the end it repeats together the warnings that did
not stop it. Everything that appears on screen is also kept in
**`/var/log/ovpn-web-instalacion.log`**, with the date and commit of each pass,
for when the SSH session has already closed:

```bash
sudo less +G /var/log/ovpn-web-instalacion.log
journalctl -u ovpn-web -n 50 --no-pager      # si lo que falla es el arranque
```

To go back to the previous version by hand:

```bash
sudo mv /opt/ovpn-web/app /opt/ovpn-web/app.descartada
sudo mv /opt/ovpn-web/app.anterior /opt/ovpn-web/app
sudo systemctl restart ovpn-web
```

## Database backups

The panel copies its database to `/var/lib/ovpn-web/respaldos/` using SQLite's
backup API, so the copy is consistent even while people are using the panel. The
schedule is set in **Settings → Database backups**
(*Configuración → Respaldos de la base*): daily or weekly, at the hour you
choose, keeping the last N. The watchdog checks it every five minutes, and if
the panel was stopped at that hour it backs up as soon as it comes back.

**Backups are not downloadable from the web, and that is not an oversight.** A
backup is the whole database: the hashes of every password and the second
factor secrets. It is worth exactly as much as the original, so it stays on the
server and is collected over SSH:

```bash
sudo cp /var/lib/ovpn-web/respaldos/ovpn-web-20260907-030000.db.gz /tmp/
sudo chown $USER /tmp/ovpn-web-*.db.gz
# y desde tu máquina:
scp servidor:/tmp/ovpn-web-20260907-030000.db.gz .
```

To look at the audit log outside the server there is **Settings → Export**
(*Configuración → Exportar*), which downloads a ZIP with the audit log and the
archived profiles as CSV and **with no secrets whatsoever**.

### Restoring

```bash
sudo systemctl stop ovpn-web
sudo cp /var/lib/ovpn-web/ovpn-web.db /var/lib/ovpn-web/ovpn-web.db.antes-de-restaurar
sudo sh -c 'gunzip -c /var/lib/ovpn-web/respaldos/ovpn-web-20260907-030000.db.gz \
    > /var/lib/ovpn-web/ovpn-web.db'
sudo chown ovpnweb:ovpnweb /var/lib/ovpn-web/ovpn-web.db
sudo chmod 0600 /var/lib/ovpn-web/ovpn-web.db
sudo systemctl start ovpn-web
```

The `chown` is not optional: the panel runs as `ovpnweb` and a database owned by
root cannot even open it. Restoring also puts the **accounts and passwords**
back as they were that day; the sessions opened since then stop being valid,
which is correct.

What a backup does **not** store: the PKI (`/etc/openvpn/easy-rsa`), the
configuration (`/etc/ovpn-web/config.yaml`) or the certificates. That belongs
to root and the panel does not reach it; back it up separately.

## Uninstalling

```bash
sudo systemctl disable --now ovpn-web
sudo rm /etc/systemd/system/ovpn-web.service /etc/sudoers.d/ovpnweb
sudo rm /usr/local/sbin/ovpn-web-helper
sudo systemctl daemon-reload
sudo rm -rf /opt/ovpn-web /etc/ovpn-web
sudo userdel ovpnweb
```

`/var/lib/ovpn-web` is deliberately left alone: it holds the panel accounts and
the audit log. Delete it only when you are sure.

Uninstalling the panel **reverts nothing in the PKI**: the certificates you
created or revoked from here stay as they are.