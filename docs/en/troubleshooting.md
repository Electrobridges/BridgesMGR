# Troubleshooting

General rule: the panel **does not silence errors**. If something fails, it says
so on screen with the reason. Start by reading the warning, and then go on to:

```bash
sudo journalctl -u ovpn-web -n 50 --no-pager
```

## The service does not start

Nine times out of ten it is one of three:

- **A key mistyped in `config.yaml`.** Loading fails on purpose with
  `Claves desconocidas en 'openvpn': satus_path` instead of falling back to a
  default value. Fix the key.
- **The TLS certificate is missing.** `ls -l /etc/ovpn-web/tls/`. If it is not
  there, run `sudo bash deploy/install.sh` again.
- **A path that does not exist.** Check `easyrsa_path` and `db_path`.

## "Management interface not available"

The panel ("management interface not available") falls back to the status file
and says so on screen; it keeps working but with less detail and without being
able to kick clients out.

```bash
ss -tlnp | grep 7505
```

If nobody is listening, `management 127.0.0.1 7505` is missing from your
`server.conf`. If it is listening but the panel does not connect, check that
`mgmt_host` is literally `127.0.0.1`: `localhost` may resolve to IPv6 and
OpenVPN's management only listens on IPv4.

## "The PKI could not be read"

Try the helper by hand, exactly as the panel calls it:

```bash
sudo -u ovpnweb sudo -n /usr/local/sbin/ovpn-web-helper listar
```

| What comes out | What is happening |
|---|---|
| `sudo: a password is required` | The rule is missing: `ls -l /etc/sudoers.d/ovpnweb` (it must be root:root 0440) |
| `command not found` | The helper is not installed, or `seguridad.helper` in `config.yaml` does not match the path in the sudoers file |
| `Falta python3-yaml` | `sudo apt install python3-yaml` — the helper runs with the system Python, not the venv |
| An easyrsa error | `easyrsa_path` points at the wrong place, or the PKI is not initialised |

## "No permission to read the log"

The user has to be in the `adm` group, which on Debian owns `/var/log`:

```bash
sudo usermod -aG adm ovpnweb
sudo systemctl restart ovpn-web
```

## The tables do not refresh themselves

`htmx.min.js` is missing. The pages load fine, but with no automatic refresh and
no warnings. The installer downloads it:

```bash
ls -l /opt/ovpn-web/app/static/htmx.min.js
```

If it is not there, run `install.sh` again. If the installer aborts with *"El hash
de HTMX no coincide"* ("the HTMX hash does not match"), do not force it: it
means what the CDN serves has changed relative to `deploy/htmx.sha256`. Find
out why before going on.

## I revoked a client and it still connects

Two causes, and they often come together:

1. **`crl-verify` is missing from the `server.conf`.** Without that line
   OpenVPN does not look at the revocation list. Add
   `crl-verify /etc/openvpn/easy-rsa/pki/crl.pem` and restart OpenVPN.
2. **The already established session does not cut itself.** Revoking prevents
   reconnecting, but does not kick out. Use the disconnect button from
   *Connections*.

## The downloaded `.ovpn` does not connect

- `cliente_ovpn.remote_host` is the address through which the VPN is reached
  **from outside** (public IP or dynamic hostname), not the panel's IP. It is the
  most frequent mistake.
- `proto` and `cipher` must match the `server.conf`.
- If the server uses `tls-crypt`, `cliente_ovpn.tls_crypt` must point at the
  key so that it is embedded in the profile.

## The two-step code is always wrong

Nine times out of ten it is **the phone's time or the server's**. TOTP is a code
derived from the clock: only ±30 seconds of drift is tolerated.

```bash
timedatectl status          # ¿está sincronizado el servidor?
sudo timedatectl set-ntp true
```

On the phone, turn on automatic network time. In Google Authenticator there is
also *Settings → Time correction for codes*.

If drift is not the problem, check that you registered the account as
**time-based** (not counter-based) and with 6 digits.

## I am locked out for losing my phone

Any admin can remove your second factor from *Users* → **Reset 2FA**. If the
one who is locked out is the only administrator, it has to be done from the
server:

```bash
cd /opt/ovpn-web
sudo -u ovpnweb venv/bin/python -m app.cli totp-restablecer tu_usuario
```

You will get in with the password alone until you enable it again. It is
audited.

## I am locked out of the panel

The lockout for failed attempts is temporary (`bloqueo_login_min`, 15 minutes by
default) and is counted per user **+ IP**, so from another address you can get
in. If you have lost the password:

```bash
cd /opt/ovpn-web
sudo -u ovpnweb venv/bin/python -m app.cli cambiar-password tu_usuario
```

## How to ask for help

Open an issue with the output of `journalctl -u ovpn-web -n 50`, your OpenVPN
version and your Debian/Ubuntu version, and the relevant lines from
`config.yaml`.

**Do not paste** certificates, keys, `.ovpn` files or the complete configuration
with real addresses.