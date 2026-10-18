# 🔧 Maintenance

**English** · [Español](../../wiki/mantenimiento.md)

[← Wiki](README.md)

## Updating

```bash
cd BridgesMGR
git pull
sudo bash deploy/install.sh
```

It can always be repeated: it keeps the database, the configuration and the
certificate, and if the panel was running it restarts it and checks that it comes
back.

> [!NOTE]
> The new version is prepared alongside the running one and only replaces it if
> it imports correctly and your `config.yaml` suits it. If it does not start
> afterwards, the installer **goes back to the previous one by itself** and
> shows you why. Everything is logged in
> `/var/log/ovpn-web-instalacion.log`.

If something goes wrong:

```bash
sudo less +G /var/log/ovpn-web-instalacion.log   # qué hizo el instalador
journalctl -u ovpn-web -n 50 --no-pager          # por qué no arranca el panel
```

The detail, including the manual rollback, is in
[Installation → Updating](../../instalacion.md#actualizar) (Spanish).

## Checking the server

Review, without changing anything, that the OpenVPN server matches what the
panel expects: paths, permissions, CRL, management, logs and policy scripts.

```bash
sudo bash deploy/comprobar-servidor.sh
```

It ends with a summary of critical issues and warnings, and every line says what
to do.

## Backups

In **Configuración → Respaldos de la base** (Settings → Database backups) you
schedule a daily or weekly copy, keeping the last N, in
`/var/lib/ovpn-web/respaldos/`.

> [!WARNING]
> Backups are **not downloadable from the web** on purpose: they contain the
> password hashes and the two-step secrets. They are collected over SSH. And
> they do not include the PKI (`/etc/openvpn/easy-rsa`) or `config.yaml`:
> back those up separately, they are what genuinely cannot be regenerated.

How to restore one: [Installation → Restoring](../../instalacion.md#restaurar)
(Spanish).

To review the audit log in a spreadsheet, **Configuración → Exportar** (Settings
→ Export) downloads a ZIP of CSVs, with no secrets whatsoever.

## Locked out of the panel

| What happens | What to do |
|---|---|
| Many failed attempts | Wait 15 minutes or come in from another IP: the lock is per user **+ IP** |
| I forgot the password | `sudo -u ovpnweb venv/bin/python -m app.cli cambiar-password tu_usuario` |
| I lost my 2FA phone | Another admin: **Usuarios → Restablecer 2FA** (Users → Reset 2FA). If there is no other: `… app.cli totp-restablecer tu_usuario` |

The commands are run from `/opt/ovpn-web`, on the server itself.

## When something does not add up

| Symptom | Where to look |
|---|---|
| *Management interface no disponible* | [Troubleshooting](../../solucion-problemas.md#management-interface-no-disponible) (Spanish) |
| I revoked a client and it still gets in | [Troubleshooting](../../solucion-problemas.md#revoco-un-cliente-y-sigue-conectándose) (Spanish) |
| The downloaded `.ovpn` does not connect | [Troubleshooting](../../solucion-problemas.md#el-ovpn-descargado-no-conecta) (Spanish) |
| The policies do not kick anyone out | The client's policies page warns if the script is missing from the `server.conf`; see [Policies](policies.md#how-they-are-applied) |
| The history does not say how long each session lasted | The OpenVPN unit starts with `--suppress-timestamps`; `deploy/fechas-log.sh` fixes it |

---

[← Monitoring the VPN](monitoring.md) · [Back to the wiki index](README.md)