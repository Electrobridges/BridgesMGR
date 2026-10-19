# 📊 Monitoring the VPN

**English** · [Español](../../wiki/vigilar.md)

[← Wiki](README.md)

## The panel

<img src="../../capturas/panel.png" alt="Main panel: two connected, two active certificates, service active and the traffic of the open sessions; below that, the daily traffic charts, this month's traffic ranking per client, and accepted and rejected connections per day" width="900">

At the top, the state right now: connected, certificates, service and the
traffic of the open sessions. Below, **the last 30 days**:

| Chart | What it is for |
|---|---|
| **Traffic per day** | Download and upload stacked. An odd upload spike is worth a look |
| **Who is using the most traffic this month** | The ranking worth seeing before you set [quotas](policies.md#monthly-traffic-quota) |
| **Connections per day** | The normal rhythm of the week |
| **Rejected connections per day** | A spike is usually a scan, or a revoked `.ovpn` that keeps retrying |

Hover over a column to see its values; **Ver los datos** (View the data) expands
the same information as a table.

## Live connections

<img src="../../capturas/conexiones.png" alt="Active connections: luis and ana connected, with their real IP, their virtual IP, the download and upload traffic and the time connected" width="900">

It refreshes itself every 10 seconds. From **Clientes VPN** (VPN clients) you
can disconnect anyone who appears here.

## History

**Auditoría** (Audit) has two tabs:

- **Panel web**: who did what in the panel, when and from which IP, including
  failed sign-ins.
- **VPN**: who got in, when they left, how long the session lasted, who was
  rejected and why, and the sessions displaced by another connection from the
  same profile. It is read from the OpenVPN log and **stored in the database**,
  so it is not lost when logrotate empties the file.

> [!TIP]
> If a profile keeps appearing as a *displaced session* alternating between two
> IPs, the panel warns you: that is the signature of an `.ovpn` being used by
> two people at once.

## Alerts

In **Configuración → Notificaciones** (Settings → Notifications) you choose the
channel and what to be alerted about:

| Category | Examples |
|---|---|
| Panel security | Failed sign-ins, changes to accounts, exports and database cleanups |
| Certificates and CA | Registrations, revocations, `.ovpn` downloads, policy evictions, quotas used up, shared profiles and certificates that expire (at 30, 14, 7, 3 and 1 days) |
| Service health | OpenVPN down and back, CRL about to expire, backups that fail |
| VPN connection rejections | IPs blocked and unblocked |

The channels (SMTP email and a Discord webhook) are configured in
`/etc/ovpn-web/config.yaml`, which the panel can read but not write: that way,
whoever compromises it cannot divert the alerts to their own mailbox. By
default nothing is alerted on; you turn it on by hand.

> [!NOTE]
> A CA that expires leaves **everyone** out at once, so its alert is always
> sent as severe.

## Metrics for Prometheus

`/metrics` exposes the state in Prometheus format: service, connected clients,
traffic per session and per month, certificate and CRL expiry, rejections over
the last 24 h, and blocked IPs. It comes switched off; to turn it on:

```bash
openssl rand -hex 32        # genera el token
sudo nano /etc/ovpn-web/config.yaml
# seguridad:
#   metricas_token: "el-token-generado"
sudo systemctl restart ovpn-web
```

And in Prometheus:

```yaml
scrape_configs:
  - job_name: bridgesmgr
    scheme: https
    tls_config:
      insecure_skip_verify: true   # el certificado del panel es autofirmado
    authorization:
      credentials: "el-token-generado"
    static_configs:
      - targets: ["192.168.1.192:55443"]
```

---

[← Server security](security.md) · Next: [🔧 Maintenance →](maintenance.md)