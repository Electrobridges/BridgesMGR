# 🛡️ Server security

**English** · [Español](../../wiki/seguridad.md)

[← Wiki](README.md)

The **Seguridad** (Security) page has two tabs: the `server.conf` review and IP
blocking.

<img src="../../capturas/seguridad.png" alt="Security page: score 96 out of 100, zero critical, zero warnings, two suggestions and nine good points; the first suggestion proposes moving to tls-crypt-v2 with the command that does it" width="900">

## The `server.conf` audit

The panel reads the `server.conf` and compares it against OpenVPN's hardening
recommendations: control channel, ciphers, minimum TLS version, CRL, duplicate
sessions, compression, privileges, exposed management, and the OpenVPN version
against known vulnerabilities (CVEs).

Every finding has a level and, except for the ones that are fine, **the exact
line that fixes it**:

| Level | What it means | How much it costs |
|---|---|---|
| `CRÍTICO` | A flaw that can be exploited today, or that breaks a panel feature | A lot |
| `AVISO` | It weakens the server without opening it up entirely | Something |
| `SUGERENCIA` | A recommended improvement, no urgency | Little |
| `BIEN` | Correct, so you can see what has been reviewed | Nothing |

> [!IMPORTANT]
> **The panel only reads the `server.conf`, it does not write it.** Whoever
> could write it could run code as root, so the fixes are applied by hand, with
> `sudo`, and then OpenVPN is restarted:
> ```bash
> sudo nano /etc/openvpn/server/server.conf
> sudo systemctl restart openvpn-server@server
> ```

## Moving to tls-crypt-v2

With `tls-crypt`, the key that protects the control channel is **the same in
every `.ovpn`**: anyone who gets hold of one has the key for all of them. With
`tls-crypt-v2` each profile carries its own, generated on every download.

```bash
cd BridgesMGR
sudo bash deploy/migrar-tls-crypt-v2.sh
```

> [!CAUTION]
> After migrating, **nobody gets in until they receive a new `.ovpn`**, and
> OpenVPN clients 2.6 or later are required. Plan for it: tell people, migrate,
> and hand out the new profiles from **VPN clients**. The script refuses to
> enable it with an OpenVPN older than 2.6.14, because of a known flaw
> (CVE-2025-2704).

## Automatic IP blocking

Like fail2ban, but using what the panel already reads from the log: an IP that
accumulates failed attempts from outside — packets without the tls-crypt key,
handshakes that never complete, certificates from another CA — is blocked in
the firewall for a while. It is reviewed every five minutes.

It comes **switched off**. When you turn it on, the defaults are:

| Setting | Default |
|---|---|
| Failed attempts | 10 |
| Within a window of | 10 minutes |
| Blocked for | 60 minutes |
| Never block | `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |

Revoked certificates and policy rejections **do not count**: they are legitimate
clients retrying on their own, and if they share an office's public IP, blocking
it would lock the whole office out.

Below are **Bloquear a mano** (Block by hand), the list of IPs currently blocked
(with a button to unblock) and the block history. The block is lifted by the
kernel itself when it expires, even if the panel is stopped.

---

[← Two-step in the VPN](vpn-2fa.md) · Next: [📊 Monitoring the VPN →](monitoring.md)