# ⏱️ Access policies

**English** · [Español](../../wiki/politicas.md)

[← Wiki](README.md)

Every client has their own policies page: **Clientes VPN → Políticas** (VPN
clients → Policies), in the client's row. Everything is optional; an empty field
means *no limit*. Fill in what you need and press **Guardar y aplicar** (Save
and apply).

<img src="../../capturas/politicas.png" alt="ana's policies: temporary access until 31/12/2026 at 18:00, a Monday-to-Friday schedule from 08:00 to 19:00 and Saturdays from 09:00 to 13:00, and a maximum session length of 480 minutes" width="900">

## How they are applied

Checking on connect is not enough, so the panel acts at three moments:

| When | Who | What it does |
|---|---|---|
| **On connect** | A script that OpenVPN runs on every connection | Rejects whoever is outside their schedule, expired or out of quota, and gives them their fixed IP |
| **During the session** | The panel's watchdog, every minute | Kicks out whoever has fallen outside (their time window closed, they hit the maximum session length, they used up their quota) and revokes expired temporary accesses |
| **On the traffic** | The firewall (nftables) | Limits which destinations a client with a fixed IP can reach |

> [!IMPORTANT]
> If the page warns in red that *the policies are not applied on connect*, the
> `server.conf` is missing the lines for the script. Without them the watchdog
> still kicks people out, but the client just connects again on its own. The
> page says exactly what to add; servers installed with
> `deploy/instalar-openvpn.sh` already have them.

## Temporary access

**Caduca** (Expires): from that date and time they cannot connect, whoever is
inside is disconnected, and **their certificate revokes itself**. This is what
you want for a contractor, an external technician or an intern.

It can also be set when creating the client, in the same registration form.

## Schedule

Up to three time windows, each with its own days and start and end time, **in
the server's time zone**. Outside all of them, they cannot connect; if they are
inside when their window closes, they are disconnected.

- To finish at midnight, put `00:00` as the end time.
- A window that crosses midnight (22:00 → 06:00) is split in two:
  `22:00–00:00` and `00:00–06:00`.

## Maximum session length

In minutes. When it is met they are disconnected and have to sign in again
(and type the certificate password, if they have one). Useful so that nobody
leaves the VPN open for days on end.

Empty uses the shared value from **Clientes VPN → Duración máxima de sesión**
(VPN clients → Maximum session length).

## Monthly traffic quota

In GB, upload plus download. The page shows what they have used this month with
a bar and a chart of their last 30 days. When it runs out they are disconnected
and **cannot come back until the 1st of the following month**, when the block
lifts on its own.

To lift it earlier, raise the quota or clear it.

## Fixed IP and destinations

**Fixed IP**: the client always gets the same address inside the VPN. The page
says which range is left free for fixed IPs; if the dynamic pool takes up the
whole network, it explains how to trim it.

**Allowed destinations**: one per line.

```text
192.168.1.0/24          a whole network
192.168.1.10            one machine
192.168.1.10:443/tcp    a single service
```

If you set any, the client reaches **only** those, including with regard to the
VPN server itself. It requires a fixed IP, because that is what identifies the
client in the firewall.

> [!TIP]
> Recipe for a contractor who only maintains one machine: **Caduca** (Expires)
> on the day the contract ends, **Horario** (Schedule) for office hours,
> **IP fija** (Fixed IP), and a single **destino** (destination),
> `DEVICE_IP:443/tcp`. And, if you want, [two-step](vpn-2fa.md).

## What the excluded client sees

Their OpenVPN client cannot get as far as connecting and keeps retrying. In
**Auditoría → VPN → Rechazos** (Audit → VPN → Rejections) it is recorded with
the reason (outside schedule, expired, quota used up…), and on the client's
policies page a yellow warning says whether they could get in right now.

---

[← VPN clients](clients.md) · Next: [📱 Two-step in the VPN →](vpn-2fa.md)