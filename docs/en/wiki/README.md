# Usage wiki

**English** · [Español](../../wiki/README.md)

Day-to-day guide for BridgesMGR, once it is installed. Each page is one task, in
the order they usually come up. To install it, configure it or understand how it
is put together inside, see the [technical documentation](../../../README.md#-documentation).

| | Page | What it is for |
|---|---|---|
| 🚪 | [Getting started](getting-started.md) | Getting in, finding your way around the menu, the roles and your own 2FA |
| 👤 | [VPN clients](clients.md) | Registering, handing over the `.ovpn`, revoking, restoring and disconnecting |
| ⏱️ | [Access policies](policies.md) | Temporary access, schedules, maximum session length, quotas, fixed IPs and destinations |
| 📱 | [Two-step in the VPN](vpn-2fa.md) | Asking for a code from the phone on top of the certificate |
| 🛡️ | [Server security](security.md) | The `server.conf` audit, tls-crypt-v2 and IP blocking |
| 📊 | [Monitoring the VPN](monitoring.md) | Charts, history, email or Discord alerts and metrics for Prometheus |
| 🔧 | [Maintenance](maintenance.md) | Updating, backups and what to do when something breaks |

> [!TIP]
> Most of what is explained here the panel itself also says, right next to the
> button that does it. The wiki is for having the whole map before you touch
> anything.

## Quick recipes

| I want… | Where |
|---|---|
| Give a contractor access only until Friday | [VPN clients](clients.md#creating-a-client) → the *Expires* field when creating them |
| Let someone in only during office hours | [Policies → Schedule](policies.md#schedule) |
| Let a client reach only one specific server | [Policies → Fixed IP and destinations](policies.md#fixed-ip-and-destinations) |
| Kick someone out right now | [VPN clients → Disconnect](clients.md#disconnecting-someone) |
| Make a stolen `.ovpn` not enough to get in | [Two-step in the VPN](vpn-2fa.md) |
| Find out whether the server is configured correctly | [Security → Audit](security.md#the-serverconf-audit) |
| Get warned about a certificate that expires | [Monitoring → Alerts](monitoring.md#alerts) |
| Recover the panel if I lost my phone | [Maintenance → Locked out of the panel](maintenance.md#locked-out-of-the-panel) |