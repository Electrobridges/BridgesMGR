# 📱 Two-step in the VPN

**English** · [Español](../../wiki/dos-pasos-vpn.md)

[← Wiki](README.md)

On top of the certificate, the server asks for a 6-digit code from an app like
Google Authenticator, Aegis or Microsoft Authenticator when connecting. A stolen
`.ovpn` is no longer enough: you also need its owner's phone.

It is enabled **client by client**: those without it keep signing in with their
certificate alone, so you can start with the laptops that leave the office and
leave the routers as they are.

## Enabling it

1. **VPN clients → Policies** for the client, then **Two-step verification →
   Enable**.
2. A QR code and the key in text appear. **They are shown only this time**: have
   the person scan it at that moment, or pass them the key through a secure
   channel.
3. **Download them a new `.ovpn`.** The old one does not ask for the code and,
   without it, they will not be able to get in.

> [!NOTE]
> If the server cannot yet ask for the code, the section says so and shows the
> lines that are missing from the `server.conf`. Servers installed with
> `deploy/instalar-openvpn.sh` already have them.

## What the person does when connecting

Their OpenVPN client will ask for **username and password**:

| Field | What to put |
|---|---|
| Username | Anything; their client name is the natural choice |
| Password | **The 6-digit code** the app is showing at that moment |

If their certificate has a password, it asks for that too, separately.

The code is asked for **on connect**, not on every key renewal: a long session
does not ask them every hour. A code already used is not valid twice.

## If they lose the phone or change it

**Generate a new key** invalidates the previous one and shows a new QR code.
The `.ovpn` they already have still works, because what changes is the key,
not the profile.

**Remove** takes them back to signing in with the certificate alone.

## If nobody can get in

Nine times out of ten it is the clock: the code depends on the time, and a
server or a phone with the wrong time gives codes that do not match. Check
`timedatectl` on the server. More cases in
[Troubleshooting](../troubleshooting.md#the-two-step-code-is-always-wrong).

---

[← Access policies](policies.md) · Next: [🛡️ Server security →](security.md)