# 👤 VPN clients

**English** · [Español](../../wiki/clientes.md)

[← Wiki](README.md)

A *VPN client* is a certificate: a person, a laptop or a router that connects.
Do not confuse it with the panel accounts.

<img src="../../capturas/clientes.png" alt="VPN clients page: the create client form with expiry and password, the maximum session length for everyone, and the table with ana and luis connected; ana carries the tags for her policies" width="900">

## Creating a client

1. **Clientes VPN → Crear cliente** (VPN clients → Create client). The name is
   the certificate's *Common Name*: letters, digits, `-` and `_`. Use something
   that identifies the device or the person (`ana-portatil`, `router-almacen`).
2. **Caduca** (Expires, optional): the date and time from which it can no longer
   get in. When it arrives, whoever is inside is disconnected and the
   certificate revokes itself. Ideal for contractors and one-off access.
3. **Cifrar la clave privada con contraseña** (Encrypt the private key with
   a password, ticked by default): the `.ovpn` on its own is not enough, you
   need the password to connect. Untick it only for unattended devices that have
   to reconnect on their own.
4. **Crear y emitir certificado** (Create and issue certificate).

> [!WARNING]
> The certificate password **cannot be recovered**. If it is lost, the
> certificate has to be revoked and a new one issued. Give it to the person
> through a channel other than the `.ovpn` itself.

## Handing over the profile

**Descargar .ovpn** (Download .ovpn) fetches the complete profile, with the
certificates and keys inside: a single file that is imported into OpenVPN
Connect, the OpenVPN client for Windows/macOS/Linux, or Tunnelblick.

Treat it like a key: whoever has it gets in (with the password, if it has one).
Send it through a channel that does not keep it around forever.

## The *Access* column

It sums up each client: this month's traffic and one tag per active policy
(expiry, schedule, maximum session length, quota, fixed IP, destinations). If
the certificate expires in under 30 days, it says so too. The **Políticas**
(Policies) link opens their [policies](policies.md) page.

## Disconnecting someone

**Desconectar** (Disconnect) cuts their session immediately, through OpenVPN's
management interface.

> [!CAUTION]
> Disconnecting **does not stop them coming back**: their client will reconnect
> on its own within seconds. To stop that, **Revocar** (Revoke), or take away
> their access with a [policy](policies.md) (an expiry that has already passed,
> for instance).

## Revoking and restoring

**Revocar** (Revoke) invalidates the certificate: the panel regenerates the CRL
and OpenVPN rejects it on the next connection. If they were connected, they are
kicked out.

A revoked client appears in the table with **Restaurar** (Restore), which issues
them a certificate again with the same name. Their old `.ovpn` does **not**
become valid again: you have to download them a new one.

An expired temporary access is not brought back by restoring: the panel first
asks you to change or clear its expiry date in the policies.

## Maximum session length for everyone

Below the registration form, **Duración máxima de sesión** (Maximum session
length) sets how many minutes a connection may last before it is forced to sign
in again. It applies to every client that does not have one of its own in their
policies.

---

[← Getting started](getting-started.md) · Next: [⏱️ Access policies →](policies.md)