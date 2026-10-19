# Security model

This is a web panel that can revoke certificates and kick users off a VPN. It is
worth understanding how it is put together before installing it, and above all
before modifying it.

**Do not expose this panel to the internet.** It is meant for the local network
or to be reached through the VPN itself.

## The privilege boundary

The underlying problem: revoking edits `pki/index.txt`, restoring needs to
delete and reissue files, and creating a client signs with the CA's key. None of
that can be done by an unprivileged user. But a web panel running as root is a
web panel that, the day it fails, hands over the whole server.

The answer is not to spread permissions over `/etc/openvpn`, but to concentrate
everything privileged in one small, auditable place:

```
browser
    │  HTTPS
    ▼
panel (ovpnweb user, unprivileged)
    │  sudo — the only thing authorised
    ▼
/usr/local/sbin/ovpn-web-helper (root, closed subcommands)
    │
    ▼
easyrsa · PKI · systemctl
```

The service runs as `ovpnweb`: no shell, no home directory, and **unable to
write to the PKI or read private keys**. It is only in the `adm` group, to read
the OpenVPN logs, which is the one thing that does not go through the helper.

The helper accepts these subcommands and nothing else:

| Subcommand | What it does |
|---|---|
| `listar` | Reads the PKI and returns the valid and revoked certificates |
| `crear <CN> [con-clave]` | Issues a client certificate; with the flag, it encrypts its private key with the password that arrives over stdin |
| `revocar <CN>` | Revokes and regenerates the CRL |
| `restaurar <CN> [con-clave]` | Redoes the certificate of a revoked CN |
| `ovpn <CN>` | Builds the complete `.ovpn` profile; with tls-crypt-v2, with a new client key |
| `estado-servicio` | Queries the status of the OpenVPN unit |
| `rotar-tls-crypt` | Generates a new tls-crypt key and restarts OpenVPN, undoing it if it does not come back |
| `server-conf` | Returns the directives of the `server.conf` **without** the contents of inline blocks, and the OpenVPN version |
| `aplicar-politicas` | Receives the whole policies document over stdin, revalidates it and writes `/etc/openvpn/ovpn-web/politicas.json` and the nftables rules |
| `bloqueos` / `listar-bloqueos` | Adds or removes IPs from the nftables set with an expiry, and lists it |
| `totp-vpn` | Enables, removes or lists a VPN client's two-step verification (secret over stdin; never returns it) |
| `caducidades` | Expiry dates of the valid certificates, the CA and the server's |

Everything that is not a CN arrives over **stdin** in JSON, never as an argument,
and the helper revalidates all of it even when the panel has already done so.

### What the helper writes outside the PKI

One single folder, `/etc/openvpn/ovpn-web/`, and one single function,
`_escribir_atomico()`, which at runtime rejects any destination that is not
inside it. That is where the policies go (`politicas.json`, 0644, read by the
connection script as `nobody`), the access rules (`acceso.nft`) and the
two-step verification secrets (`totp-vpn.json`, `root:ovpnweb-vpn` 0640: only
OpenVPN reads them, and it runs under that group). **The `server.conf` is never
written**: whoever could do that puts a `script-security 2` with their own `up`
in and runs code as root. There is a test that prevents it.

### The two scripts that OpenVPN runs

`/usr/local/lib/ovpn-web/client-connect` (policies on connect) and
`/usr/local/lib/ovpn-web/verificar-totp` (second factor). root installs them,
they are outside the panel unit's `ReadWritePaths` — the panel decides the
policies, but not the code that applies them —, they run with `python3 -I` and
only use the standard library. They repeat the panel's evaluation instead of
importing it, like everything else that lives on this side of the boundary, and
there are tests that compare the two copies.

### What is still manual

`deploy/reconstruir-ca.sh` and `deploy/migrar-tls-crypt-v2.sh` change the
`server.conf`, so they are neither in the helper nor in the sudoers file: a
person with sudo runs them, they ask for typed confirmation, and they back up
and undo on their own if OpenVPN does not come back up.

It answers with JSON on stdout; errors go to stderr with a non-zero exit code.

## The seven rules that are not broken

If you are going to touch `deploy/`, this is what has to be respected. They are
checked in [tests/test_despliegue.py](../../tests/test_despliegue.py), so breaking
them turns the CI red.

**1. The helper never accepts paths as arguments.**
It reads them from `/etc/ovpn-web/config.yaml`, which is `root:ovpnweb 0640`. If
it took paths from the panel, a compromised panel would point `easyrsa` at its
own binary and would be root. The argument it does accept is the CN, and it
revalidates it.

**2. `easyrsa` is not authorised directly in sudoers.**
`easyrsa` accepts `--pki-dir` and `--vars`. A rule like
`ovpnweb ALL=(root) NOPASSWD: /usr/share/easy-rsa/easyrsa revoke *` is
equivalent to giving away root: it is enough to pass a `--vars` pointing at your
own file. The helper is authorised, with an absolute path and no wildcards, and
nothing else.

**3. The Common Name is validated on both sides.**
[app/core/validacion.py](../../app/core/validacion.py) and the helper's `CN_RE` /
`RESERVADOS` block must be identical. The helper does not trust the panel even
when the panel already validates: they are different sides of a privilege
boundary. There is a test that compares the two regexes and fails if they
diverge.

The CN ends up in arguments of `easyrsa` run as root and in paths inside the
PKI, so the rule is restrictive on purpose: letters, digits, dot, hyphen and
underscore, starting and ending alphanumeric, maximum 64. That leaves out
`../../etc/passwd`, `cliente;rm -rf /`, `--pki-dir=/tmp`, newlines (which would
be an injection in the management protocol) and the reserved names `server` and
`ca`.

**4. `NoNewPrivileges` must stay `false`, and declaring it is not enough.**
Sudo is setuid: with the flag set it cannot escalate to the helper, so the panel
starts and issues nothing, revokes nothing and does not even list certificates
— it breaks precisely the thing it exists for, and with an error that does not
point at the cause.

What took discovering on the first real deployment is that
**`NoNewPrivileges=false` can be ignored**. From `systemd.exec(5)`:

> *"Defaults to false, but certain settings override this and ignore the value
> of this setting."*

Any option that installs a seccomp filter turns it on anyway, because the kernel
requires `no_new_privs` to load a filter without `CAP_SYS_ADMIN` and the
service runs unprivileged. So **none of these can be added to the unit**, no
matter what any hardening guide recommends:

```
SystemCallFilter        SystemCallArchitectures   RestrictAddressFamilies
RestrictNamespaces      RestrictRealtime          RestrictSUIDSGID
LockPersonality         MemoryDenyWriteExecute    PrivateDevices
ProtectKernelTunables   ProtectKernelModules      ProtectKernelLogs
ProtectClock            DynamicUser
ProtectHostname         ProtectControlGroups
```

The last two are not in that list in the systemd documentation, but they behave
the same way: measured on a real server, with the previous fourteen disabled the
process was still running with `no_new_privs=1`. There is a test that rejects
all sixteen.

What is left — `ProtectSystem=strict` with `ReadWritePaths` limited to two
paths, `PrivateTmp`, `ProtectHome`, `ProtectProc`, `PrivateMounts` and
`UMask=0077` — goes through namespaces and not through seccomp. It is also the
most valuable control of the lot: filesystem confinement.

The good answer in the medium term is for the panel to stop escalating with
setuid — a root service listening on a Unix socket — and then the sixteen would
be recoverable.

**5. `subprocess` always with an argument list, never `shell=True`.**
Checked over the syntax tree of all of `app/` and of the helper.

**6. The certificate password never touches `argv`.**
From the panel to the helper it travels over **stdin**; from the helper to
easyrsa, through the **environment** (`--passout=env:`). The helper's fourth
argument is the fixed flag `con-clave`, never the secret. `argv` is public in
`/proc`: with `--passout=pass:…` anyone with an account on the server could read
a certificate's password with a `ps` in the second it takes to issue it.

**7. `ReadWritePaths` has to cover the PKI.**
`ProtectSystem=strict` mounts the system read-only inside the service's
namespace, and **the children inherit it**: including the helper launched with
sudo, even though it runs as root. Without `/etc/openvpn` in `ReadWritePaths`
the panel cannot issue, revoke or restore a single certificate, and it fails
with an easyrsa error that does not mention systemd anywhere. If you move the
PKI, that line has to follow it.

Likewise, `UMask=0077` is inherited down to `easyrsa`: everything it writes
comes out 0600, the CRL included. That is why the helper sets the permissions by
hand after regenerating it, instead of trusting the umask.

## Setting up the OpenVPN server

[`deploy/instalar-openvpn.sh`](../../deploy/instalar-openvpn.sh) is deliberately
apart from the panel's installer: `install.sh` holds up the privilege boundary
and it is good if it still fits in one reading, whereas this sets up a VPN and
touches the machine's routing. They are two jobs with different risks. There is
a test that stops `install.sh` from ending up setting up the VPN on its own.

What you need to know about what it leaves in place:

- **`pki/private` stays 0700.** The script relaxes permissions in the rest of the
  PKI so that OpenVPN can read the CRL, and that must not end up opening the
  directory where the CA's key is. There is a test that watches it.
- **The CRL has to be readable by everyone**, and that is not an oversight:
  OpenVPN reads it again on every connection, and by then it has already dropped
  to `nobody`. A CRL is public by definition. For the same reason the helper
  leaves it at 0644 every time it regenerates it: if `gen-crl` left it at 0600,
  revoking a certificate would leave the server admitting **nobody**, and
  without anything saying so.
- **Management listens on `127.0.0.1:7505` without a password.** It is what the
  panel knows how to talk to, and whoever reaches that port can kick clients
  out. On the loopback that means: anyone with a session on the VPN server. Do
  not hand out shell accounts on that machine.
- **The NAT goes in its own nftables table** (`ip ovpnweb`), not mixed in with
  the existing rules. You can see whose it is and removing it does not take
  anything else with it.

## Authentication and sessions

- Passwords with **Argon2**.
- The database stores the **SHA-256 of the session token**, not the token.
  Stealing the `.db` yields neither passwords nor usable sessions.
- `httpOnly` cookie + `SameSite=Strict` + `Secure` (configurable only in case
  you serve over plain HTTP).
- Lockout after N failed attempts, counted per **user + IP**: that way a third
  party cannot lock the administrator out from another address.
- **There is no default user.** The first one is created by hand with the CLI.

## Roles and hierarchy

Three steps. `superusuario` and `admin` can mutate the server — which is what
`auth.solo_admin` looks at —, `supervisor` only reads.

| Role | Scope |
|---|---|
| `superusuario` | Commands the same as an admin and on top of that is **untouchable**: nobody can change its role, deactivate it, delete it, or touch its password or second factor |
| `admin` | Mutates the server and manages accounts, including other admins'. It does not reach the superusuario |
| `supervisor` | Read only: panel, connections, clients, logs and audit log. They do not get into *Usuarios* or *Configuración* |

What a supervisor does **not** see does not appear in their menu either. And no
template decides that by comparing the role name: `routers/comun.py:render()`
injects `manda` from `db.ROLES_MANDO`, the same list that `solo_admin` looks at.
Spreading that decision across templates is how you forget when adding a role —
it happened when `superusuario` was introduced, which lost half the panel without
a single route failing. There is a test that prevents comparing `sesion.rol`
with a string again.

*Configuración* is outside the supervisor's scope because it shows the PKI and
log paths, the management port and the unit status: it is the installation's
blueprint, and someone who only looks does not need it.

**The superusuario is not granted: you are born with it.** It is the first
account created in the installation, whatever role was asked for. It does not
appear among the assignable roles, neither in the panel nor in `--rol`, and a
partial unique index in the database guarantees there is not a second one even if
the code fails.

Being untouchable includes the password, and not out of over-caution: if an
admin could change it, they would sign in with it and be superusuario in two
steps. For the same reason they cannot remove its second factor either, which
would reduce the account in charge to a single password. The only way out is the
CLI, which requires being inside the server — the same boundary as everything
else.

For that same reason the CLI **can** hand the role over:

```bash
sudo -u ovpnweb venv/bin/python -m app.cli designar-superusuario otra_cuenta
```

It does not contradict it being fixed: it is fixed *from the panel*, which is
where it matters. Whoever can run that command is already inside the server and
has more authority than any role. It exists because otherwise two situations
would leave an installation with no possible fix: a migrated database that had
no admin to promote, and another where the promotion fell on the wrong account.
It asks for confirmation, closes the sessions of both affected accounts and is
audited.

**Nobody changes their own role**, superusuario included. Anyone who could
promote themselves would have nobody above them, and anyone who demoted
themselves by mistake would end up outside the only page where you can fix it.

Who can touch whom lives in
[app/routers/administracion.py](../../app/routers/administracion.py) and not in
`auth.py`: `solo_admin` answers "can this mutate the server?", which depends on
nobody else, whereas this depends on the target account and does not fit in a
FastAPI dependency.

## Two-step verification (TOTP)

A 6-digit code that changes every 30 seconds, generated by a phone app (Google
Authenticator, Aegis, FreeOTP…). It is **standard TOTP** (RFC 6238, SHA-1, 6
digits, 30 s), implemented in [app/core/totp.py](../../app/core/totp.py) with the
standard library: it adds no dependency at all, and the tests contrast it
against the RFC's official vectors.

### Who uses it

| Role | Rule |
|---|---|
| `superusuario` | **Optional.** Enables it from `/perfil`, and nobody else can remove it |
| `admin` | **Optional.** Each administrator enables their own from `/perfil` |
| `supervisor` | **An admin decides.** If it is required, supervisor accounts without a second factor can only go to their profile until they enable it |

The policy **never reaches whoever is in charge**, and that is deliberate: if an
admin could impose it on another, they could lock out an equal. Here whoever
has access to the server is in charge, not whoever reaches the panel first.

The switch lives in the `ajustes` table of the database, **not in
`config.yaml`**. Two reasons: the panel runs as `ovpnweb` and `config.yaml` is
`root:ovpnweb 0640`, so it cannot write it; and it is an operational decision,
not a deployment one.

### Signing up

A **QR** is shown to scan with the app and, next to it, the key in groups of
four in case you prefer typing it. The QR goes as a `data:` URI inside an
`<img>`: the CSP already allows `img-src 'self' data:` without being touched,
and inside an `<img>` the SVG is drawn in restricted mode, with no scripts and
no requests to the network. Nothing leaves the server — there is no external
service involved at all.

It is generated by [`segno`](https://pypi.org/project/segno/), the **only
dependency of the panel** apart from the web framework, and it was chosen
deliberately: a QR encoder is about three hundred lines of Reed-Solomon and
capacity tables per version, and its failure mode — "it does not scan" — is only
visible with a phone in front of it. That is not auditable at a glance, which
was the reason for writing the TOTP by hand. If the package is missing, the
panel **says so on screen** and signing up is still possible with the key.

### How it holds up

- **Signing up is not accepted until it is confirmed.** The secret is generated,
  shown once, and only activated when the user types a correct code. Otherwise
  anyone who copies it wrong is locked out.
- **Neither the secret nor the QR are shown again** after sign-up: the QR is the
  secret in another format, so whoever borrows an open session cannot clone the
  second factor by either route.
- **A code is not valid twice.** The last accepted interval is stored and any
  earlier or equal one is rejected. Without that, an intercepted code is good
  for the rest of its window.
- **The password alone opens nothing.** It leaves an intermediate cookie
  (`ovpnweb_2fa`, 5 minutes, `httpOnly`+`Secure`+`SameSite=Strict`) which is
  not a session: with it the only thing you can do is present a code.
- **Failed codes use up attempts** from the same counter as passwords. Otherwise
  the second factor would be a 6-digit field with unlimited attempts.
- **±30 s of drift** between the server clock and the phone's is tolerated, and
  not one second more.

### If someone loses their phone

They are locked out: that is what a second factor means. There are two ways out,
both audited:

```bash
# Desde el panel, cualquier admin:  /admin/usuarios -> "Restablecer 2FA"

# Desde el servidor, cuando el que se ha quedado fuera es el único admin:
cd /opt/ovpn-web
sudo -u ovpnweb venv/bin/python -m app.cli totp-restablecer <usuario>
```

Resetting also **closes all the sessions of that account**: if the second factor
was compromised, the sessions opened with it are compromised too.

## CSRF and CSP

Every route that mutates state depends on three things: a valid session, a
sufficient role and a correct `X-CSRF-Token` header. The `base.html` template
injects the token into `hx-headers`, so all HTMX requests carry it without
anyone having to remember. A third-party site cannot set its own headers on a
cross-origin request, and the cookie is `SameSite=Strict`: those are two
independent barriers.

The CSP is `script-src 'self'`, with no CDNs and no inline scripts. That is why
`htmx.min.js` is served from the server itself, downloaded by `install.sh` and
verified against `deploy/htmx.sha256` by SHA-256, and not versioned.

## Audit

Every mutation is recorded with who, what, when, from which IP and **with what
result**, including failures and failed login attempts. Downloading a `.ovpn` is
audited too: that file **is** the access to the VPN, and it is limited to the
admin role.

## Client certificate password

A `.ovpn` carries the private key inside: on its own, it **is** the access to the
VPN for whoever gets hold of the file. That is why, when creating a client, that
key can be encrypted with a password, and the box is ticked by default. OpenVPN
asks for it when connecting, so the file alone is no longer enough.

You untick it for unattended clients — a router, a server, a container — that
have to reconnect on their own: there would be nobody to type it.

How it travels, which is the part that matters:

- **Never through `argv`.** From the panel to the helper it goes over **stdin**;
  from the helper to easyrsa, through an **environment variable**
  (`--passout=env:…`). `argv` is public in `/proc`: with `--passout=pass:…`
  anyone with an account on the server could read a certificate's password with
  a `ps` in the second it takes to issue it. A process's environment is only
  readable by its owner or root, and the helper is already root. There is a
  test that prevents the shortcut.
- **It is not logged.** The audit log records *that* the certificate was
  encrypted, never with what. The audit log is read by any authenticated user,
  supervisor included.
- **It is validated in all three places**: form, panel and helper. The helper
  repeats the minimum on its own account, as with the CN: from that side of the
  boundary the panel is not to be trusted.
- **It cannot be recovered.** If it is lost, the certificate has to be reissued
  with *Restaurar* — which is why that also accepts a password.

Give it to whoever uses the profile through a channel other than the `.ovpn`
itself. Sending both together over the same email protects nothing.

## Sensitive material

`.gitignore` blocks `*.crt`, `*.key`, `*.pem`, `*.ovpn`, `pki/`, `tls/`,
`*.db` and `config.yaml`. If you open an issue, do not paste any of those files
nor the full output of `config.yaml`.

## What is tested and what is not

The unprivileged half has 283 tests: parsers in all three formats, CN validation,
login and lockout, second factor (including the RFC 6238 vectors, code reuse,
the QR and the policy), permissions per role, CSRF, security headers and the
audit log.

Of the QR, everything checkable without a phone is checked: that the SVG is
valid and self-contained, that the longest username the panel admits fits (64
characters → version 10), that it reaches the page with alternative text and
that it disappears when sign-up is confirmed. **That it really scans has to be
tested with a phone.**

Of the privileged half, only what is checkable without root is checked: the
syntax of the helper and the installer, the sudo rule with `visudo -c`, the
invariants above and the line endings. **The real behaviour — revoking,
restoring, issuing — is only exercised on a real Debian.** Try it in a VM
before the good server; the helper makes a timestamped copy of the PKI before
touching it, but that is not a substitute for a VM.