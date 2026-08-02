# Modelo de seguridad

Esto es un panel web que puede revocar certificados y expulsar usuarios de una
VPN. Conviene entender cómo está montado antes de instalarlo, y sobre todo
antes de modificarlo.

**No expongas este panel a internet.** Está pensado para la red local o para
llegar a él a través de la propia VPN.

## La frontera de privilegios

El problema de fondo: revocar edita `pki/index.txt`, restaurar necesita borrar
y reemitir archivos, y crear un cliente firma con la clave de la CA. Nada de
eso lo puede hacer un usuario sin privilegios. Pero un panel web que corra como
root es un panel web que, el día que falle, entrega el servidor entero.

La salida no es repartir permisos sobre `/etc/openvpn`, sino concentrar todo lo
privilegiado en un único sitio pequeño y auditable:

```
navegador
    │  HTTPS
    ▼
panel (usuario ovpnweb, sin privilegios)
    │  sudo — lo único autorizado
    ▼
/usr/local/sbin/ovpn-web-helper (root, 6 subcomandos)
    │
    ▼
easyrsa · PKI · systemctl
```

El servicio corre como `ovpnweb`: sin shell, sin directorio propio, y **sin
poder escribir en la PKI ni leer claves privadas**. Solo está en el grupo `adm`
para leer los logs de OpenVPN, que es lo único que no pasa por el helper.

El helper acepta seis subcomandos y nada más:

| Subcomando | Qué hace |
|---|---|
| `listar` | Lee la PKI y devuelve los certificados válidos y revocados |
| `crear <CN> [con-clave]` | Emite un certificado de cliente; con la marca, cifra su clave privada con la contraseña que llega por stdin |
| `revocar <CN>` | Revoca y regenera la CRL |
| `restaurar <CN> [con-clave]` | Rehace el certificado de un CN revocado |
| `ovpn <CN>` | Monta el perfil `.ovpn` completo |
| `estado-servicio` | Consulta el estado de la unidad de OpenVPN |

Responde JSON por stdout; los errores van a stderr con código distinto de cero.

## Las siete reglas que no se rompen

Si vas a tocar `deploy/`, esto es lo que hay que respetar. Están comprobadas en
[tests/test_despliegue.py](../tests/test_despliegue.py), así que romperlas pone
la CI en rojo.

**1. El helper nunca acepta rutas por argumento.**
Las lee de `/etc/ovpn-web/config.yaml`, que es `root:ovpnweb 0640`. Si tomara
rutas del panel, un panel comprometido apuntaría `easyrsa` a un binario propio
y sería root. El argumento que sí acepta es el CN, y lo revalida.

**2. No se autoriza `easyrsa` directamente en sudoers.**
`easyrsa` acepta `--pki-dir` y `--vars`. Una regla del tipo
`ovpnweb ALL=(root) NOPASSWD: /usr/share/easy-rsa/easyrsa revoke *` equivale a
regalar root: basta con pasar un `--vars` que apunte a un archivo propio. Se
autoriza el helper, con ruta absoluta y sin comodines, y nada más.

**3. El Common Name se valida a los dos lados.**
[app/core/validacion.py](../app/core/validacion.py) y el bloque `CN_RE` /
`RESERVADOS` del helper deben ser idénticos. El helper no se fía del panel
aunque el panel ya valide: son lados distintos de una frontera de privilegios.
Hay una prueba que compara los dos regex y falla si divergen.

El CN acaba en argumentos de `easyrsa` ejecutado como root y en rutas dentro de
la PKI, así que la regla es restrictiva a propósito: letras, números, punto,
guion y guion bajo, empezando y terminando en alfanumérico, máximo 64. Quedan
fuera `../../etc/passwd`, `cliente;rm -rf /`, `--pki-dir=/tmp`, los saltos de
línea (que serían inyección en el protocolo del management) y los nombres
reservados `server` y `ca`.

**4. `NoNewPrivileges` debe seguir en `false`, y declararlo no basta.**
Sudo es setuid: con la bandera puesta no puede escalar al helper, así que el
panel arranca y no emite, no revoca y ni siquiera lista certificados — se rompe
justo aquello para lo que existe, y con un error que no señala la causa.

Lo que costó descubrir en el primer despliegue real es que **`NoNewPrivileges=false`
se puede ignorar**. De `systemd.exec(5)`:

> *"Defaults to false, but certain settings override this and ignore the value
> of this setting."*

Cualquier opción que instale un filtro seccomp la enciende igualmente, porque
el kernel exige `no_new_privs` para cargar un filtro sin `CAP_SYS_ADMIN` y el
servicio corre sin privilegios. Así que **no se puede añadir a la unidad**
ninguna de estas, por mucho que las recomiende cualquier guía de endurecimiento:

```
SystemCallFilter        SystemCallArchitectures   RestrictAddressFamilies
RestrictNamespaces      RestrictRealtime          RestrictSUIDSGID
LockPersonality         MemoryDenyWriteExecute    PrivateDevices
ProtectKernelTunables   ProtectKernelModules      ProtectKernelLogs
ProtectClock            DynamicUser
ProtectHostname         ProtectControlGroups
```

Las dos últimas no figuran en esa lista de la documentación de systemd, pero se
comportan igual: medido en un servidor real, con las catorce anteriores
desactivadas el proceso seguía con `no_new_privs=1`. Hay una prueba que rechaza
las dieciséis.

Lo que queda —`ProtectSystem=strict` con `ReadWritePaths` acotado a dos rutas,
`PrivateTmp`, `ProtectHome`, `ProtectProc`, `PrivateMounts` y `UMask=0077`— va
por espacios de nombres y no por seccomp. Es además el control de más valor: el
confinamiento del sistema de archivos.

La salida buena a medio plazo es que el panel deje de escalar con setuid —un
servicio root escuchando en un socket Unix— y entonces se recuperarían las
dieciséis.

**5. `subprocess` siempre con lista de argumentos, jamás `shell=True`.**
Comprobado sobre el árbol sintáctico de todo `app/` y del helper.

**6. La contraseña del certificado no toca `argv`.**
Del panel al helper viaja por **stdin**; del helper a easyrsa, por el
**entorno** (`--passout=env:`). El cuarto argumento del helper es la marca fija
`con-clave`, nunca el secreto. `argv` es público en `/proc`: con
`--passout=pass:…` cualquiera con una cuenta en el servidor podría leer la
contraseña de un certificado con un `ps` en el segundo que dura la emisión.

**7. `ReadWritePaths` tiene que cubrir la PKI.**
`ProtectSystem=strict` monta el sistema en solo lectura dentro del espacio de
nombres del servicio, y **los hijos lo heredan**: también el helper lanzado con
sudo, aunque corra como root. Sin `/etc/openvpn` en `ReadWritePaths` el panel no
puede emitir, revocar ni restaurar un solo certificado, y falla con un error de
easyrsa que no menciona systemd por ningún lado. Si mueves la PKI, esa línea
tiene que seguirla.

Del mismo modo, `UMask=0077` se hereda hasta `easyrsa`: todo lo que escribe sale
en 0600, CRL incluida. Por eso el helper le pone los permisos a mano después de
regenerarla, en vez de fiarlo al umask.

## Montar el servidor OpenVPN

[`deploy/instalar-openvpn.sh`](../deploy/instalar-openvpn.sh) va aparte del
instalador del panel a propósito: `install.sh` sostiene la frontera de
privilegios y conviene que siga cabiendo de una lectura, mientras que esto
monta una VPN y toca el encaminamiento de la máquina. Son dos trabajos con
riesgos distintos. Hay una prueba que impide que `install.sh` acabe montando la
VPN por su cuenta.

Lo que hay que saber de lo que deja montado:

- **`pki/private` se queda en 0700.** El script relaja permisos en el resto de
  la PKI para que OpenVPN pueda leer la CRL, y eso no puede acabar abriendo el
  directorio donde está la clave de la CA. Hay una prueba que lo vigila.
- **La CRL tiene que ser legible por todos**, y no es un descuido: OpenVPN la
  relee en cada conexión y para entonces ya bajó a `nobody`. Una CRL es pública
  por definición. Por lo mismo el helper la deja en 0644 cada vez que la
  regenera: si `gen-crl` la dejara en 0600, revocar un certificado dejaría al
  servidor sin admitir a **nadie**, y sin que nada lo dijera.
- **El management escucha en `127.0.0.1:7505` sin contraseña.** Es lo que el
  panel sabe hablar, y quien alcance ese puerto puede expulsar clientes. En el
  bucle local eso significa: cualquiera con una sesión en el servidor VPN. No
  repartas cuentas de shell en esa máquina.
- **El NAT va en su propia tabla de nftables** (`ip ovpnweb`), no mezclado con
  las reglas existentes. Se ve de quién es y quitarla no se lleva nada por
  delante.

## Autenticación y sesiones

- Contraseñas con **Argon2**.
- En la base de datos se guarda el **SHA-256 del token de sesión**, no el
  token. Robar el `.db` no da ni contraseñas ni sesiones utilizables.
- Cookie `httpOnly` + `SameSite=Strict` + `Secure` (configurable solo por si
  sirves en HTTP plano).
- Bloqueo tras N intentos fallidos, contado por **usuario + IP**: así un
  tercero no puede dejar fuera al administrador desde otra dirección.
- **No hay usuario por defecto.** El primero se crea a mano con la CLI.

## Roles y jerarquía

Tres escalones. `superusuario` y `admin` pueden mutar el servidor —es lo que
mira `auth.solo_admin`—, `supervisor` solo consulta.

| Rol | Alcance |
|---|---|
| `superusuario` | Manda igual que un admin y además es **intocable**: nadie puede cambiarle el rol, desactivarlo, borrarlo, ni tocarle la contraseña o el segundo factor |
| `admin` | Muta el servidor y gestiona cuentas, incluidas las de otros admins. No alcanza al superusuario |
| `supervisor` | Solo consulta: panel, conexiones, clientes, logs y auditoría. No entra en *Usuarios* ni en *Configuración* |

Lo que un supervisor **no** ve tampoco aparece en su menú. Y ninguna plantilla
decide eso comparando el nombre del rol: `routers/comun.py:render()` inyecta
`manda` desde `db.ROLES_MANDO`, la misma lista que mira `solo_admin`. Repartir
esa decisión por las plantillas es cómo se olvida al añadir un rol — pasó al
introducir `superusuario`, que perdió medio panel sin que ninguna ruta fallara.
Hay una prueba que impide volver a comparar `sesion.rol` con una cadena.

*Configuración* queda fuera del alcance del supervisor porque enseña las rutas
de la PKI y de los logs, el puerto del management y el estado de la unidad: es
el plano de la instalación, y a quien solo mira no le hace falta.

**El superusuario no se concede: se nace con él.** Lo es la primera cuenta que
se creó en la instalación, se pidiera el rol que se pidiera. No aparece entre
los roles asignables, ni en el panel ni en `--rol`, y un índice único parcial
en la base garantiza que no haya dos aunque falle el código.

Que sea intocable incluye la contraseña, y no por exceso de celo: si un admin
pudiera cambiársela, entraría con ella y sería superusuario en dos pasos. Por
lo mismo tampoco puede quitarle el segundo factor, que sería rebajar a una sola
contraseña la cuenta que manda. La única vía de recuperación es la CLI, que
exige estar dentro del servidor — la misma frontera que todo lo demás.

Por eso mismo la CLI **sí** puede trasladar el rol:

```bash
sudo -u ovpnweb venv/bin/python -m app.cli designar-superusuario otra_cuenta
```

No contradice que sea fijo: lo es *desde el panel*, que es donde importa. Quien
puede ejecutar esa orden ya está dentro del servidor y tiene más autoridad que
cualquier rol. Existe porque si no, dos situaciones dejarían una instalación
sin arreglo posible: una base migrada que no tenía ningún admin al que
ascender, y otra en la que el ascenso recayó en la cuenta equivocada. Pide
confirmación, cierra las sesiones de las dos cuentas afectadas y queda
auditado.

**Nadie cambia su propio rol**, superusuario incluido. Quien pudiera ascenderse
no tendría a nadie por encima, y quien se degradara por error quedaría fuera de
la única página donde arreglarlo.

Quién puede tocar a quién vive en
[app/routers/administracion.py](../app/routers/administracion.py) y no en
`auth.py`: `solo_admin` responde "¿puede mutar el servidor?", que no depende de
nadie más, mientras que esto depende de la cuenta de destino y no cabe en una
dependencia de FastAPI.

## Verificación en dos pasos (TOTP)

Código de 6 dígitos que cambia cada 30 segundos, generado por una aplicación
del móvil (Google Authenticator, Aegis, FreeOTP…). Es **TOTP estándar**
(RFC 6238, SHA-1, 6 dígitos, 30 s), implementado en
[app/core/totp.py](../app/core/totp.py) con la biblioteca estándar: no añade
ninguna dependencia, y las pruebas lo contrastan contra los vectores oficiales
de la RFC.

### Quién lo usa

| Rol | Regla |
|---|---|
| `superusuario` | **Opcional.** Lo activa desde `/perfil`, y nadie más se lo puede quitar |
| `admin` | **Opcional.** Cada administrador activa el suyo desde `/perfil` |
| `supervisor` | **Lo decide un admin.** Si lo exige, las cuentas supervisor sin segundo factor solo pueden ir a su perfil hasta activarlo |

La política **nunca alcanza a quien manda**, y es deliberado: si un admin
pudiera imponérselo a otro, podría dejar fuera a un igual. Aquí manda quien
tiene acceso al servidor, no quien llega antes al panel.

El interruptor vive en la tabla `ajustes` de la base de datos, **no en
`config.yaml`**. Dos motivos: el panel corre como `ovpnweb` y `config.yaml` es
`root:ovpnweb 0640`, así que no puede escribirlo; y es una decisión de
operación, no de despliegue.

### El alta

Se muestra un **QR** para escanear con la app y, al lado, la clave en grupos
de cuatro por si se prefiere teclearla. El QR va como `data:` URI dentro de un
`<img>`: la CSP ya admite `img-src 'self' data:` sin tocarla, y dentro de un
`<img>` el SVG se dibuja en modo restringido, sin scripts ni peticiones a la
red. Nada sale del servidor — no hay ningún servicio externo de por medio.

Lo genera [`segno`](https://pypi.org/project/segno/), la **única dependencia
del panel** aparte del marco web, y está elegida a conciencia: un codificador
QR son unas trescientas líneas de Reed-Solomon y tablas de capacidad por
versión, y su modo de fallo —"no escanea"— solo se ve con un móvil delante.
Eso no es auditable de un vistazo, que fue el motivo de escribir el TOTP a
mano. Si el paquete falta, el panel **lo dice en pantalla** y el alta sigue
siendo posible con la clave.

### Cómo se sostiene

- **El alta no se da por buena hasta confirmarla.** Se genera el secreto, se
  muestra una vez, y solo se activa cuando el usuario teclea un código
  correcto. Si no, cualquiera que lo copie mal se queda fuera.
- **Ni el secreto ni el QR se vuelven a mostrar** después del alta: el QR es
  el secreto en otro formato, así que quien tome prestada una sesión abierta
  no puede clonarse el segundo factor por ninguna de las dos vías.
- **Un código no vale dos veces.** Se guarda el último intervalo aceptado y se
  rechaza cualquiera anterior o igual. Sin eso, un código interceptado sirve
  durante el resto de su ventana.
- **La contraseña sola no abre nada.** Deja una cookie intermedia
  (`ovpnweb_2fa`, 5 minutos, `httpOnly`+`Secure`+`SameSite=Strict`) que no es
  una sesión: con ella solo se puede presentar un código.
- **Los códigos fallidos gastan intentos** del mismo contador que las
  contraseñas. Si no, el segundo factor sería un campo de 6 dígitos con
  intentos ilimitados.
- **Se tolera ±30 s** de desfase entre el reloj del servidor y el del móvil, y
  ni un segundo más.

### Si alguien pierde el móvil

Se queda fuera: es lo que significa un segundo factor. Hay dos salidas, ambas
auditadas:

```bash
# Desde el panel, cualquier admin:  /admin/usuarios -> "Restablecer 2FA"

# Desde el servidor, cuando el que se ha quedado fuera es el único admin:
cd /opt/ovpn-web
sudo -u ovpnweb venv/bin/python -m app.cli totp-restablecer <usuario>
```

Restablecer **cierra además todas las sesiones de esa cuenta**: si el segundo
factor estaba comprometido, las sesiones abiertas con él también lo están.

## CSRF y CSP

Toda ruta que muta estado depende de tres cosas: sesión válida, rol suficiente
y cabecera `X-CSRF-Token` correcta. La plantilla `base.html` inyecta el token
en `hx-headers`, así que todas las peticiones HTMX lo llevan sin tener que
acordarse. Una web ajena no puede fijar cabeceras propias en una petición
entre orígenes, y la cookie es `SameSite=Strict`: son dos barreras
independientes.

La CSP es `script-src 'self'`, sin CDNs ni scripts inline. Por eso
`htmx.min.js` se sirve desde el propio servidor, lo descarga `install.sh`
verificando su SHA-256 contra `deploy/htmx.sha256`, y no se versiona.

## Auditoría

Toda mutación queda registrada con quién, qué, cuándo, desde qué IP y **con qué
resultado**, incluidos los fallos y los intentos de login fallidos. La descarga
de un `.ovpn` también se audita: ese archivo **es** el acceso a la VPN, y está
limitada al rol admin.

## Contraseña del certificado de cliente

Un `.ovpn` lleva la clave privada dentro: sin más, **es** el acceso a la VPN
para quien se haga con el archivo. Por eso al crear un cliente se puede cifrar
esa clave con una contraseña, y la casilla viene marcada por defecto. OpenVPN la
pide al conectar, así que el archivo por sí solo deja de bastar.

Se desmarca para clientes desatendidos —un rúter, un servidor, un contenedor—
que tengan que reconectar solos: no habría nadie para escribirla.

Cómo viaja, que es lo que importa:

- **Nunca por `argv`.** Del panel al helper va por **stdin**; del helper a
  easyrsa, por una **variable de entorno** (`--passout=env:…`). `argv` es
  público en `/proc`: con `--passout=pass:…` cualquiera con una cuenta en el
  servidor podría leer la contraseña de un certificado con un `ps` en el
  segundo que dura la emisión. El entorno de un proceso solo lo lee su dueño o
  root, y el helper ya es root. Hay una prueba que impide el atajo.
- **No se registra.** En la auditoría consta *que* el certificado se cifró,
  nunca con qué. La auditoría la lee cualquier usuario autenticado, supervisor
  incluido.
- **Se valida en los tres sitios**: formulario, panel y helper. El helper repite
  el mínimo por su cuenta, como con el CN: desde ese lado de la frontera el
  panel no es de fiar.
- **No se puede recuperar.** Si se pierde, hay que reemitir el certificado con
  *Restaurar* — que por eso también admite contraseña.

Dásela a quien use el perfil por una vía distinta del propio `.ovpn`. Mandar los
dos juntos por el mismo correo no protege de nada.

## Material sensible

`.gitignore` bloquea `*.crt`, `*.key`, `*.pem`, `*.ovpn`, `pki/`, `tls/`,
`*.db` y `config.yaml`. Si abres una incidencia, no pegues ninguno de esos
archivos ni la salida completa de `config.yaml`.

## Qué está probado y qué no

La mitad no privilegiada tiene 283 pruebas: parsers en los tres formatos,
validación de CN, login y bloqueo, segundo factor (incluidos los vectores de
la RFC 6238, la reutilización de códigos, el QR y la política), permisos por
rol, CSRF, cabeceras de seguridad y auditoría.

Del QR se comprueba lo comprobable sin un móvil: que el SVG es válido y
autocontenido, que cabe el nombre de usuario más largo que admite el panel
(64 caracteres → versión 10), que llega a la página con texto alternativo y
que desaparece al confirmar el alta. **Que escanee de verdad hay que probarlo
con un teléfono.**

De la mitad privilegiada solo se comprueba lo que es comprobable sin root:
sintaxis del helper y del instalador, la regla de sudo con `visudo -c`, los
invariantes de arriba y los finales de línea. **El comportamiento real —
revocar, restaurar, emitir— solo se ejercita en un Debian de verdad.** Pruébalo
en una VM antes que en el servidor bueno; el helper hace copia de la PKI con
marca de tiempo antes de tocarla, pero eso no sustituye a una VM.
