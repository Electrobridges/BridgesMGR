# Instalación

## Requisitos

- Debian 11+ o Ubuntu 20.04+ (con systemd y `apt`)
- Python 3.9 o superior
- Acceso root para la instalación

OpenVPN **no** es un requisito previo: si no lo tienes, el instalador se ofrece
a montarlo. Si ya lo tienes, no lo toca.

## Instalar

```bash
git clone https://github.com/Electrobridges/BridgesMGR.git
cd BridgesMGR
sudo bash deploy/install.sh
```

Lo primero que hace es mirar si hay un servidor OpenVPN montado. Si no lo hay,
pregunta si montarlo y llama a [`deploy/instalar-openvpn.sh`](#montar-el-servidor-openvpn).
Todas las preguntas caen ahí, al principio, y no a los cinco minutos.

Después, y esto no ha cambiado:

1. Instala las dependencias del sistema (`python3-venv`, `openssl`, `curl`…).
2. Crea el usuario de sistema `ovpnweb`, sin shell ni directorio propio, y lo
   añade al grupo `adm` para que pueda leer los logs de OpenVPN.
3. Copia la aplicación a `/opt/ovpn-web` y crea su entorno virtual.
4. Instala el helper privilegiado en `/usr/local/sbin/ovpn-web-helper` (0750,
   root:root).
5. Descarga HTMX y **verifica su SHA-256** contra `deploy/htmx.sha256`, que va
   versionado en el repositorio. Si no coincide, aborta. Y si el archivo falta,
   **también aborta**: HTMX se sirve desde el propio panel, así que la CSP lo da
   por bueno y un archivo manipulado sería JavaScript corriendo con la sesión
   del administrador. Aceptar lo que devuelva un CDN sin comparar no es una
   opción por defecto; para subir de versión a conciencia está `--htmx-confiar`.
6. Coloca la configuración de ejemplo en `/etc/ovpn-web/config.yaml`
   (root:ovpnweb 0640) si no existe ya. Si existe, **no la pisa**. Y si acaba
   de montar la VPN, la rellena con lo que ese script decidió, en vez de
   pedirte que lo copies de una pantalla a un archivo.
7. Genera un certificado TLS autofirmado para la IP de la LAN, a 10 años.
8. Valida la regla de sudo con `visudo -c` antes de instalarla, y registra el
   servicio en systemd.

Opciones:

| Opción | Para qué |
|---|---|
| `--sin-openvpn` | No ofrecer montar nada. Ya tienes servidor, o lo harás aparte |
| `--con-openvpn` | Montarlo sin preguntar |
| `--salida lan\|todo` | Se le pasa tal cual a `instalar-openvpn.sh` |
| `--host <destino>` | Idem: por dónde llegan los clientes a la VPN |
| `--si` | No preguntar nada (instalación desatendida) |

## Montar el servidor OpenVPN

```bash
sudo bash deploy/instalar-openvpn.sh --salida lan --host vpn.ejemplo.com
```

Se puede lanzar suelto, y es idempotente: si encuentra una PKI la conserva, y
si encuentra un `server.conf` **no lo toca** y te dice qué necesita el panel.

Pregunta lo único que no puede adivinar —qué debe alcanzar un cliente— y
detecta el resto: interfaz de salida, red local e IP pública. Enseña un resumen
y espera confirmación antes de tocar nada.

### Qué deja montado

| | |
|---|---|
| PKI | `/etc/openvpn/easy-rsa`, curva elíptica `secp384r1` |
| Configuración | `/etc/openvpn/server/server.conf` |
| Clave `tls-crypt` | `/etc/openvpn/tls-crypt.key` |
| Estado | `/var/log/openvpn/status.log`, formato v3 |
| Log | `/var/log/openvpn/openvpn.log` |
| Management | `127.0.0.1:7505` |
| Unidad | `openvpn-server@server` |

Usa curva elíptica en vez de RSA por dos motivos: evita generar los parámetros
Diffie-Hellman, que son los minutos que se lleva una instalación de OpenVPN, y
la clave resultante es más fuerte. Necesita OpenVPN 2.4 o superior, de 2018.

### Los dos alcances

- **`--salida lan`** (túnel dividido): se le empuja al cliente la ruta de la red
  local del servidor y nada más. Su tráfico a internet sigue saliendo por su
  propia conexión. Es el caso de «entrar a la oficina desde fuera».
- **`--salida todo`** (túnel completo): `redirect-gateway`, el cliente sale a
  internet por el servidor, y se le empujan DNS. Convierte al servidor en la
  salida de todos.

### Lo que le hace a la red del servidor

Sin esto la VPN levanta y los clientes conectan, pero no encaminan a ningún
sitio, así que va por defecto. Con `--sin-red` no se toca nada y el script deja
los comandos exactos por pantalla.

- Activa el reenvío IP en `/etc/sysctl.d/99-ovpn-web-forward.conf`.
- Instala una regla de NAT en su **propia tabla de nftables** (`ip ovpnweb`),
  cargada por la unidad `ovpn-web-nat.service`. Tabla aparte a propósito:
  se ve de quién es, y quitarla no se lleva por delante las reglas de nadie.
- Si `ufw` está activo, le añade el puerto y el reenvío en su idioma. El NAT y
  el filtrado del reenvío cuelgan de enganches distintos, así que la tabla de
  arriba no basta cuando hay ufw de por medio.

### Otras opciones

| Opción | Por defecto |
|---|---|
| `--puerto <n>` | `1194` |
| `--proto udp\|tcp` | `udp` |
| `--red <CIDR>` | `10.8.0.0/24` |
| `--iface <nombre>` | Se detecta de la ruta por defecto |
| `--red-lan <CIDR>` | Se detecta de la interfaz de salida |
| `--dns <a> <b>` | `9.9.9.9`, `149.112.112.112` |
| `--sin-arrancar` | Deja todo escrito sin habilitar la unidad |

## Si ya tenías un servidor OpenVPN

El instalador lo respeta y no cambia ni una línea. A cambio hay que ajustar
varias cosas a mano, y para no ir a ciegas está el comprobador:

```bash
sudo bash deploy/comprobar-servidor.sh
```

**Solo lee**: no instala, no escribe y no reinicia nada, así que se puede lanzar
en producción con clientes conectados. Contrasta tu `server.conf` con lo que
dice `/etc/ovpn-web/config.yaml`, ordena los hallazgos en críticos y avisos, y
da el comando exacto para arreglar cada uno. `install.sh` lo llama solo cuando
detecta que tu OpenVPN ya existía.

Dos de sus comprobaciones existen porque son las que fallan sin decir nada:

- **Que el usuario al que OpenVPN suelta privilegios pueda leer de verdad la
  CRL.** No lo deduce de los permisos: lo intenta. El directorio que la contiene
  también tiene que dejarse atravesar, y ese detalle se escapa mirando solo el
  modo del archivo.
- **Que la CRL no esté caducada.** Una CRL vencida hace que OpenVPN rechace
  *todas* las conexiones, no solo las revocadas, y el síntoma no apunta a la CRL
  por ninguna parte.

El `server.conf` que ya tienes debe llevar esto, o el panel no verá nada:

```conf
management 127.0.0.1 7505
status /var/log/openvpn/status.log
status-version 3
log-append /var/log/openvpn/openvpn.log
crl-verify /etc/openvpn/easy-rsa/pki/crl.pem
```

Detalles que importan:

- **`status-version 3`**: OpenVPN 2.5.x escribe ese formato separado por TAB y
  es el que el panel entiende mejor. También lee el formato antiguo (v1), pero
  con v3 obtienes la IP real y la virtual por separado sin ambigüedades.
- **`management 127.0.0.1`**, no `localhost`: puede resolver a IPv6 y el
  management de OpenVPN solo escucha en IPv4.
- **`crl-verify`** es lo que hace que revocar sirva de algo. Sin esa línea,
  revocar un certificado no impide que el cliente siga conectándose.

Y en `/etc/ovpn-web/config.yaml` hay que ajustar las rutas a las tuyas, sobre
todo `openvpn.servicio`: en Debian conviven dos nombres de unidad que no son
intercambiables —`openvpn-server@server` lee `/etc/openvpn/server/server.conf`
y `openvpn@server` lee `/etc/openvpn/server.conf`—. Comprueba cuál tienes con
`systemctl list-units 'openvpn*'`.

Tras tocar el `server.conf`: `sudo systemctl restart openvpn-server@server`.

## Los tres pasos que faltan

El instalador deja el servicio registrado pero **parado**, y sin ninguna cuenta
creada. Es deliberado: un panel que arranca solo con un usuario por defecto es
un panel comprometido esperando a que alguien lo encuentre.

```bash
# 1. Repasa la configuración
sudo nano /etc/ovpn-web/config.yaml
```

Si el instalador montó la VPN, esto ya viene relleno y basta con repasarlo —
sobre todo `cliente_ovpn.remote_host`, que es por donde llegarán los clientes
y solo se detecta bien si la máquina tiene salida a internet.

Si el servidor OpenVPN ya existía, hay que revisar como mínimo
`servidor.host_bind`, `openvpn.status_path`, `openvpn.servicio` y
`cliente_ovpn.remote_host`. Ver [configuracion.md](configuracion.md).

```bash
# 2. Crea la primera cuenta: será el superusuario de la instalación
cd /opt/ovpn-web
sudo -u ovpnweb venv/bin/python -m app.cli crear-usuario tu_usuario --rol admin

# 3. Arranca
sudo systemctl start ovpn-web
sudo systemctl status ovpn-web
```

Abre `https://TU_IP:55443`. El navegador avisará de que el certificado es
autofirmado: es lo esperado, acepta la excepción.

## Cuentas del panel

```bash
cd /opt/ovpn-web
sudo -u ovpnweb venv/bin/python -m app.cli listar-usuarios
sudo -u ovpnweb venv/bin/python -m app.cli crear-usuario soporte --rol supervisor
sudo -u ovpnweb venv/bin/python -m app.cli cambiar-password tu_usuario
```

Tres roles, en jerarquía:

| Rol | Qué puede |
|---|---|
| `superusuario` | Todo lo que un admin. Además es **intocable**: nadie puede cambiarle el rol, desactivarlo, borrarlo ni tocarle la contraseña o el segundo factor |
| `admin` | Crear, revocar, restaurar, desconectar, descargar perfiles y gestionar cuentas, incluidas las de otros admins |
| `supervisor` | Solo consulta: panel, conexiones, clientes, logs y auditoría. No entra en *Usuarios* ni en *Configuración* |

El superusuario **no se concede**: lo es la primera cuenta que se creó en la
instalación, se pidiera el rol que se pidiera. `--rol superusuario` no existe, y
desde el panel nadie puede dárselo ni quitárselo.

Trasladarlo sí se puede, pero solo desde el servidor:

```bash
sudo -u ovpnweb venv/bin/python -m app.cli designar-superusuario otra_cuenta
```

Pide confirmación, baja a admin al que lo era, cierra las sesiones de las dos
cuentas y queda auditado.

Nadie puede cambiarse el rol a sí mismo, superusuario incluido: quien se
degradara por error se quedaría fuera de la página donde arreglarlo.

### Verificación en dos pasos

Cada usuario la activa desde **Mi cuenta** (`/perfil`), con la aplicación de
autenticación del móvil. Para quien manda —superusuario y admins— es opcional;
a las cuentas de rol `supervisor` se les puede exigir desde *Usuarios* o desde
la CLI:

```bash
sudo -u ovpnweb venv/bin/python -m app.cli politica-totp              # consultar
sudo -u ovpnweb venv/bin/python -m app.cli politica-totp --exigir si

# Si alguien pierde el móvil y se queda fuera:
sudo -u ovpnweb venv/bin/python -m app.cli totp-restablecer tu_usuario
```

El detalle está en [seguridad.md](seguridad.md#verificación-en-dos-pasos-totp).

## Actualizar

```bash
cd BridgesMGR
git pull
sudo bash deploy/install.sh
sudo systemctl restart ovpn-web
```

Se conservan la base de datos (`/var/lib/ovpn-web/`), la configuración y el
certificado TLS.

## Respaldos de la base

El panel copia su base a `/var/lib/ovpn-web/respaldos/` con la API de respaldo
de SQLite, así que la copia es consistente aunque haya gente usando el panel.
El horario se programa en **Configuración → Respaldos de la base**: cada día o
cada semana, a la hora que elijas, conservando las N últimas. Lo comprueba el
vigilante cada cinco minutos, y si el panel estuvo parado a esa hora respalda
en cuanto vuelve.

**Los respaldos no se descargan desde la web, y no es un olvido.** Un respaldo
es la base entera: los hashes de todas las contraseñas y los secretos de
segundo factor. Vale tanto como el original, así que se queda en el servidor y
se recoge por SSH:

```bash
sudo cp /var/lib/ovpn-web/respaldos/ovpn-web-20260907-030000.db.gz /tmp/
sudo chown $USER /tmp/ovpn-web-*.db.gz
# y desde tu máquina:
scp servidor:/tmp/ovpn-web-20260907-030000.db.gz .
```

Para mirar la auditoría fuera del servidor está **Configuración → Exportar**,
que baja un ZIP con la auditoría y los perfiles archivados en CSV y **sin
ningún secreto**.

### Restaurar

```bash
sudo systemctl stop ovpn-web
sudo cp /var/lib/ovpn-web/ovpn-web.db /var/lib/ovpn-web/ovpn-web.db.antes-de-restaurar
sudo sh -c 'gunzip -c /var/lib/ovpn-web/respaldos/ovpn-web-20260907-030000.db.gz \
    > /var/lib/ovpn-web/ovpn-web.db'
sudo chown ovpnweb:ovpnweb /var/lib/ovpn-web/ovpn-web.db
sudo chmod 0600 /var/lib/ovpn-web/ovpn-web.db
sudo systemctl start ovpn-web
```

El `chown` no es opcional: el panel corre como `ovpnweb` y una base propiedad
de root no la puede ni abrir. Restaurar devuelve también las **cuentas y las
contraseñas** a como estaban ese día; las sesiones abiertas desde entonces
dejan de valer, que es lo correcto.

Lo que un respaldo **no** guarda: la PKI (`/etc/openvpn/easy-rsa`), la
configuración (`/etc/ovpn-web/config.yaml`) ni los certificados. Eso es de
root y el panel no lo alcanza; respáldalo aparte.

## Desinstalar

```bash
sudo systemctl disable --now ovpn-web
sudo rm /etc/systemd/system/ovpn-web.service /etc/sudoers.d/ovpnweb
sudo rm /usr/local/sbin/ovpn-web-helper
sudo systemctl daemon-reload
sudo rm -rf /opt/ovpn-web /etc/ovpn-web
sudo userdel ovpnweb
```

`/var/lib/ovpn-web` se deja aparte a propósito: contiene las cuentas del panel
y la auditoría. Bórralo solo cuando estés seguro.

Desinstalar el panel **no revierte nada en la PKI**: los certificados que
creaste o revocaste desde aquí siguen como estén.
