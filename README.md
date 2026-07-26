# OpenVPN Manager Web

Panel web para administrar un servidor OpenVPN desde el navegador. Se instala
en el propio servidor VPN y se accede por su IP de la red local, por ejemplo
`https://192.168.1.192:55443`.

![Licencia](https://img.shields.io/badge/licencia-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![Plataforma](https://img.shields.io/badge/plataforma-Linux-lightgrey.svg)

Es la versión web de [OpenVPN-Manager-CLI](https://github.com/Electrobridges/OpenVPN-Manager-CLI),
del que hereda el núcleo de parseo y comunicación con OpenVPN.

## Qué hace

- **Panel de estado**: clientes conectados, tráfico, certificados y estado del servicio.
- **Conexiones en vivo**: tabla que se refresca sola, con IP real, IP virtual y tráfico.
- **Clientes VPN**: crear, revocar, restaurar y descargar el perfil `.ovpn` ya montado.
- **Expulsar clientes**: desconectar a alguien conectado en ese momento.
- **Logs**: visor con filtro de texto y coloreado por tipo de mensaje.
- **Usuarios del panel**: cuentas con rol `admin` (puede modificar) o `lector` (solo consulta).
- **Auditoría**: quién hizo qué, cuándo y desde qué IP, incluidos los logins fallidos.

## Modelo de seguridad

Es un panel que puede revocar certificados y expulsar usuarios de una VPN, así
que conviene entender cómo está montado antes de instalarlo.

| Decisión | Por qué |
|---|---|
| El servicio corre como `ovpnweb`, sin privilegios ni shell | Un fallo en la web no es root en el servidor VPN |
| Todo lo privilegiado pasa por `/usr/local/sbin/ovpn-web-helper` | Un único script cerrado, con seis subcomandos, fácil de auditar |
| `sudoers` autoriza **solo ese script**, nunca `easyrsa` | `easyrsa` acepta `--pki-dir` y `--vars`: autorizarlo con comodines equivale a dar root |
| El helper lee sus rutas de `config.yaml` (root:ovpnweb 0640), jamás de sus argumentos | Si aceptara rutas del panel, un panel comprometido escalaría a root |
| El Common Name se valida a ambos lados de la frontera | El helper no se fía del panel aunque el panel ya valide |
| Contraseñas con Argon2; en la base solo el SHA-256 del token de sesión | Robar el `.db` no da ni contraseñas ni sesiones |
| Cookie `httpOnly` + `SameSite=Strict` + cabecera `X-CSRF-Token` obligatoria | Dos barreras independientes contra CSRF |
| CSP estricta `'self'`, sin CDNs ni scripts inline | HTMX se sirve desde el propio servidor |
| Bloqueo tras N intentos, contado por usuario+IP | Frena la fuerza bruta sin que un tercero pueda dejar fuera al admin |
| HTTPS con certificado autofirmado | Las credenciales no viajan en claro por la LAN |

**No expongas este panel a internet.** Está pensado para la red local o para
llegar a él a través de la propia VPN.

## Requisitos

- Linux con systemd (Debian 11+, Ubuntu 20.04+ o similar)
- Python 3.9 o superior
- OpenVPN 2.4+ con management interface y archivo de status activados
- EasyRSA 3.x
- Acceso root para la instalación

En tu `server.conf` deben estar estas líneas:

```conf
management 127.0.0.1 7505
status /var/log/openvpn/status.log
status-version 3
log-append /var/log/openvpn/openvpn.log
crl-verify /etc/openvpn/easy-rsa/pki/crl.pem
```

> `status-version 3` importa: OpenVPN 2.5.x escribe ese formato separado por
> TAB, y es el que el panel entiende mejor. También lee el formato antiguo.

## Instalación

```bash
git clone https://github.com/Electrobridges/OpenVPN-Manager-Web.git
cd OpenVPN-Manager-Web
sudo bash deploy/install.sh
```

El instalador crea el usuario `ovpnweb`, instala la app en `/opt/ovpn-web`,
genera un certificado TLS autofirmado, coloca la regla de sudo y registra el
servicio. Es idempotente: puedes volver a lanzarlo para actualizar.

Después, **tres pasos obligatorios**:

```bash
# 1. Ajusta la configuración (al menos host_bind, status_path y remote_host)
sudo nano /etc/ovpn-web/config.yaml

# 2. Crea el primer administrador (no hay usuario por defecto)
cd /opt/ovpn-web
sudo -u ovpnweb venv/bin/python -m app.cli crear-usuario tu_usuario --rol admin

# 3. Arranca
sudo systemctl start ovpn-web
sudo systemctl status ovpn-web
```

Abre `https://TU_IP:55443`. El navegador avisará de que el certificado es
autofirmado: es lo esperado, acepta la excepción.

### Cuentas del panel

```bash
cd /opt/ovpn-web
sudo -u ovpnweb venv/bin/python -m app.cli listar-usuarios
sudo -u ovpnweb venv/bin/python -m app.cli crear-usuario soporte --rol lector
sudo -u ovpnweb venv/bin/python -m app.cli cambiar-password tu_usuario
```

Los roles: `admin` puede crear, revocar, restaurar, desconectar y descargar
perfiles; `lector` solo consulta.

## Configuración

Todo está en `/etc/ovpn-web/config.yaml` (ver [deploy/config.ejemplo.yaml](deploy/config.ejemplo.yaml)).
Los valores que casi siempre hay que tocar:

| Clave | Qué es |
|---|---|
| `servidor.host_bind` | IP de la LAN donde escucha el panel. No uses `0.0.0.0` si la máquina da a internet |
| `openvpn.status_path` | Debe coincidir con la línea `status` de tu `server.conf` |
| `cliente_ovpn.remote_host` | Dirección por la que los clientes llegan a la VPN desde fuera; **no** es la IP del panel |
| `cliente_ovpn.tls_crypt` | Ruta a la clave `tls-crypt`, para embeberla en los `.ovpn`. Vacío si no la usas |

Tras cambiarlo: `sudo systemctl restart ovpn-web`.

## Desarrollo

El núcleo (`app/core/`) no importa nada de FastAPI, así que se prueba sin
levantar la web:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

pytest                          # toda la suite
pytest tests/test_auth.py       # un archivo
pytest -k csrf                  # por nombre
```

Para levantar el panel en local necesitas un `config.yaml` propio:

```bash
cp deploy/config.ejemplo.yaml config.local.yaml   # y ajústalo
OVPN_WEB_CONFIG=config.local.yaml python -m app.servidor
```

Sin `htmx.min.js` (que descarga el instalador) las páginas cargan pero no se
refrescan solas.

## Solución de problemas

**"Management interface no disponible"**
El panel cae al archivo de status y lo dice en pantalla. Comprueba
`ss -tlnp | grep 7505` y que en `server.conf` ponga `management 127.0.0.1 7505`.
Usa `127.0.0.1`, no `localhost`: puede resolver a IPv6 y OpenVPN solo escucha IPv4.

**"No se pudo consultar la PKI"**
Prueba el helper a mano:
```bash
sudo -u ovpnweb sudo -n /usr/local/sbin/ovpn-web-helper listar
```

**"Sin permisos para leer el log"**
El usuario debe estar en el grupo `adm`: `sudo usermod -aG adm ovpnweb` y
reinicia el servicio.

**El servicio no arranca**
`sudo journalctl -u ovpn-web -n 50`. Casi siempre es una ruta mal puesta en
`config.yaml` o el certificado TLS ausente.

## Licencia

MIT. Ver [LICENSE](LICENSE).

## Autor

**Daniel Puentes** — [GitHub](https://github.com/Electrobridges)
