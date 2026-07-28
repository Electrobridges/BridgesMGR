# OpenVPN Manager Web

Panel web para administrar un servidor OpenVPN desde el navegador. Se instala
en el propio servidor VPN y se accede por su IP de la red local, por ejemplo
`https://192.168.1.192:55443`.

![Licencia](https://img.shields.io/badge/licencia-Apache%202.0-blue.svg)
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
- **Usuarios del panel**: jerarquía de tres roles — `superusuario` (la primera cuenta, intocable), `admin` (puede modificar) y `supervisor` (solo consulta).
- **Verificación en dos pasos**: TOTP con la app del móvil, opcional para quien manda y exigible al rol supervisor.
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
| Verificación en dos pasos (TOTP), opcional para quien manda y exigible al rol supervisor | Una contraseña robada no basta para revocar certificados |
| El `superusuario` es la primera cuenta creada y nadie más puede tocarla, ni siquiera su contraseña | Si un admin pudiera cambiársela, entraría con ella: sería superusuario en dos pasos |
| Cookie `httpOnly` + `SameSite=Strict` + cabecera `X-CSRF-Token` obligatoria | Dos barreras independientes contra CSRF |
| CSP estricta `'self'`, sin CDNs ni scripts inline | HTMX se sirve desde el propio servidor |
| Bloqueo tras N intentos, contado por usuario+IP | Frena la fuerza bruta sin que un tercero pueda dejar fuera al admin |
| HTTPS con certificado autofirmado | Las credenciales no viajan en claro por la LAN |

**No expongas este panel a internet.** Está pensado para la red local o para
llegar a él a través de la propia VPN.

El detalle completo, con las reglas que no se deben romper al modificar el
código, está en [docs/seguridad.md](docs/seguridad.md).

## Instalación rápida

Requiere Debian 11+ o Ubuntu 20.04+ y Python 3.9+. **OpenVPN no hace falta
tenerlo ya**: si no lo encuentra, el instalador se ofrece a montarlo —PKI,
`server.conf`, NAT y todo— y luego rellena la configuración del panel con lo
que haya decidido. Si ya tienes un servidor, no le toca ni una línea.

```bash
git clone https://github.com/Electrobridges/OpenVPN-Manager-Web.git
cd OpenVPN-Manager-Web
sudo bash deploy/install.sh
```

Después, **tres pasos obligatorios**:

```bash
# 1. Repasa la configuración (sobre todo cliente_ovpn.remote_host)
sudo nano /etc/ovpn-web/config.yaml

# 2. Crea la primera cuenta: será el superusuario (no hay usuario por defecto)
cd /opt/ovpn-web
sudo -u ovpnweb venv/bin/python -m app.cli crear-usuario tu_usuario --rol admin

# 3. Arranca
sudo systemctl start ovpn-web
```

Abre `https://TU_IP:55443`. El navegador avisará de que el certificado es
autofirmado: es lo esperado, acepta la excepción.

Los requisitos del `server.conf`, la actualización y la desinstalación están en
[docs/instalacion.md](docs/instalacion.md).

## Documentación

| | |
|---|---|
| [Instalación](docs/instalacion.md) | Requisitos, `server.conf`, instalar, actualizar y desinstalar |
| [Configuración](docs/configuracion.md) | Todas las claves de `config.yaml`, con sus valores por defecto |
| [Seguridad](docs/seguridad.md) | La frontera de privilegios y las reglas que la sostienen |
| [Arquitectura](docs/arquitectura.md) | Cómo está montado por dentro y por qué |
| [Solución de problemas](docs/solucion-problemas.md) | Los fallos habituales y cómo diagnosticarlos |
| [Contribuir](CONTRIBUTING.md) | Entorno de desarrollo, estilo y pruebas |
| [Cambios](CHANGELOG.md) | Registro de versiones |

## Desarrollo

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

pytest
```

La suite corre entera en Windows o Linux, sin OpenVPN instalado. Lo que **no**
se puede probar fuera de un servidor real es la mitad privilegiada: el helper,
el instalador, la regla de sudo y la unidad de systemd. Ver
[CONTRIBUTING.md](CONTRIBUTING.md).

## Licencia

**Apache License 2.0.** Ver [LICENSE](LICENSE) y [NOTICE](NOTICE).

Puedes usarlo, modificarlo y distribuirlo, incluso comercialmente. A cambio se
piden tres cosas: conservar los avisos de copyright y el contenido de `NOTICE`,
señalar los archivos que hayas cambiado, e incluir una copia de la licencia.

Dos cosas que conviene saber, y que la licencia MIT no cubre:

- **Patentes.** Quien contribuye concede expresamente los derechos de patente
  necesarios para usar su aportación. Si alguien demanda al proyecto por
  patentes, pierde esa concesión.
- **Marcas.** «BridgesMGR» y «Electrobridges» son marcas de Daniel Puentes. La
  sección 6 de la licencia **no concede derecho a usarlas**: un derivado puede
  reutilizar este código, pero no presentarse con este nombre ni con esta
  identidad visual.

Material de terceros incluido en el repositorio, con su propia licencia (el
detalle completo, en [NOTICE](NOTICE)):

| Qué | Dónde | Licencia |
| --- | --- | --- |
| Poppins | `app/static/fuentes/` | SIL Open Font License 1.1 |
| Material Design Icons (vía `react-icons/md`) | `app/templates/partials/fondo_marca.html` | Apache License 2.0 |

## Autor

**Daniel Puentes** — [GitHub](https://github.com/Electrobridges)
