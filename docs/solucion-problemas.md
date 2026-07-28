# Solución de problemas

Regla general: el panel **no silencia errores**. Si algo falla, lo dice en
pantalla con el motivo. Empieza por leer el aviso, y sigue por:

```bash
sudo journalctl -u ovpn-web -n 50 --no-pager
```

## El servicio no arranca

Casi siempre es una de tres:

- **Una clave mal escrita en `config.yaml`.** La carga falla a propósito con
  `Claves desconocidas en 'openvpn': satus_path` en vez de tirar de valor por
  defecto. Corrige la clave.
- **Falta el certificado TLS.** `ls -l /etc/ovpn-web/tls/`. Si no está, vuelve
  a lanzar `sudo bash deploy/install.sh`.
- **Una ruta que no existe.** Comprueba `easyrsa_path` y `db_path`.

## "Management interface no disponible"

El panel cae al archivo de status y lo dice en pantalla; sigue funcionando pero
con menos detalle y sin poder expulsar clientes.

```bash
ss -tlnp | grep 7505
```

Si no escucha nadie, falta `management 127.0.0.1 7505` en tu `server.conf`.
Si escucha pero el panel no conecta, revisa que `mgmt_host` sea literalmente
`127.0.0.1`: `localhost` puede resolver a IPv6 y el management de OpenVPN solo
escucha en IPv4.

## "No se pudo consultar la PKI"

Prueba el helper a mano, tal como lo llama el panel:

```bash
sudo -u ovpnweb sudo -n /usr/local/sbin/ovpn-web-helper listar
```

| Lo que sale | Qué pasa |
|---|---|
| `sudo: a password is required` | No está la regla: `ls -l /etc/sudoers.d/ovpnweb` (debe ser root:root 0440) |
| `command not found` | El helper no está instalado, o `seguridad.helper` en `config.yaml` no coincide con la ruta del sudoers |
| `Falta python3-yaml` | `sudo apt install python3-yaml` — el helper corre con el Python del sistema, no con el venv |
| Un error de easyrsa | `easyrsa_path` apunta a un sitio equivocado, o la PKI no está inicializada |

## "Sin permisos para leer el log"

El usuario debe estar en el grupo `adm`, que en Debian es el dueño de
`/var/log`:

```bash
sudo usermod -aG adm ovpnweb
sudo systemctl restart ovpn-web
```

## Las tablas no se refrescan solas

Falta `htmx.min.js`. Las páginas cargan igual, pero sin actualización
automática ni avisos. Lo descarga el instalador:

```bash
ls -l /opt/ovpn-web/app/static/htmx.min.js
```

Si no está, vuelve a lanzar `install.sh`. Si el instalador aborta con *"El hash
de HTMX no coincide"*, no lo fuerces: significa que lo que sirve el CDN ha
cambiado respecto a `deploy/htmx.sha256`. Revisa por qué antes de continuar.

## Revoco un cliente y sigue conectándose

Dos causas, y suelen darse juntas:

1. **Falta `crl-verify` en el `server.conf`.** Sin esa línea OpenVPN no mira la
   lista de revocados. Añade
   `crl-verify /etc/openvpn/easy-rsa/pki/crl.pem` y reinicia OpenVPN.
2. **La sesión ya establecida no se corta sola.** Revocar impide reconectar,
   pero no expulsa. Usa el botón de desconectar desde *Conexiones*.

## El `.ovpn` descargado no conecta

- `cliente_ovpn.remote_host` es la dirección por la que se llega a la VPN
  **desde fuera** (IP pública o dominio dinámico), no la IP del panel. Es el
  error más frecuente.
- `proto` y `cipher` deben coincidir con el `server.conf`.
- Si el servidor usa `tls-crypt`, `cliente_ovpn.tls_crypt` debe apuntar a la
  clave para que se embeba en el perfil.

## El código de dos pasos siempre sale mal

Casi siempre es **la hora del móvil o la del servidor**. TOTP es un código
derivado del reloj: solo se toleran ±30 segundos de desfase.

```bash
timedatectl status          # ¿está sincronizado el servidor?
sudo timedatectl set-ntp true
```

En el móvil, activa la hora automática de red. En Google Authenticator hay
además *Ajustes → Corrección de hora para los códigos*.

Si el desfase no es el problema, comprueba que diste de alta la cuenta como
**basada en tiempo** (no en contador) y con 6 dígitos.

## Me he quedado fuera por perder el móvil

Cualquier admin puede quitarte el segundo factor desde *Usuarios* →
**Restablecer 2FA**. Si el que se ha quedado fuera es el único administrador,
hay que hacerlo desde el servidor:

```bash
cd /opt/ovpn-web
sudo -u ovpnweb venv/bin/python -m app.cli totp-restablecer tu_usuario
```

Entrarás solo con la contraseña hasta que vuelvas a activarlo. Queda auditado.

## Me he quedado fuera del panel

El bloqueo por intentos fallidos es temporal (`bloqueo_login_min`, 15 minutos
por defecto) y se cuenta por usuario **+ IP**, así que desde otra dirección
puedes entrar. Si has perdido la contraseña:

```bash
cd /opt/ovpn-web
sudo -u ovpnweb venv/bin/python -m app.cli cambiar-password tu_usuario
```

## Cómo pedir ayuda

Abre una incidencia con la salida de `journalctl -u ovpn-web -n 50`, tu versión
de OpenVPN y de Debian/Ubuntu, y las líneas relevantes de `config.yaml`.

**No pegues** certificados, claves, archivos `.ovpn` ni la configuración
completa con direcciones reales.
