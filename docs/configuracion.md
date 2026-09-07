# Configuración

Todo vive en `/etc/ovpn-web/config.yaml`, propiedad de `root:ovpnweb` con modo
`0640`. La plantilla comentada es
[deploy/config.ejemplo.yaml](../deploy/config.ejemplo.yaml).

Lo leen **dos procesos con privilegios distintos**: el panel (como `ovpnweb`) y
el helper (como root). Por eso el archivo pertenece a root y `ovpnweb` solo
puede leerlo: es lo que impide que un panel comprometido reescriba las rutas
que el helper va a usar como root.

Tras cualquier cambio: `sudo systemctl restart ovpn-web`.

> Una clave mal escrita **no** se ignora: la carga falla con
> `Claves desconocidas en 'openvpn': satus_path` y el servicio no arranca. Es
> a propósito — una errata que se cuela como valor por defecto es un fallo que
> aparece semanas después.

## `servidor`

| Clave | Por defecto | Qué es |
|---|---|---|
| `host_bind` | `127.0.0.1` | IP en la que escucha el panel. Ponla en la IP de la LAN. **No uses `0.0.0.0`** si la máquina tiene una pata en internet |
| `puerto` | `55443` | Puerto HTTPS del panel |
| `tls_cert` | `/etc/ovpn-web/tls/cert.pem` | Certificado del panel (lo genera el instalador) |
| `tls_key` | `/etc/ovpn-web/tls/key.pem` | Clave privada del certificado |

## `openvpn`

| Clave | Por defecto | Qué es |
|---|---|---|
| `log_path` | `/var/log/openvpn/openvpn.log` | Log que muestra el visor. Debe coincidir con tu `log-append` |
| `status_path` | `/var/log/openvpn/status.log` | Debe coincidir con la línea `status` de tu `server.conf`. Si pusiste `status /var/log/openvpn/status.log`, va **sin** el prefijo `openvpn-` |
| `mgmt_host` | `127.0.0.1` | Management interface. Literal `127.0.0.1`: `localhost` puede resolver a IPv6 |
| `mgmt_port` | `7505` | Puerto del management |
| `easyrsa_path` | `/etc/openvpn/easy-rsa` | Directorio de EasyRSA; dentro está `pki/` |
| `servicio` | `openvpn@server` | Unidad de systemd que se consulta para el estado |

## `cliente_ovpn`

Datos con los que se arma el `.ovpn` que se descarga desde el panel.

| Clave | Por defecto | Qué es |
|---|---|---|
| `remote_host` | *(vacío)* | Dirección por la que los clientes llegan a la VPN **desde fuera**: la IP pública o el dominio dinámico. **No es la IP del panel** — es el error más habitual |
| `remote_puerto` | `1194` | Puerto de la VPN |
| `proto` | `udp` | `udp` o `tcp`, igual que en `server.conf` |
| `cipher` | `AES-256-CBC` | Debe coincidir con el servidor |
| `tls_crypt` | `/etc/openvpn/tls-crypt.key` | Ruta a la clave `tls-crypt` para embeberla en el perfil. Déjalo vacío si no usas tls-crypt |
| `dns` | *(lista vacía)* | Servidores DNS a empujar al cliente, p. ej. `["1.1.1.1", "9.9.9.9"]` |

## `seguridad`

| Clave | Por defecto | Qué es |
|---|---|---|
| `helper` | `/usr/local/sbin/ovpn-web-helper` | Ruta del helper privilegiado. Debe coincidir **exactamente** con la de `/etc/sudoers.d/ovpnweb` |
| `usar_sudo` | `true` | Invocar el helper por sudo. Solo se pone en `false` para pruebas fuera del servidor |
| `db_path` | `/var/lib/ovpn-web/ovpn-web.db` | SQLite con cuentas, sesiones y auditoría |
| `respaldos_dir` | *(vacío)* | Dónde se guardan las copias de la base. Vacío = `<dir de db_path>/respaldos`. Va aquí y no en el panel para que quien lo comprometa no pueda mandar copias de la base a una ruta suya; si lo cambias, añade la ruta al `ReadWritePaths` de la unidad |
| `duracion_sesion_min` | `60` | Minutos de validez de una sesión |
| `max_intentos_login` | `5` | Intentos fallidos antes de bloquear |
| `bloqueo_login_min` | `15` | Minutos de bloqueo. Se cuenta por usuario **+ IP**, para que un tercero no pueda dejar fuera al admin |
| `cookie_segura` | `true` | Marca `Secure` en la cookie de sesión. Solo desactívalo si sirves el panel por HTTP plano, que no se recomienda |

## Configuración para desarrollo

En local no hay `/etc/ovpn-web/`, así que se usa la variable de entorno:

```bash
cp deploy/config.ejemplo.yaml config.local.yaml   # y ajústalo
OVPN_WEB_CONFIG=config.local.yaml python -m app.servidor
```

El orden de búsqueda es: argumento explícito → `OVPN_WEB_CONFIG` →
`/etc/ovpn-web/config.yaml`.

`config.yaml` y `config.local.yaml` están en `.gitignore`: contienen las rutas
y direcciones reales de tu servidor.
