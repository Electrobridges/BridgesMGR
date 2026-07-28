# Política de seguridad

## Versiones con soporte

| Versión | Soporte |
|---|---|
| 0.1.x | Sí |

Mientras el proyecto esté en 0.x, solo la última versión recibe correcciones.

## Cómo informar de un fallo

**No abras una incidencia pública.** Escribe a **Contact@Electrobridges.com**
con:

- Qué has encontrado y qué permite hacer.
- Los pasos para reproducirlo.
- La versión o el commit del panel, y la distribución del servidor.

Se responde en cuanto sea posible. Si el fallo se confirma, se acuerda contigo
cuándo publicar el arreglo y se te acredita en el `CHANGELOG.md`, salvo que
prefieras lo contrario.

## Qué entra dentro del alcance

Cualquier cosa que rompa alguna de estas propiedades:

- Que el panel, corriendo como `ovpnweb`, pueda **escalar a root** por una vía
  distinta de los seis subcomandos previstos del helper.
- Que se pueda ejecutar una acción sin la sesión, el rol o el token CSRF que le
  corresponden.
- Que un Common Name manipulado escape de la validación y llegue a `easyrsa`,
  al sistema de archivos o al protocolo del management interface.
- Que se pueda leer una clave privada, un `.ovpn` o la base de datos sin ser
  admin.
- Que una mutación del servidor no quede registrada en la auditoría.

## Qué queda fuera

- **Exponer el panel a internet.** Está pensado para la LAN o para llegar a él
  por la propia VPN, y así se documenta.
- **El aviso del certificado autofirmado** en el navegador: es esperado.
- Que un usuario con rol `admin` pueda revocar certificados o descargar
  perfiles: es exactamente su función. El control ahí es la auditoría.
- Fallos de OpenVPN, EasyRSA o el sistema operativo. Repórtalos aguas arriba.

## Al desplegar

- No pongas `host_bind` en `0.0.0.0` si la máquina tiene una pata en internet.
- Deja `/etc/ovpn-web/config.yaml` como `root:ovpnweb 0640`. Si `ovpnweb`
  pudiera escribirlo, se cae la separación de privilegios entera.
- No amplíes `/etc/sudoers.d/ovpnweb`. En particular, no autorices `easyrsa`:
  acepta `--pki-dir` y `--vars`, así que hacerlo equivale a dar root.
- No actives `NoNewPrivileges` en la unidad de systemd: sudo es setuid y
  rompería la gestión de certificados.

El razonamiento completo está en [docs/seguridad.md](docs/seguridad.md).
