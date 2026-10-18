# 🔧 Mantenimiento

[English](../en/wiki/maintenance.md) · **Español**

[← Wiki](README.md)

## Actualizar

```bash
cd BridgesMGR
git pull
sudo bash deploy/install.sh
```

Se puede repetir siempre: conserva la base, la configuración y el certificado,
y si el panel estaba en marcha lo reinicia y comprueba que vuelve.

> [!NOTE]
> La versión nueva se prepara al lado y solo sustituye a la que corre si
> importa bien y le vale tu `config.yaml`. Si después no arranca, el instalador
> **vuelve solo a la anterior** y te enseña por qué. Todo queda en
> `/var/log/ovpn-web-instalacion.log`.

Si algo sale mal:

```bash
sudo less +G /var/log/ovpn-web-instalacion.log   # qué hizo el instalador
journalctl -u ovpn-web -n 50 --no-pager          # por qué no arranca el panel
```

El detalle, incluida la vuelta atrás a mano, en
[Instalación → Actualizar](../instalacion.md#actualizar).

## Comprobar el servidor

Revisa, sin tocar nada, que el servidor OpenVPN encaja con lo que espera el
panel: rutas, permisos, CRL, management, logs y scripts de políticas.

```bash
sudo bash deploy/comprobar-servidor.sh
```

Termina con un resumen de críticos y avisos, y cada línea dice qué hacer.

## Respaldos

En **Configuración → Respaldos de la base** se programa una copia diaria o
semanal, conservando las N últimas, en `/var/lib/ovpn-web/respaldos/`.

> [!WARNING]
> Los respaldos **no se descargan desde la web** a propósito: llevan los hashes
> de las contraseñas y los secretos de dos pasos. Se recogen por SSH. Y no
> incluyen la PKI (`/etc/openvpn/easy-rsa`) ni `config.yaml`: respáldalos
> aparte, son lo que de verdad no se puede regenerar.

Cómo restaurar uno: [Instalación → Restaurar](../instalacion.md#restaurar).

Para revisar la auditoría en una hoja de cálculo, **Configuración → Exportar**
baja un ZIP en CSV, sin ningún secreto.

## Me he quedado fuera del panel

| Qué pasa | Qué hacer |
|---|---|
| Muchos intentos fallidos | Espera 15 minutos o entra desde otra IP: el bloqueo es por usuario **+ IP** |
| Olvidé la contraseña | `sudo -u ovpnweb venv/bin/python -m app.cli cambiar-password tu_usuario` |
| Perdí el móvil del 2FA | Otro admin: **Usuarios → Restablecer 2FA**. Si no hay otro: `… app.cli totp-restablecer tu_usuario` |

Las órdenes se lanzan desde `/opt/ovpn-web`, en el propio servidor.

## Cuando algo no cuadra

| Síntoma | Dónde mirar |
|---|---|
| *Management interface no disponible* | [Solución de problemas](../solucion-problemas.md#management-interface-no-disponible) |
| Revoco un cliente y sigue entrando | [Solución de problemas](../solucion-problemas.md#revoco-un-cliente-y-sigue-conectándose) |
| El `.ovpn` descargado no conecta | [Solución de problemas](../solucion-problemas.md#el-ovpn-descargado-no-conecta) |
| Las políticas no echan a nadie | La página de políticas del cliente avisa si falta el script en el `server.conf`; ver [Políticas](politicas.md#cómo-se-aplican) |
| El historial no dice cuánto duró cada sesión | La unidad de OpenVPN arranca con `--suppress-timestamps`; `deploy/fechas-log.sh` lo corrige |

---

[← Vigilar la VPN](vigilar.md) · [Volver al inicio de la wiki](README.md)
