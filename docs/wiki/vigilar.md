# 📊 Vigilar la VPN

[← Wiki](README.md)

## El panel

<img src="../capturas/panel.png" alt="Panel principal: dos conectados, dos certificados activos, servicio activo y el tráfico de las sesiones abiertas; debajo, las gráficas de tráfico por día, el ranking de tráfico del mes por cliente y las conexiones aceptadas y rechazadas por día" width="900">

Arriba, el estado de ahora: conectados, certificados, servicio y el tráfico de
las sesiones abiertas. Debajo, **los últimos 30 días**:

| Gráfica | Para qué sirve |
|---|---|
| **Tráfico por día** | Bajada y subida apiladas. Un pico raro de subida merece una mirada |
| **Quién más tráfico lleva este mes** | El ranking que conviene ver antes de poner [cuotas](politicas.md#cuota-de-tráfico-mensual) |
| **Conexiones por día** | El ritmo normal de la semana |
| **Conexiones rechazadas por día** | Un pico suele ser un escaneo, o un `.ovpn` revocado que sigue reintentando |

Pasa el ratón por una columna para ver sus valores; **Ver los datos** despliega
la misma información en tabla.

## Conexiones en vivo

<img src="../capturas/conexiones.png" alt="Conexiones activas: luis y ana conectados, con su IP real, su IP virtual, el tráfico de bajada y subida y el tiempo conectado" width="900">

Se refresca sola cada 10 segundos. Desde **Clientes VPN** se puede desconectar
a cualquiera de los que aparecen aquí.

## Historial

**Auditoría** tiene dos pestañas:

- **Panel web**: quién hizo qué en el panel, cuándo y desde qué IP, incluidos
  los logins fallidos.
- **VPN**: quién entró, cuándo salió, cuánto duró la sesión, quién fue
  rechazado y por qué, y las sesiones desplazadas por otra conexión del mismo
  perfil. Se lee del log de OpenVPN y **se guarda en la base**, así que no se
  pierde cuando logrotate vacía el archivo.

> [!TIP]
> Si un perfil aparece una y otra vez como *sesión desplazada* alternando entre
> dos IP, el panel avisa: es la firma de un `.ovpn` que están usando dos
> personas a la vez.

## Avisos

En **Configuración → Notificaciones** eliges canal y qué avisar:

| Categoría | Ejemplos |
|---|---|
| Seguridad del panel | Logins fallidos, cambios en las cuentas, exportaciones y limpiezas de la base |
| Certificados y CA | Altas, revocaciones, descargas de `.ovpn`, expulsiones por política, cuotas agotadas, perfiles compartidos y certificados que caducan (a 30, 14, 7, 3 y 1 días) |
| Salud del servicio | OpenVPN caído y de vuelta, CRL a punto de caducar, respaldos que fallan |
| Rechazos de conexión a la VPN | IPs bloqueadas y desbloqueadas |

Los canales (correo SMTP y webhook de Discord) se configuran en
`/etc/ovpn-web/config.yaml`, que el panel puede leer pero no escribir: así,
quien lo comprometa no puede desviar las alertas a su propio buzón. Por defecto
no se avisa de nada; se enciende a mano.

> [!NOTE]
> Una CA que caduca deja fuera **a todos** los clientes a la vez, así que su
> aviso va siempre como grave.

## Métricas para Prometheus

`/metrics` expone el estado en el formato de Prometheus: servicio, conectados,
tráfico por sesión y por mes, caducidades de certificados y de la CRL, rechazos
de las últimas 24 h e IPs bloqueadas. Viene apagado; para encenderlo:

```bash
openssl rand -hex 32        # genera el token
sudo nano /etc/ovpn-web/config.yaml
# seguridad:
#   metricas_token: "el-token-generado"
sudo systemctl restart ovpn-web
```

Y en Prometheus:

```yaml
scrape_configs:
  - job_name: bridgesmgr
    scheme: https
    tls_config:
      insecure_skip_verify: true   # el certificado del panel es autofirmado
    authorization:
      credentials: "el-token-generado"
    static_configs:
      - targets: ["192.168.1.192:55443"]
```

---

[← Seguridad del servidor](seguridad.md) · Siguiente: [🔧 Mantenimiento →](mantenimiento.md)
