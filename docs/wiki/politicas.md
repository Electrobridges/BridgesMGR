# ⏱️ Políticas de acceso

[← Wiki](README.md)

Cada cliente tiene su página de políticas: **Clientes VPN → Políticas**, en la
fila del cliente. Todo es opcional; un campo vacío significa *sin límite*.
Rellena lo que necesites y pulsa **Guardar y aplicar**.

<img src="../capturas/politicas.png" alt="Políticas de ana: acceso temporal hasta el 31/12/2026 a las 18:00, horario de lunes a viernes de 08:00 a 19:00 y sábados de 09:00 a 13:00, y sesión máxima de 480 minutos" width="900">

## Cómo se aplican

No basta con mirar al conectar, así que el panel actúa en tres momentos:

| Cuándo | Quién | Qué hace |
|---|---|---|
| **Al conectar** | Un script que OpenVPN ejecuta en cada conexión | Rechaza a quien está fuera de horario, caducado o sin cuota, y le da su IP fija |
| **Durante la sesión** | El vigilante del panel, cada minuto | Expulsa a quien se ha quedado fuera (se cerró su franja, cumplió la sesión máxima, agotó la cuota) y revoca los accesos temporales vencidos |
| **En el tráfico** | El cortafuegos (nftables) | Limita a qué destinos llega un cliente con IP fija |

> [!IMPORTANT]
> Si la página avisa en rojo de que *las políticas no se aplican al conectar*,
> al `server.conf` le faltan las líneas del script. Sin ellas el vigilante
> expulsa, pero el cliente vuelve a entrar solo. La página dice exactamente qué
> añadir; los servidores montados con `deploy/instalar-openvpn.sh` ya las traen.

## Acceso temporal

**Caduca**: desde esa fecha y hora no puede conectar, quien esté dentro es
desconectado y **su certificado se revoca solo**. Es lo que quieres para un
proveedor, un técnico externo o un becario.

También se puede poner al crear el cliente, en el mismo formulario de alta.

## Horario

Hasta tres franjas, cada una con sus días y su hora de inicio y fin, **en la
hora del servidor**. Fuera de todas, no puede conectar; si está dentro cuando se
cierra su franja, se le desconecta.

- Para terminar a medianoche, pon `00:00` como hora de fin.
- Una franja que cruza la medianoche (22:00 → 06:00) se parte en dos:
  `22:00–00:00` y `00:00–06:00`.

## Duración máxima de sesión

En minutos. Al cumplirla se le desconecta y tiene que volver a entrar (y a
escribir la contraseña del certificado, si la lleva). Útil para que nadie deje
la VPN abierta días enteros.

Vacío usa el valor común de **Clientes VPN → Duración máxima de sesión**.

## Cuota de tráfico mensual

En GB, subida más bajada. La página enseña lo que lleva este mes con una barra
y una gráfica de sus últimos 30 días. Al agotarla se le desconecta y **no puede
volver hasta el día 1 del mes siguiente**, cuando el bloqueo se levanta solo.

Para levantarlo antes, sube la cuota o vacíala.

## IP fija y destinos

**IP fija**: el cliente recibe siempre la misma dirección dentro de la VPN. La
página dice qué rango queda libre para IP fijas; si el pool dinámico ocupa toda
la red, explica cómo recortarlo.

**Destinos permitidos**: uno por línea.

```text
192.168.1.0/24          una red entera
192.168.1.10            un equipo
192.168.1.10:443/tcp    un solo servicio
```

Si pones alguno, el cliente llega **solo** a esos, también en lo que respecta
al propio servidor VPN. Exige IP fija, porque es lo que identifica al cliente
en el cortafuegos.

> [!TIP]
> Receta para un proveedor que mantiene un solo equipo: **Caduca** el día que
> termina el contrato, **Horario** de oficina, **IP fija** y un único
> **destino**, `IP_DEL_EQUIPO:443/tcp`. Y, si quieres, [dos pasos](dos-pasos-vpn.md).

## Qué ve quien queda fuera

Su cliente OpenVPN no llega a conectar y reintenta. En **Auditoría → VPN →
Rechazos** queda registrado con el motivo (fuera de horario, caducado, cuota
agotada…), y en la página de políticas del cliente un aviso amarillo dice si
ahora mismo podría entrar.

---

[← Clientes VPN](clientes.md) · Siguiente: [📱 Dos pasos en la VPN →](dos-pasos-vpn.md)
