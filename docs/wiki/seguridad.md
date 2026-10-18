# 🛡️ Seguridad del servidor

[English](../en/wiki/security.md) · **Español**

[← Wiki](README.md)

La página **Seguridad** tiene dos pestañas: la revisión del `server.conf` y el
bloqueo de IPs.

<img src="../capturas/seguridad.png" alt="Página de seguridad: nota 96 sobre 100, cero críticos, cero avisos, dos sugerencias y nueve puntos bien; la primera sugerencia propone pasar a tls-crypt-v2 con el comando que lo hace" width="900">

## La auditoría del `server.conf`

El panel lee el `server.conf` y lo compara con las recomendaciones de
endurecimiento de OpenVPN: canal de control, cifrados, versión mínima de TLS,
CRL, sesiones duplicadas, compresión, privilegios, management expuesto y la
versión de OpenVPN contra fallos conocidos (CVE).

Cada hallazgo tiene un nivel y, salvo los que están bien, **la línea exacta que
lo arregla**:

| Nivel | Qué significa | Cuánto resta |
|---|---|---|
| `CRÍTICO` | Un fallo que se puede aprovechar hoy, o que rompe una función del panel | Mucho |
| `AVISO` | Debilita el servidor sin abrirlo del todo | Algo |
| `SUGERENCIA` | Mejora recomendable, sin urgencia | Poco |
| `BIEN` | Correcto, para que se vea qué se ha revisado | Nada |

> [!IMPORTANT]
> **El panel solo lee el `server.conf`, no lo escribe.** Quien pudiera
> escribirlo podría ejecutar código como root, así que los arreglos se aplican
> a mano, con `sudo`, y después se reinicia OpenVPN:
> ```bash
> sudo nano /etc/openvpn/server/server.conf
> sudo systemctl restart openvpn-server@server
> ```

## Pasar a tls-crypt-v2

Con `tls-crypt`, la clave que protege el canal de control es **la misma en
todos los `.ovpn`**: quien se haga con uno tiene la de todos. Con
`tls-crypt-v2` cada perfil lleva la suya, generada en cada descarga.

```bash
cd BridgesMGR
sudo bash deploy/migrar-tls-crypt-v2.sh
```

> [!CAUTION]
> Tras migrar, **nadie entra hasta que recibe un `.ovpn` nuevo**, y hacen falta
> clientes OpenVPN 2.6 o posteriores. Planifícalo: avisa, migra, y reparte los
> perfiles nuevos desde **Clientes VPN**. El script se niega a activarlo con un
> OpenVPN anterior a 2.6.14, por un fallo conocido (CVE-2025-2704).

## Bloqueo automático de IPs

Como fail2ban, pero con lo que el panel ya lee del log: una IP que acumula
intentos fallidos desde fuera —paquetes sin la clave tls-crypt, handshakes que
no terminan, certificados de otra CA— queda bloqueada en el cortafuegos durante
un tiempo. Se revisa cada cinco minutos.

Viene **apagado**. Al encenderlo, los valores por defecto son:

| Ajuste | Por defecto |
|---|---|
| Intentos fallidos | 10 |
| En una ventana de | 10 minutos |
| Bloqueo durante | 60 minutos |
| Nunca bloquear | `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |

**No cuentan** los certificados revocados ni los rechazos por política: son
clientes legítimos que reintentan solos, y si comparten la IP pública de una
oficina, bloquearla dejaría fuera a toda la oficina.

Abajo están **Bloquear a mano**, la lista de IPs bloqueadas ahora (con botón
para desbloquear) y el histórico de bloqueos. El bloqueo lo levanta el propio
núcleo al caducar, aunque el panel esté parado.

---

[← Dos pasos en la VPN](dos-pasos-vpn.md) · Siguiente: [📊 Vigilar la VPN →](vigilar.md)
