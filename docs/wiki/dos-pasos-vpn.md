# 📱 Dos pasos en la VPN

[English](../en/wiki/vpn-2fa.md) · **Español**

[← Wiki](README.md)

Además del certificado, el servidor pide al conectar el código de 6 dígitos de
una app como Google Authenticator, Aegis o Microsoft Authenticator. Un `.ovpn`
robado deja de bastar: hace falta también el móvil de su dueño.

Se activa **cliente a cliente**: los que no lo tienen siguen entrando solo con
su certificado, así que puedes empezar por los portátiles que salen de la
oficina y dejar los routers como están.

## Activarlo

1. **Clientes VPN → Políticas** del cliente → **Verificación en dos pasos →
   Activar**.
2. Aparece un QR y la clave en texto. **Solo se enseñan esta vez**: que la
   persona la escanee en ese momento, o pásale la clave por un canal seguro.
3. **Descárgale un `.ovpn` nuevo.** El anterior no pide el código y, sin él, no
   podrá entrar.

> [!NOTE]
> Si el servidor aún no puede pedir el código, la sección lo dice y enseña las
> líneas que faltan en el `server.conf`. Los servidores montados con
> `deploy/instalar-openvpn.sh` ya las traen.

## Qué hace la persona al conectar

Su cliente OpenVPN le pedirá **usuario y contraseña**:

| Campo | Qué poner |
|---|---|
| Usuario | Da igual; lo natural es su nombre de cliente |
| Contraseña | **El código de 6 dígitos** que marca la app en ese momento |

Si su certificado lleva contraseña, se la pedirá también, aparte.

El código se pide **al conectar**, no en cada renovación de claves: una sesión
larga no le pregunta cada hora. Un código ya usado no vale dos veces.

## Si pierde el móvil o cambia de teléfono

**Generar clave nueva** invalida la anterior y enseña un QR nuevo. El `.ovpn`
que ya tenía sigue valiendo, porque lo que cambia es la clave, no el perfil.

**Quitar** le devuelve a entrar solo con el certificado.

## Si nadie consigue entrar

Casi siempre es la hora: el código depende del reloj, y un servidor o un móvil
con la hora desfasada da códigos que no coinciden. Comprueba
`timedatectl` en el servidor. Más casos en
[Solución de problemas](../solucion-problemas.md#el-código-de-dos-pasos-siempre-sale-mal).

---

[← Políticas de acceso](politicas.md) · Siguiente: [🛡️ Seguridad del servidor →](seguridad.md)
