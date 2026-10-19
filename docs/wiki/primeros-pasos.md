# 🚪 Primeros pasos

[English](../en/wiki/getting-started.md) · **Español**

[← Wiki](README.md)

## Entrar

Abre `https://IP_DEL_SERVIDOR:55443` desde la red local o desde la propia VPN.
La primera vez el navegador avisa de que el certificado es autofirmado: es lo
esperado, acepta la excepción.

<img src="../capturas/login.png" alt="Pantalla de entrada de BridgesMGR: usuario, contraseña y el escudo con llave sobre fondo navy" width="720">

La primera cuenta se crea desde el servidor, no desde la web (no hay usuario
por defecto):

```bash
cd /opt/ovpn-web
sudo -u ovpnweb venv/bin/python -m app.cli crear-usuario tu_usuario --rol admin
```

Esa primera cuenta es el **superusuario** de la instalación.

> [!NOTE]
> Tras cinco intentos fallidos desde la misma IP, esa cuenta queda bloqueada
> quince minutos **solo para esa IP**: un tercero no puede dejarte fuera a ti
> equivocándose a propósito.

## El menú

| Página | Qué hay |
|---|---|
| **Panel** | El estado de un vistazo y las gráficas de los últimos 30 días |
| **Conexiones** | Quién está conectado ahora, con su IP y su tráfico. Se refresca sola |
| **Clientes VPN** | Los certificados: crear, descargar, revocar, políticas |
| **Logs** | El log de OpenVPN, coloreado y con filtro |
| **Auditoría** | Qué se hizo en el panel y qué pasó en la VPN, guardado en la base |
| **Usuarios** | Las cuentas del panel |
| **Seguridad** | La revisión del `server.conf` y el bloqueo de IPs |
| **Configuración** | Avisos, retención del historial y lo que el panel lee de `config.yaml` |

Un `supervisor` no ve en el menú lo que no puede usar.

## Los tres roles

| Rol | Puede |
|---|---|
| `superusuario` | Todo, y nadie puede tocar su cuenta. Es la primera que se creó |
| `admin` | Todo lo de la VPN y gestionar las cuentas, incluidas las de otros admins; al superusuario no lo alcanza |
| `supervisor` | Mirar: panel, conexiones, clientes, logs y auditoría, sin un solo botón que cambie algo. No entra en *Usuarios* ni en *Configuración* |

Un `supervisor` es lo que le das a quien tiene que vigilar sin poder romper:
soporte, un auditor, un compañero de guardia.

<img src="../capturas/usuarios.png" alt="Página de usuarios del panel: formulario de nuevo usuario con el rol supervisor por defecto, la política de dos pasos para supervisores y la tabla de cuentas" width="720">

## Tu verificación en dos pasos

Pulsa **tu nombre, arriba a la derecha**, para abrir tu perfil. Desde ahí activas el 2FA de tu cuenta del
panel: escaneas un QR con Google Authenticator, Aegis o similar y confirmas con
un código. A partir de ahí, la contraseña sola no basta para entrar.

Es opcional para quien manda; en **Usuarios** se puede hacer obligatorio para
los `supervisor`.

> [!IMPORTANT]
> Esto protege **el panel**. Pedir un código a los clientes **de la VPN** es
> otra cosa, y se activa cliente a cliente: [Dos pasos en la VPN](dos-pasos-vpn.md).

---

Siguiente: [👤 Clientes VPN →](clientes.md)
