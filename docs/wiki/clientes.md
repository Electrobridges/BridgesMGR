# 👤 Clientes VPN

[← Wiki](README.md)

Un *cliente VPN* es un certificado: una persona, un portátil o un router que
se conecta. No confundir con las cuentas del panel.

<img src="../capturas/clientes.png" alt="Página de clientes VPN: formulario de crear cliente con caducidad y contraseña, la duración máxima de sesión para todos y la tabla con ana y luis conectados; ana lleva las etiquetas de sus políticas" width="900">

## Crear un cliente

1. **Clientes VPN → Crear cliente.** El nombre es el *Common Name* del
   certificado: letras, números, `-` y `_`. Usa algo que identifique el equipo
   o la persona (`ana-portatil`, `router-almacen`).
2. **Caduca** (opcional): fecha y hora a partir de la cual deja de poder entrar.
   Al llegar, quien esté dentro es desconectado y el certificado se revoca
   solo. Ideal para proveedores y accesos puntuales.
3. **Cifrar la clave privada con contraseña** (marcado por defecto): el `.ovpn`
   por sí solo no sirve, hace falta la contraseña al conectar. Desmárcalo solo
   para equipos desatendidos que tengan que reconectar solos.
4. **Crear y emitir certificado.**

> [!WARNING]
> La contraseña del certificado **no se puede recuperar**. Si se pierde, hay
> que revocar y emitir uno nuevo. Dásela a la persona por una vía distinta del
> propio `.ovpn`.

## Entregar el perfil

**Descargar .ovpn** baja el perfil completo, con certificados y claves dentro:
un solo archivo que se importa en OpenVPN Connect, el cliente de OpenVPN de
Windows/macOS/Linux o Tunnelblick.

Trátalo como una llave: quien lo tenga entra (con la contraseña, si la lleva).
Mándalo por un canal que no se quede guardado para siempre.

## La columna *Acceso*

Resume cada cliente: el tráfico del mes y una etiqueta por política activa
(caducidad, horario, sesión máxima, cuota, IP fija, destinos). Si el
certificado caduca en menos de 30 días, también lo dice. El enlace
**Políticas** abre su página de [políticas](politicas.md).

## Desconectar a alguien

**Desconectar** corta su sesión al momento por la interfaz de management de
OpenVPN.

> [!CAUTION]
> Desconectar **no impide que vuelva**: su cliente reconectará solo en unos
> segundos. Para que no vuelva, **Revocar**, o quítale el acceso con una
> [política](politicas.md) (por ejemplo, una caducidad ya pasada).

## Revocar y restaurar

**Revocar** invalida el certificado: el panel regenera la CRL y OpenVPN lo
rechaza en la siguiente conexión. Si estaba conectado, se le expulsa.

Un revocado aparece en la tabla con **Restaurar**, que vuelve a emitirle
certificado con el mismo nombre. Su `.ovpn` antiguo **no** vuelve a valer: hay
que descargarle uno nuevo.

Un acceso temporal ya vencido no se resucita restaurando: el panel pide antes
cambiar o vaciar su fecha de caducidad en las políticas.

## Sesión máxima para todos

Debajo del formulario de alta, **Duración máxima de sesión** fija cuántos
minutos puede durar una conexión antes de que se le obligue a volver a entrar.
Vale para todos los clientes que no tengan una propia en sus políticas.

---

[← Primeros pasos](primeros-pasos.md) · Siguiente: [⏱️ Políticas de acceso →](politicas.md)
