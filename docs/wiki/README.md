# Wiki de uso

Guía del día a día con BridgesMGR, ya instalado. Cada página es una tarea, en
el orden en que suele hacer falta. Para instalarlo, configurarlo o entender por
dentro cómo está montado, mira la [documentación técnica](../../README.md#-documentación).

| | Página | Para qué |
|---|---|---|
| 🚪 | [Primeros pasos](primeros-pasos.md) | Entrar, orientarse en el menú, los roles y tu propio 2FA |
| 👤 | [Clientes VPN](clientes.md) | Dar de alta, entregar el `.ovpn`, revocar, restaurar y desconectar |
| ⏱️ | [Políticas de acceso](politicas.md) | Accesos temporales, horarios, sesión máxima, cuotas, IP fija y destinos |
| 📱 | [Dos pasos en la VPN](dos-pasos-vpn.md) | Pedir un código del móvil además del certificado |
| 🛡️ | [Seguridad del servidor](seguridad.md) | La auditoría del `server.conf`, tls-crypt-v2 y el bloqueo de IPs |
| 📊 | [Vigilar la VPN](vigilar.md) | Gráficas, historial, avisos por correo o Discord y métricas para Prometheus |
| 🔧 | [Mantenimiento](mantenimiento.md) | Actualizar, respaldos y qué hacer cuando algo falla |

> [!TIP]
> Casi todo lo que se explica aquí lo dice también el propio panel, junto al
> botón que lo hace. La wiki sirve para tener el mapa completo antes de tocar.

## Recetas rápidas

| Quiero… | Dónde |
|---|---|
| Dar acceso a un proveedor solo hasta el viernes | [Clientes VPN](clientes.md#crear-un-cliente) → campo *Caduca* al crearlo |
| Que alguien solo entre en horario de oficina | [Políticas → Horario](politicas.md#horario) |
| Que un cliente solo llegue a un servidor concreto | [Políticas → IP fija y destinos](politicas.md#ip-fija-y-destinos) |
| Echar ahora mismo a alguien | [Clientes VPN → Desconectar](clientes.md#desconectar-a-alguien) |
| Que un `.ovpn` robado no baste para entrar | [Dos pasos en la VPN](dos-pasos-vpn.md) |
| Saber si el servidor está bien configurado | [Seguridad → Auditoría](seguridad.md#la-auditoría-del-serverconf) |
| Enterarme de un certificado que caduca | [Vigilar → Avisos](vigilar.md#avisos) |
| Recuperar el panel si he perdido el móvil | [Mantenimiento → Fuera del panel](mantenimiento.md#me-he-quedado-fuera-del-panel) |
