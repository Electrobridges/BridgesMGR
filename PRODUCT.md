# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Equipos de IT pequeños que administran un servidor OpenVPN propio. Dos perfiles
confirmados, que el panel modela como una jerarquía de tres roles:

- **superusuario** — el mismo alcance que un admin, pero blindado: es la cuenta
  que montó la instalación y nadie más puede tocarla. Existe porque en un
  equipo pequeño el dueño del servidor y los administradores del día a día no
  son la misma persona, y quien monta la máquina no debería poder ser expulsado
  por alguien a quien él mismo dio acceso.
- **admin** — emite, revoca y restaura certificados de cliente, expulsa
  conexiones activas y descarga perfiles `.ovpn`. Es quien asume el riesgo:
  cada acción suya cambia quién puede entrar en la VPN.
- **supervisor** — consulta estado, conexiones, logs y auditoría sin poder
  mutar nada.

Trabajan desde un navegador de escritorio conectado a la red local. El acceso
móvil no es un escenario de uso confirmado: el responsive es cortesía, no
requisito.

La situación típica no es de exploración sino de intervención: alguien abre el
panel porque necesita saber quién está conectado, dar de alta a una persona
nueva o cortarle el acceso a alguien ya.

## Product Purpose

Administrar un servidor OpenVPN desde el navegador sin entrar por SSH ni
manejar EasyRSA a mano. El panel se instala en el propio servidor VPN y escucha
en su IP de LAN.

Tiene éxito cuando un operador resuelve una tarea de certificados o conexiones
sin abrir una terminal, y cuando cualquiera puede reconstruir después quién
hizo qué.

## Positioning

Es la versión web de [OpenVPN-Manager-CLI](https://github.com/Electrobridges/OpenVPN-Manager-CLI),
del que hereda el núcleo de parseo de status, el cliente del management
interface y las operaciones de EasyRSA.

Lo que un panel vecino no podría copiar sin rehacerlo entero es su **frontera
de privilegios**: el servicio corre como `ovpnweb`, sin privilegios ni shell, y
no puede escribir en la PKI ni leer claves privadas. Todo lo privilegiado pasa
por un único script cerrado, `ovpn-web-helper`, que es lo único que autoriza el
sudoers, que lee sus rutas de un config que el panel no puede escribir, y que
revalida el Common Name por su cuenta porque no se fía del panel. La respuesta
habitual —darle root al servicio web— es justamente lo que aquí se evita.

## Operating Context

- Se accede por HTTPS con certificado autofirmado, en una URL de LAN del tipo
  `https://192.168.1.192:55443`. El navegador avisa del certificado y se acepta
  la excepción: es lo esperado.
- **No se expone a internet.** Está pensado para la red local o para llegar a
  él a través de la propia VPN.
- Corre sobre Linux con systemd (Debian), Python 3.9+, OpenVPN 2.4+ con
  management interface y archivo de status activados, y EasyRSA 3.x.
- La instalación deja tres pasos manuales obligatorios: ajustar
  `/etc/ovpn-web/config.yaml`, crear el primer administrador por CLI y arrancar
  el servicio. No existe usuario por defecto.
- Las superficies del panel son: estado, conexiones en vivo, clientes VPN,
  logs, configuración, usuarios del panel y auditoría.

## Capabilities and Constraints

Funcionalidad confirmada:

- Panel de estado con clientes conectados, tráfico, certificados y estado del
  servicio.
- Tabla de conexiones que se refresca sola, con IP real, IP virtual y tráfico.
- Alta, revocación, restauración y descarga del perfil `.ovpn` ya montado.
- Expulsión de clientes conectados en ese momento.
- Visor de logs con filtro de texto y coloreado por tipo de mensaje.
- Gestión de cuentas del panel y registro de auditoría, con logins fallidos
  incluidos.

Restricciones técnicas que el diseño no puede negociar:

- **CSP estricta `script-src 'self'`**: sin CDNs, sin scripts inline y sin
  estilos inline. HTMX se sirve desde el propio servidor, descargado por el
  instalador con verificación de hash.
- Renderizado en servidor con Jinja2 + HTMX. No hay build de frontend, ni
  bundler, ni framework de componentes: son plantillas y una hoja de estilos.
- Las mutaciones exigen cabecera `X-CSRF-Token`; las acciones devuelven
  fragmentos HTML y emiten `HX-Trigger` para recargar las tablas afectadas.
- Python 3.9 es el suelo de compatibilidad.
- Contraseñas con Argon2; en la base solo el SHA-256 del token de sesión.
- Cookie `httpOnly` + `SameSite=Strict`, y bloqueo tras N intentos contado por
  usuario+IP.

## Brand Commitments

- Nombre: **OpenVPN Manager Web**. Autor: Daniel Puentes. Licencia Apache 2.0.
- **Todo en español**: textos de interfaz, documentación, docstrings,
  comentarios y mensajes de commit. Es una convención vinculante del proyecto,
  no una preferencia.
- Nomenclatura en español también en el código, salvo las claves de los dicts
  de conexión, que se mantienen en inglés (`user`, `bytes_recv`) por
  compatibilidad con el CLI.
- No hay logotipo ni identidad visual establecida más allá de la hoja de
  estilos existente.

## Evidence on Hand

- `README.md`, `CHANGELOG.md` y cinco documentos en `docs/`: instalación,
  configuración, seguridad, arquitectura y solución de problemas.
- La interfaz real: 13 plantillas en `app/templates/` y `app/static/estilo.css`.
- Suite de 114 pruebas que corre en Windows o Linux sin OpenVPN instalado.

Ausencias que el trabajo futuro **no debe rellenar inventando**: no hay
testimonios, clientes, casos de estudio, prensa, benchmarks, cifras de
adopción, precios ni planes. Tampoco hay capturas de pantalla publicadas.

## Product Principles

1. **La frontera de privilegios manda sobre la comodidad.** Ninguna mejora de
   interfaz puede exigir que el panel gane privilegios, ni relajar la CSP, ni
   mover trabajo privilegiado fuera del helper.
2. **Operar antes que impresionar.** Es una herramienta de trabajo para gente
   que llega con una tarea concreta: escaneabilidad, consistencia y densidad
   útil por encima de la expresión visual.
3. **Nada se silencia.** Si una vía falla, se dice cuál y por qué. Los errores
   son contenido de primera clase, no ruido que esconder; es la lección que
   costó cara en el CLI.
4. **Toda mutación deja rastro.** Lo que cambia el servidor se audita,
   incluidos los fallos, y la interfaz tiene que hacer esa trazabilidad
   visible y consultable.
5. **El idioma es parte del producto.** Todo lo que ve el usuario va en
   español, sin excepciones ni mezclas.
