# Arquitectura

```
app/core/       parsers, mgmt, conexiones, easyrsa, logs, validacion, totp  (sin FastAPI)
app/            config, db, auth, qr, main, servidor, cli
app/routers/    sesion, panel, clientes, administracion, perfil
app/templates/  base + 11 páginas + 7 parciales HTMX
app/static/     estilo.css, fuentes/  (htmx.min.js lo pone el instalador)
deploy/         helper privilegiado, systemd, sudoers, install.sh + instalar-openvpn.sh
tests/          283 pruebas
```

## El núcleo (`app/core/`)

No importa nada de FastAPI, a propósito: se prueba y se reutiliza sin levantar
la web. Está portado de [OpenVPN-Manager-CLI](https://github.com/Electrobridges/OpenVPN-Manager-CLI),
ya con las correcciones que allí costaron encontrar.

**`parsers.py`** — `_split_row()` divide por TAB si los hay y, si no, por coma.
No es capricho: OpenVPN 2.5.x escribe el status v3 separado por TAB, pero el
management interface puede devolver la misma información con comas.
`parse_status_text()` despacha entre v3 y v1 según aparezca `CLIENT_LIST`.

**`mgmt.py`** — envía `status 3` y acumula con `_leer_hasta_end()` hasta la
marca `END`. Un solo `recv()` trunca la respuesta en cuanto hay varios clientes
conectados; ese fue un bug real.

**`conexiones.py`** — **punto de entrada único**: `obtener_conexiones(cfg)`
devuelve `(conexiones, fuente, errores)`, donde `fuente` es `"management"`,
`"status"` o `None`. El fallback de una vía a otra vive aquí y solo aquí; no lo
reintroduzcas a mano en los routers. Y los errores se devuelven para mostrarlos
en pantalla, no para tragárselos.

**`easyrsa.py`** — cliente del helper: lo invoca por sudo y parsea el JSON.

**`validacion.py`** — la frontera de seguridad. Todo CN pasa por aquí antes de
tocar `subprocess` o el sistema de archivos.

**`totp.py`** — segundo factor (RFC 6238) con la biblioteca estándar. Está en
`core/` por lo mismo que el resto: se prueba sin levantar la web, y así se
contrasta directamente contra los vectores oficiales de la RFC.
`verificar()` devuelve el **paso** que coincidió y no un booleano, a propósito:
quien llama lo guarda para que un código no pueda usarse dos veces.

## La capa web

**`config.py`** — dataclasses cargadas de YAML que **rechazan claves
desconocidas**, para que una errata no pase inadvertida como valor por defecto.

**`db.py`** — SQLite con usuarios, sesiones, intentos de login, ajustes,
logins a medio hacer y auditoría. Una conexión por operación: los endpoints
corren en un pool de hilos y `sqlite3` no comparte conexión entre hilos.

Las columnas y tablas añadidas después de la primera versión están en
`COLUMNAS_NUEVAS` y las aplica `_migrar()` al arrancar: `CREATE TABLE IF NOT
EXISTS` no toca una tabla que ya existe, así que una instalación en marcha se
quedaría sin ellas. Se comprueba qué hay con `PRAGMA table_info` en vez de
capturar el error del `ALTER`, para no confundir un fallo real con "ya estaba".

El paso de dos roles a tres necesitó algo más que un `ALTER`: el rol lleva un
`CHECK` y SQLite no sabe alterarlo, así que `_migrar_roles()` **reconstruye la
tabla** siguiendo el procedimiento de la documentación —claves foráneas fuera,
tabla nueva, copia, intercambio, claves foráneas dentro— con una conexión
propia, porque `conexion()` las deja siempre activas y renombrar con ellas
puestas reescribiría las referencias de `sesiones` para que apuntaran a la
tabla temporal. Por eso `DDL_USUARIOS` está fuera de `ESQUEMA` y lleva el
nombre de tabla por parámetro: escribir esas columnas dos veces es justo cómo
acaban divergiendo. Traduce `lector` a `supervisor` y asciende al **admin más
antiguo** —no a la cuenta de id 1, que podría ser un lector— y no toca la
auditoría, que es el registro de lo que pasó.

**`auth.py`** — las dependencias `usuario_actual`, `solo_admin` y
`verificar_csrf`. Toda ruta que mute estado depende de las tres. `solo_admin`
mira `db.ROLES_MANDO`, no una cadena: responde "¿puede mutar el servidor?", que
es lo mismo para el superusuario y para un admin. Quién puede tocar a QUIÉN es
otra pregunta, depende de la cuenta de destino y vive en
`routers/administracion.py`.

También la puerta del segundo factor: si la política lo exige para ese rol y la
cuenta no lo tiene, `usuario_actual` levanta `RequiereAltaTOTP` y todo lleva a
`/perfil` hasta que se active. Se comprueba en cada petición y no al iniciar
sesión, para que imponer la política alcance también a las sesiones ya
abiertas.

**`qr.py`** — dibuja el QR del alta del segundo factor con `segno`. Está aquí
y no en `core/` justo para que `core/` siga siendo solo biblioteca estándar:
es el único sitio del panel que importa algo de fuera del marco web. Si el
paquete falta, lanza `QRNoDisponible` y el perfil lo dice en pantalla en vez
de dejar un hueco.

**`main.py`** — `crear_app(cfg)` es una **factory**; no hay `app` a nivel de
módulo. uvicorn arranca vía `app/servidor.py`, que saca host, puerto y
certificados del YAML para no repetirlos en la unidad de systemd.

## Decisiones que sorprenden si no se explican

### Los endpoints son síncronos a propósito

Se declaran `def`, no `async def`. Casi todo lo que hacen es E/S bloqueante:
sqlite, sockets al management, `subprocess` al helper. FastAPI ejecuta los
endpoints síncronos en un pool de hilos; declararlos `async` congelaría el
bucle de eventos en cada llamada al helper y el panel entero se quedaría
esperando.

### `TemplateResponse` lleva el request primero

Starlette moderno usa `TemplateResponse(request, nombre, contexto)`. La firma
antigua `(nombre, contexto)` ya no funciona: interpreta el nombre como request
y revienta al buscar la plantilla. Todo pasa por
[app/routers/comun.py](../app/routers/comun.py)`:render()` para no repetirlo.

### HTMX devuelve fragmentos, no páginas

Las acciones responden con el parcial `partials/aviso.html` hacia `#avisos` y
emiten una cabecera `HX-Trigger` para que las tablas afectadas se recarguen
solas. No hay redirecciones tras POST.

### Finales de línea LF forzados

`.gitattributes` fuerza LF en todo, y explícitamente en `deploy/`. El repo se
edita en Windows y se despliega en Linux: sin eso, los scripts llegan al
servidor con CRLF y fallan con `bad interpreter: /bin/bash^M`, que es un error
que no dice lo que pasa. Hay una comprobación en la CI.

## Convenciones

- **Todo en español**: interfaz, docstrings, comentarios, documentación y
  mensajes de commit.
- Funciones y variables en español (`obtener_conexiones`, `errores`, `sesion`),
  **salvo** las claves de los dicts de conexión, que se mantienen en inglés
  (`user`, `bytes_recv`…) por compatibilidad con el CLI.
- Los errores se muestran al usuario, nunca se silencian: si una vía falla, hay
  que decir cuál y por qué. Es la lección que costó cara en el CLI.
- Toda mutación del servidor se registra en la auditoría con su resultado,
  incluidos los fallos.
