# Registro de cambios

Todos los cambios relevantes de este proyecto se anotan aquí.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y
el versionado es [SemVer](https://semver.org/lang/es/).

## [Sin publicar]

### Cambiado

- **Los roles pasan a ser una jerarquía de tres.** El rol `lector` se llama
  ahora `supervisor`, y por encima de los administradores aparece un
  **`superusuario`**.
  - Lo es **la primera cuenta que se creó** en la instalación, se pidiera el
    rol que se pidiera. No se concede: `--rol superusuario` no existe y el
    panel tampoco lo ofrece.
  - Es **intocable**: nadie puede cambiarle el rol, desactivarlo, borrarlo, ni
    tocarle la contraseña o el segundo factor. Lo último importa tanto como lo
    primero — quien pudiera cambiarle la contraseña sería superusuario en dos
    pasos. La única recuperación es la CLI, desde dentro del servidor.
  - Los administradores siguen gestionándose entre ellos.
  - **Nadie cambia su propio rol**, superusuario incluido.
  - **Migración automática al arrancar.** Las cuentas `lector` pasan a
    `supervisor` y el **admin más antiguo** pasa a superusuario. Se asciende al
    admin más antiguo y no a la cuenta de id 1, que podría ser un lector. La
    auditoría no se reescribe: es el registro de lo que pasó, y lo que pasó se
    llamaba `lector`.
  - La ruta de la política de TOTP pasa de `/admin/politica/totp-lector` a
    `/admin/politica/totp-supervisor`.
- **El rol `supervisor` ya no entra en *Configuración*.** Esa página enseña las
  rutas de la PKI y de los logs, el puerto del management y el estado de la
  unidad: es el plano de la instalación, no el estado de la VPN. Nada de eso le
  hace falta para mirar quién está conectado, y le dice a un curioso por dónde
  empezar. El enlace tampoco aparece en el menú.
  - Nuevo `app.cli designar-superusuario <usuario>`: la única forma de trasladar
    el rol, y solo desde el servidor. Hace falta para las dos instalaciones que
    la migración no puede resolver sola — una sin ningún admin al que ascender,
    y otra donde el ascenso recayó en la cuenta equivocada.

### Corregido

- **El hash de HTMX no estaba versionado.** `deploy/htmx.sha256` existía solo en
  la máquina de quien instaló la primera vez, así que cualquier instalación
  desde un clon limpio descargaba HTMX del CDN y guardaba lo que le dieran sin
  comparar con nada. HTMX se sirve desde el propio panel, de modo que la CSP
  `script-src 'self'` lo da por bueno: un archivo manipulado sería JavaScript
  ejecutándose con la sesión del administrador. Ahora el instalador **aborta**
  si falta el hash, y fijarlo sin verificar exige `--htmx-confiar`.
- El token CSRF se comparaba con `!=` en vez de `hmac.compare_digest`.

Los cuatro siguientes salieron del primer despliegue en un servidor real
(Debian 13, easy-rsa 3.2.2). Ninguno se veía leyendo el código, y los cuatro
rompían el panel entero.

- **El panel no podía emitir ni revocar ningún certificado.** `ovpn-web.service`
  lleva `ProtectSystem=strict`, que monta el sistema en solo lectura dentro del
  espacio de nombres del servicio; los hijos lo heredan, también el helper
  lanzado con sudo aunque corra como root. Faltaba `/etc/openvpn` en
  `ReadWritePaths`. Fallaba con un error de easyrsa que no menciona systemd por
  ningún lado.
- **Todos los certificados salían con el CN de la CA.** El instalador de
  OpenVPN ponía `EASYRSA_REQ_CN` en `vars`, y desde ahí se aplica a **todas**
  las peticiones, no solo a la de la CA. Dejaba el certificado del servidor y
  el de cada cliente con el mismo nombre, el índice de la PKI inservible y el
  panel incapaz de identificar a nadie. Ahora va como opción de `build-ca`.
- **`easy-rsa` 3.2 pide confirmación en `build-client-full`.** El helper no
  pasaba `--batch`, así que en Debian 13 no se podía crear un cliente. Las
  versiones anteriores no preguntaban: el fallo aparece al actualizar el
  sistema operativo, no al tocar el código.
- **El superusuario veía el panel como si fuera de solo lectura.** Cuatro
  sitios seguían comparando el rol de la sesión con la cadena `'admin'` —el
  menú de *Usuarios*, la guía de contraseña del perfil, el formulario de crear
  clientes y los botones de la tabla—, así que la cuenta con más poder los
  perdía todos. Las rutas respondían 200: el fallo estaba solo en lo que se
  dibujaba. Las plantillas ya no comparan roles: `render()` inyecta `manda`
  desde `db.ROLES_MANDO`, la misma lista que mira `solo_admin`, y hay una
  prueba que impide volver a comparar cadenas.
- **El helper escondía el error real de easyrsa.** Prefería `stderr` sobre
  `stdout` cuando el primero no estaba vacío, y easy-rsa escribe separadores
  decorativos (`-----`) en `stderr` y el motivo en `stdout`. El panel decía
  `-----` y nada más. Ahora reporta los dos flujos y el código de salida.
- **Cambiar el rol sin cambiarlo cerraba la sesión.** Pulsar *Cambiar rol* sin
  tocar el desplegable borraba igualmente las sesiones de la cuenta afectada, y
  como uno podía apuntarse a sí mismo, el resultado era quedarse fuera del
  panel sin haber cambiado nada.
- **Una cuenta podía cambiarse el rol a sí misma.** Que a unos les funcionara y
  a otros no era casualidad, no una regla: los supervisores no llegaban a la
  página, y a los administradores solo les paraba el guardián del último admin.
- El aviso de «último administrador» saltaba también al degradar o borrar a un
  admin **ya desactivado**, que no resta a nadie del mando: bloqueaba una
  limpieza legítima.
- **Revocar dejaba al servidor sin admitir a nadie.** El helper regenera la CRL
  con `easyrsa gen-crl`, cuyos permisos dependen del umask — y el umask que
  hereda es el `UMask=0077` de la unidad del panel, así que salía en 0600.
  OpenVPN la relee en cada conexión y para entonces ya bajó a `nobody`: no
  podía leerla y rechazaba a todo el mundo. El panel decía que había cortado un
  acceso y los había cortado todos, sin que nada lo dijera. Reproducido y
  verificado en el servidor de pruebas. Ahora se asegura de dejarla legible.

### Añadido

- **Dependencias fijadas y verificadas.** `requirements.txt` pasa a ser un lock
  generado de `requirements.in`, con versiones exactas y el SHA-256 de cada
  artefacto. El instalador usa `pip install --require-hashes`: si PyPI o un
  espejo devuelven algo distinto de lo que se probó, aborta en vez de
  instalarlo. Cada versión publicada lleva su lock, así que reinstalar una
  versión antigua reproduce lo que se probó entonces y no lo que hubiera en
  PyPI ese día.
  - Los rangos llevan techo, en `requirements.in` y en `pyproject.toml`. Una
    prueba rechaza cualquier `>=` suelto y otra comprueba que los dos archivos
    dicen lo mismo.
  - El lock se resuelve contra Python 3.9, la mínima soportada, para que valga
    en todo el rango de Debian 11 a 13.
  - La CI regenera los locks y falla si no coinciden con los `.in`, y pasa
    `pip-audit` sobre las dependencias.
- **Certificados de cliente con contraseña.** Al crear un cliente se puede
  cifrar su clave privada; OpenVPN la pide al conectar, así que el `.ovpn`
  robado ya no es acceso directo a la VPN. La casilla viene **marcada por
  defecto** y se desmarca para clientes desatendidos —un rúter, un servidor—,
  que no tienen a nadie que la teclee al reconectar.
  - La contraseña **nunca pasa por `argv`**: viaja al helper por stdin y de ahí
    a easyrsa por el entorno. `--passout=pass:…` habría sido una línea más
    corta y dejaría la contraseña de cada certificado al alcance de cualquier
    usuario del servidor con un `ps`. Hay una prueba que lo impide.
  - No se registra en ninguna parte. En la auditoría consta **que** el
    certificado se cifró, nunca con qué.
  - Mínimo de 12 caracteres, igual que las cuentas del panel, y validado en los
    tres sitios: formulario, panel y helper.
  - *Restaurar* también la admite, porque reemite una clave privada nueva.
  - No se puede recuperar: si se pierde, hay que reemitir el certificado.
- **El instalador monta OpenVPN si no lo encuentra.** `deploy/install.sh` mira
  si hay un servidor montado y, si no, se ofrece a montarlo con el nuevo
  `deploy/instalar-openvpn.sh`. Si ya existe uno, no le toca ni una línea.
  - PKI con curva elíptica `secp384r1`: evita generar parámetros
    Diffie-Hellman, que son los minutos que se lleva instalar OpenVPN.
  - Deja el `server.conf` con `management`, `status-version 3` y `crl-verify`,
    que son las tres líneas sin las que el panel no ve ni corta nada.
  - Dos alcances, elegibles con `--salida`: solo la red local del servidor
    (túnel dividido) o todo el tráfico del cliente (túnel completo).
  - Activa el reenvío IP y el NAT —en su propia tabla de nftables— y se
    entiende con `ufw` si está activo. Con `--sin-red` no toca nada y deja los
    comandos por pantalla.
  - Idempotente: conserva la PKI que encuentre y nunca pisa un `server.conf`.
  - Cuando monta la VPN, `install.sh` rellena `/etc/ovpn-web/config.yaml` con
    lo que ese script decidió, sin destruir los comentarios del archivo.
- El botón **Cambiar rol** solo aparece cuando el desplegable deja de mostrar
  el rol vigente. Va en CSS con `:has()`, sin JavaScript; un navegador que no
  lo soporte lo deja siempre visible, como antes.
- **Verificación en dos pasos (TOTP)** para entrar al panel. RFC 6238 con la
  biblioteca estándar, sin dependencias nuevas y contrastado contra los
  vectores oficiales de la RFC.
  - Opcional para quien manda: cada uno activa el suyo desde **Mi cuenta**.
  - Exigible al rol `supervisor` desde *Usuarios* o con `app.cli politica-totp`.
    Mientras esté exigido, un supervisor sin segundo factor solo puede ir a su
    perfil. La política no alcanza nunca a superusuario ni admins, para que un
    administrador no pueda dejar fuera a otro.
  - Alta con **código QR** para escanear con la app, y la clave al lado por si
    se prefiere teclearla. El QR se genera en el propio servidor y viaja como
    `data:` URI dentro de un `<img>`, sin tocar la CSP ni pasar por ningún
    servicio externo.
  - El alta no se confirma hasta que el usuario teclea un código correcto, y
    ni el secreto ni el QR se vuelven a mostrar después.
  - Un código no vale dos veces, la contraseña sola no abre ninguna página, y
    los códigos fallidos gastan intentos del mismo contador de bloqueo.
  - Restablecimiento desde `/admin/usuarios` o con
    `app.cli totp-restablecer <usuario>`, que además cierra las sesiones de
    esa cuenta.
- Página **Mi cuenta** (`/perfil`), accesible desde el nombre de usuario.
- Identidad **BridgesMGR** en la interfaz: el isotipo (escudo con llave) en la
  barra superior, en el login y como favicon, y el nombre compuesto con el
  patrón de marca —*Bridges* en blanco, *MGR* en cian—. Los archivos viven en
  `app/static/imagenes/`, con su propio README.
  Los identificadores de instalación (servicio `ovpn-web`, usuario `ovpnweb`,
  `/opt/ovpn-web`) **no cambian**: es solo la marca de la interfaz.
- Comandos de CLI `totp-restablecer` y `politica-totp`; `listar-usuarios`
  muestra ahora el estado del segundo factor.

### Cambiado

- El esquema de la base de datos se **migra solo** al arrancar: las
  instalaciones existentes ganan las columnas del TOTP y las tablas `ajustes`
  y `logins_pendientes` sin perder nada.
- Nueva dependencia: **`segno`** (Python puro, sin dependencias propias en
  3.10+), solo para dibujar el QR del alta. El algoritmo TOTP en sí no añade
  ninguna: es la biblioteca estándar. Si `segno` falta, el panel avisa en
  pantalla y el alta sigue siendo posible tecleando la clave.

- Documentación separada en `docs/`: instalación, configuración, seguridad,
  arquitectura y solución de problemas.
- Integración continua en GitHub Actions: la suite en Python 3.9, 3.11 y 3.13,
  más comprobación de sintaxis de la mitad privilegiada (`bash -n`,
  `py_compile`, `visudo -c`) y de que no se cuelen finales CRLF en `deploy/`.
- `tests/test_despliegue.py`: convierte en pruebas los invariantes de la
  frontera de privilegios que hasta ahora solo estaban documentados —paridad
  del regex de CN entre panel y helper, que sudoers no gane alcance, que
  `NoNewPrivileges` siga en `false` y que no aparezca `shell=True`.
- Guía de contribución, código de conducta, política de seguridad y plantillas
  de incidencia y de pull request.

## [0.1.0] — 2026-07-26

Primera versión. Panel web (FastAPI + Jinja2 + HTMX) para administrar un
servidor OpenVPN desde el navegador, con el núcleo portado de
[OpenVPN-Manager-CLI](https://github.com/Electrobridges/OpenVPN-Manager-CLI).

### Añadido

- **Panel de estado**: clientes conectados, tráfico, certificados y estado del
  servicio.
- **Conexiones en vivo**: tabla autorrefrescada con IP real, IP virtual y
  tráfico, leyendo del management interface y cayendo al archivo de status si
  no está disponible —diciendo en pantalla cuál se usó y por qué.
- **Clientes VPN**: crear, revocar, restaurar y descargar el perfil `.ovpn` ya
  montado, con `tls-crypt` embebido si está configurado.
- **Expulsar clientes** conectados desde el management interface.
- **Visor de logs** con filtro de texto y coloreado por tipo de mensaje.
- **Cuentas del panel** con roles `admin` y `lector`, gestionadas por CLI.
- **Auditoría**: quién hizo qué, cuándo, desde qué IP y con qué resultado,
  incluidos los logins fallidos y las descargas de perfiles.
- **Frontera de privilegios**: el servicio corre como `ovpnweb` sin
  privilegios y delega todo lo que necesita root en
  `deploy/ovpn-web-helper`, único comando autorizado en
  `/etc/sudoers.d/ovpnweb`. El helper lee sus rutas de `config.yaml`, nunca de
  sus argumentos, y revalida el Common Name por su cuenta.
- **Autenticación** con Argon2, sesiones cuyo token se guarda hasheado con
  SHA-256, cookie `httpOnly` + `SameSite=Strict` y bloqueo por intentos
  contado por usuario + IP.
- **CSRF** obligatorio en toda mutación, inyectado en las peticiones HTMX desde
  `base.html`, y CSP estricta `script-src 'self'` con HTMX servido en local y
  verificado por SHA-256 durante la instalación.
- **Instalador** idempotente para Debian/Ubuntu con unidad de systemd
  endurecida y certificado TLS autofirmado.
- 84 pruebas.

[Sin publicar]: https://github.com/Electrobridges/BridgesMGR/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Electrobridges/BridgesMGR/releases/tag/v0.1.0
