# Registro de cambios

Todos los cambios relevantes de este proyecto se anotan aquí.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y
el versionado es [SemVer](https://semver.org/lang/es/).

## [Sin publicar]

### Añadido

- **Respaldos de la base, programables desde el panel.** Copia a
  `/var/lib/ovpn-web/respaldos/` con la API de respaldo de SQLite —consistente
  con el panel en uso, que un `cp` no garantiza— comprimida y con los mismos
  permisos que la base.
  - Se programa en *Configuración*: cada día o cada semana, a la hora elegida,
    conservando las N últimas. Lo dispara el vigilante en su vuelta de cinco
    minutos, y si el panel estuvo parado a esa hora respalda al volver en vez
    de saltarse el día.
  - **No se descargan desde la web.** Un respaldo es la base entera: hashes de
    contraseñas y secretos TOTP. Se quedan en el servidor y se recogen por SSH;
    hay una prueba que se pone roja si alguien añade la ruta de descarga.
  - El **directorio** va en `config.yaml`, que el panel no puede escribir: si
    se pudiera elegir desde la web, quien entrara podría mandar copias de la
    base a una ruta suya. El **horario** va en la tabla `ajustes`, que sí.
  - Un respaldo que falla sí avisa, una vez por racha y otra al recuperarse:
    el síntoma de que no se está respaldando es que no pasa nada, y eso se
    descubre el día que hace falta la copia.
  - Cómo restaurar uno está en [docs/instalacion.md](docs/instalacion.md).
- **Exportación descargable de la auditoría.** Un ZIP con `auditoria.csv` y
  `clientes-archivados.csv` para abrirlos en una hoja de cálculo. Las columnas
  que salen están nombradas una a una en el código, así que una columna nueva
  con algo delicado no se cuela sola; hay una prueba que busca hashes y
  secretos dentro del ZIP.
- **Limpieza de la base desde el panel.** Auditoría de más de 30/90/180/365
  días —o **todo el historial, desde el primer registro**—, sesiones e intentos
  caducados, y `VACUUM` opcional. Se elige con casillas y hay que escribir
  `LIMPIAR`, como al rotar la clave tls-crypt: borrar auditoría destruye el
  registro de quién hizo qué.
  - «Todo» es una opción del desplegable, con su texto propio, para que sea una
    elección y no un accidente. Un corte que no esté en la lista cae en el más
    conservador y **nunca** en «todo»: al revés, un valor raro llegado del
    formulario se llevaría el historial sin que nadie lo hubiera pedido.
  - Los perfiles archivados no se tocan: son el historial de quién tuvo
    certificado y ocupan tres columnas de texto.
  - Los bloqueos de login **en vigor** se respetan aunque se pida limpiar los
    contadores de intentos; levantarlos es justo lo que querría de una
    «limpieza» quien está bloqueado.
  - La propia limpieza queda anotada en la auditoría que sobrevive, con
    cuántas filas se llevó por delante.

- **La tabla de conexiones dice cuánto lleva dentro cada cliente.** Antes solo
  estaba la fecha de entrada, y saber si alguien llevaba diez minutos o tres
  días obligaba a restar de cabeza en cada fila.
  - El dato sale de la columna `Connected Since (time_t)` del status v3, que es
    un instante absoluto; solo cuando falta —status v3 antiguos, o el formato
    v1— se lee la fecha escrita, que es hora local del servidor.
  - La fecha se interpreta con una tabla de meses propia y no con `strptime`,
    que mira el locale del proceso: un `LC_TIME` español habría vaciado la
    columna sin decir por qué.
  - **Si no hay hora de conexión no se inventa una duración**: la celda pone un
    guion que explica la causa. Una diferencia negativa —al servidor le
    cambiaron la hora— tampoco se muestra, mismo criterio que las duraciones de
    sesión de la auditoría.
  - La tabla ya se refrescaba sola cada diez segundos, así que el tiempo sube
    sin tocar nada.
- **Botón de actualizar en Conexiones**, con el icono de recarga. La tabla ya
  se refresca sola cada diez segundos, pero quien acaba de desconectar a
  alguien quiere verlo ahora. Pide el mismo fragmento que el intervalo, así que
  no hay dos caminos distintos hasta la tabla, y el icono gira mientras dura la
  petición: sin novedades la tabla vuelve idéntica y nada diría que el clic
  hizo algo.
- **Las sesiones de la VPN que siguen abiertas dicen cuánto llevan.** La columna
  de duración ponía «en curso», que no responde a la pregunta que se hace quien
  la mira. Va en una clave aparte de la duración medida y con la palabra
  «lleva» delante: la sesión no ha terminado, así que es el tiempo desde la
  entrada, no algo medido entre dos líneas del log.

### Corregido

- **El filtro «Conexiones» de la auditoría de VPN se dejaba fuera las
  desconexiones.** Solo listaba las entradas, así que una sesión ya terminada
  parecía seguir abierta, y la salida no aparecía en ninguna pestaña salvo
  «Todo», mezclada con arranques del servidor y recargas de la CRL. Una
  desconexión es la otra mitad del mismo hecho y ahora salen juntas.
- **La CI se rompía sola cada vez que FastAPI publicaba una versión.** El
  trabajo que comprueba el lock lo regeneraba y lo comparaba, pero sin fijar
  una fecha de corte: `uv pip compile` resolvía a lo más nuevo que hubiera en
  PyPI **en el instante de ejecutarse**, así que el resultado dependía del
  calendario de otros y no de nada del repositorio.
  - Confundía dos cosas: «el lock no refleja los rangos», que es un fallo real,
    con «el lock no es lo último de PyPI», que es precisamente para lo que
    existe un lock.
  - Ahora la fecha vive en `requirements.fecha` y se pasa con `--exclude-newer`,
    de modo que la comprobación solo salta cuando alguien cambia de verdad un
    `.in`. Actualizar dependencias pasa a ser deliberado: subir la fecha y
    regenerar, en el mismo commit.
  - La CI instala además una versión **fijada** de `uv`, por el mismo motivo: su
    formato de salida cambia entre versiones.
  - Una CI que falla por motivos ajenos al cambio enseña a ignorarla, y el día
    que falle por algo de verdad nadie la mirará.

### Cambiado

- Dependencias actualizadas a fecha 2026-08-02: FastAPI 0.141.1, Starlette
  1.3.1, uvicorn 0.52.1 y websockets 17 para Python 3.11+.

## [0.2.0] — 2026-08-02

Los cinco fallos corregidos que más importan salieron del primer despliegue en
un servidor real y del uso de la interfaz, no de la suite. Esta versión añade
las pruebas que los habrían cazado.

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

Los cinco primeros salieron del primer despliegue en producción y del repaso
que provocó. Ninguno lo habría encontrado la suite tal como estaba.

- **El certificado del servidor aparecía como un cliente más**, con sus botones
  de revocar y de descargar el `.ovpn`. El filtro comparaba exacto contra
  `{'server', 'ca'}` y los instaladores al uso generan el nombre con un sufijo
  aleatorio (`server_SU1O2eUJ8SUV0x2W`). Ahora el helper deduce el CN del
  certificado que declara el `server.conf` —resolviendo las rutas relativas— y
  lo excluye al listar, además de rechazarlo en las cuatro operaciones que
  reciben un CN: no salir en la lista no impide invocarlas a mano.
- **El alta del segundo factor se pisaba a sí misma.** El secreto solo se
  enseña una vez, así que al recargar la página reaparecía el botón de activar;
  pulsarlo generaba un secreto nuevo y dejaba muerta la cuenta ya guardada en
  el móvil, sin que nada lo explicara. Ahora no se pisa un alta en curso, y
  empezar de cero es un acto deliberado con su propio botón.
- **Ninguna acción se podía disparar dos veces seguidas.** Diecinueve controles
  no se desactivaban mientras su petición estaba en vuelo. El peor era
  *restaurar*, que reemite el certificado con una clave privada nueva: un
  segundo disparo mataba el `.ovpn` que el panel acababa de decir que
  descargaras. `hx-confirm` no protegía —se puede confirmar dos veces—, y los
  formularios que no usan HTMX tampoco: en `/login` un doble envío quemaba dos
  de los cinco intentos, y en el código de dos pasos el segundo encontraba el
  paso ya consumido y respondía *"Código incorrecto"* a un código correcto.
- **El formulario de alta no se vaciaba al crear un cliente**, así que la
  contraseña del certificado se quedaba a la vista en el navegador y el botón
  invitaba a crear el mismo CN otra vez.
- **Enlaces rotos entre plantillas y rutas.** Las pestañas de Auditoría
  apuntaban a `/auditoria` cuando el router lleva prefijo `/admin`. Ahora una
  prueba recorre las trece plantillas y comprueba contra la aplicación que
  ninguno de sus destinos da 404 — algo que no verifica ni Python, ni Jinja, ni
  el navegador hasta que alguien pulsa.

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

- **Avisos de sucesos por correo y por Discord.** Cuatro categorías que se
  eligen por separado: seguridad del panel, certificados y CA, salud del
  servicio y rechazos de conexión. Sin dependencias nuevas: `smtplib` y
  `urllib.request` son de la biblioteca estándar.
  - **Es lo único que hace que el panel salga a internet.** Hasta ahora solo
    hablaba con `127.0.0.1`, el disco y `sudo`. Si se deja sin configurar, no
    sale nada y no hay canal de salida que comprometer.
  - Los **destinos y las credenciales** van en `config.yaml`, que es
    root:ovpnweb 0640: el panel lo lee y no lo escribe, así que quien lo
    comprometa **no puede redirigir las alertas a su propio buzón**. Los
    **interruptores** viven en la base y se cambian desde el panel, para no
    exigir SSH cada vez.
  - El hueco que eso deja lo cierra la **regla del aviso previo**: apagar un
    canal o quitar una categoría manda primero el aviso de que se está
    reduciendo la vigilancia, por los canales que todavía estaban activos, y
    solo después guarda. El último mensaje que sale por ahí es el que delata
    que lo callaron. La interfaz no lo anuncia, a propósito.
  - Un botón de prueba comprueba los canales configurados —estén activados o
    no— y enseña el error exacto de cada uno. Sin él, la única forma de
    descubrir un SMTP mal escrito era esperar a un incidente y no recibir nada.
  - El envío va en un hilo aparte, y nunca tumba la acción que lo provocó: se
    revoca un certificado aunque el correo esté caído. Los fallos de entrega
    quedan en la auditoría.

- **Auditoría de la VPN, en su propia pestaña.** Conexiones establecidas y
  rechazadas, con su IP y su hora, leídas del log de OpenVPN. Aparte de la
  auditoría del panel porque son cosas distintas: aquella registra acciones de
  una cuenta, esta conexiones de un certificado.
  - Reconoce certificados revocados o caducados, handshakes fallidos y claves
    `tls-crypt` que no coinciden —este último con mensaje propio, porque es el
    síntoma de un cliente con el perfil anterior a una rotación.
  - Ata cada rechazo con el CN que lo provocó agrupando por `ip:puerto`, que es
    como OpenVPN marca las líneas de una misma sesión. Cuando la conexión muere
    antes de presentar certificado **la columna queda vacía en vez de
    inventarlo**: en una auditoría, rellenarla sería mentir.
  - Avisa de por qué no hay nada que enseñar. Los tres motivos se parecen y
    solo uno es normal: que no haya pasado nada, que el panel no pueda leer el
    archivo, o que el `verb` del servidor sea demasiado bajo.

- **Filtros y paginación en las dos pestañas de Auditoría**, con tamaño de
  página elegible entre 50, 100 y 200. Del lado del panel se filtra y se pagina
  en SQL: la tabla crece sin límite y traerla entera para descartar la mayor
  parte sería leer todo el historial en cada visita.

- **Histórico de perfiles eliminados.** Un desplegable al final de *Clientes
  VPN* con los retirados de la lista, y un botón que los manda ahí.
  - **No se borran de la PKI, y eso es lo que hace segura la función.** La CRL
    no se guarda: se regenera desde `index.txt` cada vez que se revoca a
    alguien, así que quitar de ahí un certificado le devolvería la validez en
    esa siguiente regeneración, en silencio. Archivado sigue revocado y
    bloqueado; solo deja de estorbar.
  - Solo se admiten certificados ya revocados: ocultar uno válido escondería un
    acceso vivo.

- **Aviso de perfiles pendientes de repartir.** Cuando una operación invalida
  todos los `.ovpn` de golpe, queda una banda en *Clientes VPN* con la lista de
  quién necesita uno nuevo, marcando los ya descargados, hasta que alguien la
  da por cerrada. Vive en el servidor: uno que se fuera al recargar no serviría.

- **`deploy/comprobar-servidor.sh`**, para instalar sobre un OpenVPN que ya
  existía. Contrasta el `server.conf` con la configuración del panel
  —resolviendo las rutas relativas como lo hace OpenVPN— y ordena los hallazgos
  en críticos y avisos, con el comando exacto de arreglo para cada uno. Solo
  lee; hay una prueba que lo mantiene así. `install.sh` lo llama solo cuando
  detecta que la VPN ya estaba montada.
  - Dos de sus comprobaciones existen porque fallan en silencio: que el usuario
    al que OpenVPN suelta privilegios **pueda leer de verdad la CRL** —se
    intenta, no se deduce de los permisos— y que la CRL no esté caducada, que
    hace rechazar todas las conexiones y no solo las revocadas.

- **Rotación de `openvpn.log`.** Con `log-append` y sin ella el archivo crecía
  sin límite. Va con `copytruncate`: rotar renombrando obligaría a avisar a
  OpenVPN con SIGHUP, que reinicia el túnel y desconecta a todo el mundo.

- **Diálogo de confirmación propio** en vez del `confirm()` del navegador, con
  `<dialog>` nativo —foco atrapado, cierre con Escape y papel de modal ante el
  lector de pantalla, sin reimplementar nada. El foco arranca en *Cancelar*:
  casi todo lo que pasa por ahí es destructivo y un Intro de más no puede ser
  lo que revoque un certificado. Si el script no carga, vuelve el `confirm`
  nativo: la guarda no depende de que funcione.

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

- 560 pruebas, 476 más que en la 0.1.0.

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

[Sin publicar]: https://github.com/Electrobridges/BridgesMGR/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Electrobridges/BridgesMGR/releases/tag/v0.2.0
[0.1.0]: https://github.com/Electrobridges/BridgesMGR/releases/tag/v0.1.0
