# Cómo contribuir

Gracias por el interés. Este proyecto administra un servidor OpenVPN con
permisos elevados, así que hay un par de cosas que conviene leer antes de
mandar código.

## Antes de nada

- **Todo va en español**: interfaz, docstrings, comentarios, documentación y
  mensajes de commit.
- Si el cambio toca `deploy/`, lee primero [docs/seguridad.md](docs/seguridad.md).
  Ahí están las siete reglas de la frontera de privilegios; romper cualquiera
  convierte el panel en una vía a root.
- Para cambios grandes, abre una incidencia antes de escribir el código. Es
  mejor discutir el enfoque que descartar trabajo hecho.

## Montar el entorno

```bash
git clone https://github.com/Electrobridges/BridgesMGR.git
cd BridgesMGR

python -m venv .venv
source .venv/bin/activate        # en Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

pytest
```

La suite corre entera en Windows o en Linux, **sin OpenVPN instalado**:
`app/core/` no importa FastAPI y las pruebas de rutas sustituyen el helper por
dobles.

```bash
pytest                                                  # toda la suite
pytest tests/test_auth.py                               # un archivo
pytest -k csrf                                          # por nombre
pytest tests/test_auth.py::test_supervisor_no_puede_revocar # una sola
```

Para levantar el panel en local hace falta una configuración propia:

```bash
cp deploy/config.ejemplo.yaml config.local.yaml   # y ajústalo
OVPN_WEB_CONFIG=config.local.yaml python -m app.servidor
```

Sin `htmx.min.js` (que descarga el instalador) las páginas cargan pero no se
refrescan solas.

## Dependencias

Hay dos preguntas distintas y cada una tiene su archivo. Confundirlas es lo que
lleva a que «funciona en mi máquina».

| Pregunta | Archivo | Contenido |
|---|---|---|
| ¿Qué versiones **sostiene** el código? | `requirements.in`, `pyproject.toml` | Rangos con techo |
| ¿Qué versiones se **instalan**? | `requirements.txt` | Versiones exactas + SHA-256 |

`requirements.txt` es un **lock generado**. No se edita a mano: se regenera de
`requirements.in` y cualquier cambio directo se pierde en el siguiente compile.

```bash
CORTE=$(cat requirements.fecha)

uv pip compile requirements.in --universal --python-version 3.9 \
    --generate-hashes --no-header --exclude-newer "$CORTE" -o requirements.txt

uv pip compile requirements-dev.in --universal --python-version 3.9 \
    --generate-hashes --no-header --exclude-newer "$CORTE" -o requirements-dev.txt
```

**Para actualizar dependencias**, sube la fecha de `requirements.fecha` a hoy y
vuelve a ejecutar eso. Los tres archivos van en el mismo commit.

Cinco decisiones que conviene entender antes de tocarlo:

**`--python-version 3.9`, y no la que tengas.** El mínimo que declara
`pyproject.toml`, y lo que trae Debian 11. Resolviendo contra la **mínima** el
resultado vale hacia arriba; al revés no: una versión que exija 3.11 se
elegiría en tu máquina y reventaría en un Debian 11.

**`--universal`, o el lock sale sesgado hacia tu sistema operativo.** Sin él,
uv resuelve solo para la máquina donde corre. Generado en Windows sale **sin
uvloop**, porque `uvicorn[standard]` lo excluye allí — y el servidor Linux se
quedaría sin él, cayendo al bucle asyncio estándar sin que nada fallara ni lo
dijera. Con `--universal` el lock lleva marcadores (`sys_platform != 'win32'`)
y cubre las dos. Hay una prueba y una comprobación en CI que lo vigilan; pasó
de verdad mientras se montaba esto.

**Genéralo en Linux, aunque desarrolles en Windows.** `--universal` quita la
dependencia de la *plataforma* del resultado, pero no la del entorno donde se
resuelve: con la misma versión de uv y el mismo comando, Windows y Linux dan
locks distintos —Linux desdobla paquetes por versión de Python
(`annotated-types==0.7.0 ; python_full_version < '3.10'` y otra para arriba) y
Windows fija una sola—. Son 384 líneas de diferencia, y la CI lo detecta al
regenerarlo.

El que vale es el de **Linux**, porque es donde se instala. Usa WSL, un
contenedor o la propia máquina de pruebas:

```bash
# desde WSL o cualquier Linux, en la raíz del repo
python3 -m venv /tmp/uv && /tmp/uv/bin/pip install -q 'uv==0.12.1'
/tmp/uv/bin/uv pip compile requirements.in --universal --python-version 3.9 \
    --generate-hashes --no-header --exclude-newer "$(cat requirements.fecha)" \
    -o requirements.txt
```

La versión de `uv` va fijada y es la misma que instala la CI: el formato de
salida cambia entre versiones, y con una distinta el lock generado aquí no
coincidiría con el que ella regenera para comparar.

**`--exclude-newer`, con la fecha en `requirements.fecha`.** Sin ella la
resolución depende de qué haya en PyPI en el instante en que se ejecuta, así
que la CI —que regenera el lock y lo compara— fallaba sola cada vez que FastAPI
publicaba una versión, sin que nadie hubiera tocado nada.

Confundía dos cosas: «el lock no refleja los rangos», que es un fallo real, con
«el lock no es lo último de PyPI», que es precisamente para lo que existe un
lock. Con la fecha fija, esa comprobación solo salta cuando alguien cambia de
verdad un `.in`, y actualizar dependencias pasa a ser un acto deliberado en
lugar de algo impuesto por el calendario de otros.

Por el mismo motivo la CI instala una versión **fijada** de `uv`: si no, el
formato de salida podría cambiar y volveríamos al mismo problema.

**`--generate-hashes`, siempre.** Sin hashes el lock da reproducibilidad pero
no integridad: un espejo de PyPI que devuelva otro artefacto con la misma
versión se instala tan tranquilo. Con ellos, `pip install --require-hashes`
aborta — y eso es lo que hace el instalador. Es la misma idea que el hash de
HTMX, aplicada a todas las dependencias.

**Los rangos llevan techo.** Un `>=` suelto deja que una instalación de mañana
traiga una versión mayor que nadie probó contra este código. El techo se sube
cuando alguien prueba la versión nueva, no antes. Hay una prueba que rechaza
cualquier rango sin techo.

### Actualizar

1. Sube el techo en `requirements.in` (y en `pyproject.toml`: hay una prueba que
   comprueba que dicen lo mismo).
2. Regenera los dos locks.
3. `pytest` con el lock nuevo, y si toca la mitad privilegiada, prueba manual en
   una VM.
4. Un commit aparte, solo para la actualización. Mezclarla con un cambio
   funcional hace imposible saber cuál de los dos rompió algo.

La CI regenera los locks y falla si no coinciden con los `.in`, así que un
rango cambiado sin regenerar se detecta antes de llegar a un servidor. Y pasa
`pip-audit` sobre `requirements.txt`: es informativo —un CVE publicado hoy no
debe bloquear un arreglo urgente que no tiene nada que ver— pero queda en el
registro y hay que mirarlo.

### Cadencia

- **Programada**: revisión mensual. Se actualiza, se prueba, se publica una
  versión de mantenimiento aunque no haya cambios funcionales.
- **Fuera de cadencia**: solo por CVE que afecte de verdad a este panel. Un
  fallo en una parte de una dependencia que aquí no se usa puede esperar a la
  revisión mensual; decirlo en el aviso de la versión es mejor que publicar una
  actualización a las tres de la mañana sin probar.

Cada versión publicada lleva su lock. `git checkout v0.2.0 && bash
deploy/install.sh` reproduce exactamente lo que se probó para esa versión, no
lo que hubiera en PyPI ese día.

## Qué se puede verificar y qué no

Esto es lo más importante de esta página.

**Se verifica en cualquier máquina**: parsers en los tres formatos, validación
de CN, login y bloqueo por intentos, segundo factor (vectores de la RFC 6238,
reutilización de códigos y política por rol), permisos por rol, CSRF,
cabeceras de seguridad, auditoría, y los invariantes de `deploy/` que se
pueden comprobar leyendo los archivos.

**No se puede verificar aquí**: el comportamiento real de
`deploy/ovpn-web-helper`, `install.sh`, la regla de sudo y la unidad de
systemd. Hacen falta root, easyrsa y una PKI de verdad. De eso la CI solo
comprueba sintaxis y los invariantes.

> Si tu cambio toca la mitad privilegiada, **pruébalo en una VM Debian** y dilo
> en el PR: qué probaste y qué viste. Revocar y restaurar tocan la PKI de
> verdad. No lo estrenes en el servidor bueno.

## Estilo

Sigue el código que ya hay; si dudas, mira
[docs/arquitectura.md](docs/arquitectura.md). Lo que más se olvida:

- Nombres de funciones y variables **en español** (`obtener_conexiones`,
  `errores`, `sesion`). Excepción: las claves de los dicts de conexión se
  mantienen en inglés (`user`, `bytes_recv`…) por compatibilidad con el CLI.
- Los endpoints se declaran `def`, **no `async def`**. Casi todo es E/S
  bloqueante y FastAPI los ejecuta en un pool de hilos; declararlos `async`
  congelaría el bucle de eventos en cada llamada al helper.
- Las plantillas se renderizan con `routers/comun.py:render()`, nunca llamando
  a `TemplateResponse` a mano.
- `subprocess` siempre con lista de argumentos, jamás `shell=True`.
- Toda ruta que mute estado depende de `usuario_actual`, el rol que
  corresponda y `verificar_csrf`.
- **Los errores se muestran, nunca se silencian.** Si una vía falla, hay que
  decir cuál y por qué. Un `except: pass` no pasa revisión.
- Toda mutación se registra en la auditoría con su resultado, incluidos los
  fallos.

No hay linter configurado. Cuatro espacios de indentación y líneas de hasta 88
caracteres, como el resto del código.

## Pruebas

Todo cambio de comportamiento viene con pruebas. Si arreglas un fallo, añade la
prueba que lo reproduce **antes** del arreglo: así queda constancia de que
falla sin él.

Las pruebas se nombran en español y describen la regla, no la implementación:
`test_supervisor_no_puede_revocar` dice más que `test_post_403`.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/), en español:

```
feat: añade filtro por estado en la tabla de clientes
fix: corrige el truncado de status con varios clientes conectados
docs: separa el modelo de seguridad en docs/seguridad.md
test: cubre la paridad del regex de CN entre panel y helper
refactor: unifica el fallback de conexiones en obtener_conexiones()
chore: actualiza la versión de HTMX
```

Un commit por idea. El cuerpo explica **por qué**, no qué: el qué ya está en el
diff.

## Pull requests

1. Rama desde `main`: `git checkout -b feat/lo-que-sea`
2. `pytest` en verde.
3. Rellena la plantilla del PR, sobre todo la parte de cómo lo has probado.
4. Si tocaste `deploy/`, di explícitamente en qué VM lo probaste.

## Seguridad

Si encuentras un fallo de seguridad, **no abras una incidencia pública**.
Escribe a Contact@Electrobridges.com describiendo el problema y cómo
reproducirlo.

## Nunca subas al repositorio

Certificados, claves, archivos `.ovpn`, la base de datos, ni tu `config.yaml`.
El `.gitignore` los bloquea, pero revisa `git status` antes de commitear: el
`.db` contiene hashes de contraseñas y el `.ovpn` **es** el acceso a la VPN.
