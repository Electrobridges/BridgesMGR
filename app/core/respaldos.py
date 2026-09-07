"""
Copias de la base del panel.

Solo stdlib, como todo `core/`: aquí está el *cómo* se copia, se lista y se
rota. El *cuándo* y el *quién puede* viven arriba, en `app/respaldar.py` y en
las rutas.

Dos decisiones que no son de estilo:

- **Se copia con la API de backup de sqlite3, no con `cp`.** La base está en
  uso mientras el panel corre. Un `cp` puede llevarse un archivo a medio
  escribir —o el `.db` sin su journal— y el respaldo parece bueno hasta el día
  que hace falta. `Connection.backup()` copia página a página coordinándose con
  el motor, y lo que sale es una base íntegra.
- **El archivo nace con permisos 0600 y el directorio 0700.** Un respaldo es la
  base entera: hashes de contraseñas y secretos TOTP. Vale exactamente lo mismo
  que el original y se protege igual.
"""

import gzip
import os
import re
import shutil
import sqlite3
from datetime import datetime

# Los respaldos se llaman así y solo así. El nombre lleva la fecha para que
# ordenen solos y para saber qué se borra al rotar sin abrir nada.
PREFIJO = "ovpn-web-"
SUFIJO = ".db.gz"
FORMATO_SELLO = "%Y%m%d-%H%M%S"

# Un nombre que llegue por la URL —borrar uno desde el panel— se comprueba
# contra esto antes de tocar el disco. No es paranoia: 'nombre' es entrada del
# usuario y os.path.join('/dir', '../../etc/passwd') sale del directorio sin
# quejarse.
#
# El sufijo '-2', '-3'… es para dos respaldos del mismo segundo: pulsar dos
# veces «Respaldar ahora» daba el mismo nombre y el segundo pisaba al primero,
# que es lo contrario de lo que hace un respaldo.
NOMBRE = re.compile(r"^ovpn-web-(\d{8}-\d{6})(?:-(\d+))?\.db\.gz$")

# Cuántos conservar si nadie lo ha dicho. Una semana de respaldos diarios.
CONSERVAR_POR_DEFECTO = 7


class ErrorRespaldo(Exception):
    """No se pudo crear, listar o borrar un respaldo"""


def preparar_directorio(directorio):
    """
    Crea el directorio de respaldos si falta y le cierra los permisos.

    Vive bajo /var/lib/ovpn-web, que es lo único que la unidad de systemd deja
    escribir al panel (ReadWritePaths); fuera de ahí ProtectSystem=strict lo
    impide y el fallo es un permiso denegado que no menciona la causa.
    """
    try:
        os.makedirs(directorio, exist_ok=True)
        os.chmod(directorio, 0o700)
    except OSError as e:
        raise ErrorRespaldo(
            "No se pudo preparar %s: %s. El panel corre como 'ovpnweb' y solo "
            "escribe dentro de /var/lib/ovpn-web." % (directorio, e)
        )


def crear(ruta_db, directorio, ahora=None):
    """
    Copia la base a <directorio>/ovpn-web-AAAAMMDD-HHMMSS.db.gz.

    Devuelve el nombre del archivo creado.

    El temporal se escribe en el mismo directorio y no en /tmp: así el paso
    final es dentro del mismo sistema de archivos, y de paso /tmp nunca ve una
    copia de la base sin comprimir.
    """
    ahora = ahora or datetime.now()
    preparar_directorio(directorio)

    nombre = _nombre_libre(directorio, ahora)
    destino = os.path.join(directorio, nombre)
    temporal = os.path.join(directorio, ".%s.tmp" % nombre)

    try:
        _copiar_base(ruta_db, temporal)
        _comprimir(temporal, destino)
        os.chmod(destino, 0o600)
    except (OSError, sqlite3.Error) as e:
        # Un respaldo a medias es peor que ninguno: parece que hay copia.
        for sobra in (temporal, destino):
            _borrar_sin_ruido(sobra)
        raise ErrorRespaldo("No se pudo crear el respaldo: %s" % e)
    finally:
        _borrar_sin_ruido(temporal)

    return nombre


def _nombre_libre(directorio, ahora):
    """
    El nombre del respaldo, con sufijo si ya hay uno de ese mismo segundo.

    Pasa al pulsar dos veces seguidas «Respaldar ahora»: sin esto, el segundo
    sobrescribía al primero en silencio.
    """
    sello = ahora.strftime(FORMATO_SELLO)
    nombre = "%s%s%s" % (PREFIJO, sello, SUFIJO)
    indice = 1

    while os.path.exists(os.path.join(directorio, nombre)):
        indice += 1
        nombre = "%s%s-%d%s" % (PREFIJO, sello, indice, SUFIJO)

    return nombre


def _clave_orden(nombre):
    """
    Por qué se ordena: (sello, número de la copia dentro de ese segundo).

    Se parsea el nombre en vez de mirar la fecha del archivo para que copiar
    los respaldos de sitio no cambie su orden. Y se parsea de verdad en vez de
    comparar el texto, porque '-2' ordena antes que '.db' por ASCII y el más
    nuevo del mismo segundo acabaría el primero de la lista... por debajo del
    viejo, que es justo al revés.
    """
    coincide = NOMBRE.match(nombre)
    return (coincide.group(1), int(coincide.group(2) or 1))


def _copiar_base(ruta_db, temporal):
    """Copia consistente de una base en uso, con la API de backup de sqlite3"""
    origen = sqlite3.connect(ruta_db)
    try:
        copia = sqlite3.connect(temporal)
        try:
            origen.backup(copia)
        finally:
            copia.close()
    finally:
        origen.close()


def _comprimir(temporal, destino):
    """Comprime y borra el intermedio. Una base SQLite baja mucho con gzip."""
    with open(temporal, "rb") as entrada:
        with gzip.open(destino, "wb") as salida:
            shutil.copyfileobj(entrada, salida)


def _borrar_sin_ruido(ruta):
    try:
        os.remove(ruta)
    except OSError:
        pass


def listar(directorio):
    """
    Los respaldos que hay, del más reciente al más antiguo.

    Cada uno: {'nombre', 'bytes', 'creado'}. Un directorio que no existe todavía
    no es un error: es que aún no se ha hecho ninguno.
    """
    try:
        nombres = os.listdir(directorio)
    except FileNotFoundError:
        return []
    except OSError as e:
        raise ErrorRespaldo("No se pudo leer %s: %s" % (directorio, e))

    encontrados = []

    for nombre in nombres:
        if not NOMBRE.match(nombre):
            continue
        try:
            info = os.stat(os.path.join(directorio, nombre))
        except OSError:
            # Se lo llevó una rotación entre el listdir y el stat. No es un
            # fallo que contar: simplemente ya no está.
            continue
        encontrados.append({
            "nombre": nombre,
            "bytes": info.st_size,
            "creado": datetime.fromtimestamp(info.st_mtime),
        })

    encontrados.sort(key=lambda r: _clave_orden(r["nombre"]), reverse=True)
    return encontrados


def ruta_de(directorio, nombre):
    """
    Ruta absoluta de un respaldo, validando el nombre.

    Lanza ErrorRespaldo si no tiene la forma exacta que genera crear(). El
    nombre llega desde el panel, así que se comprueba antes de tocar el disco.
    """
    if not NOMBRE.match(nombre or ""):
        raise ErrorRespaldo("Nombre de respaldo no válido: %s" % (nombre or "(vacío)"))

    return os.path.join(directorio, nombre)


def borrar(directorio, nombre):
    """Borra un respaldo. Devuelve False si ya no estaba."""
    ruta = ruta_de(directorio, nombre)

    try:
        os.remove(ruta)
    except FileNotFoundError:
        return False
    except OSError as e:
        raise ErrorRespaldo("No se pudo borrar %s: %s" % (nombre, e))

    return True


def rotar(directorio, conservar=CONSERVAR_POR_DEFECTO):
    """
    Deja solo los N más recientes y devuelve los nombres que se han borrado.

    Con conservar <= 0 no borra nada: se lee como 'no rotar', que es lo que
    espera quien deja el campo a cero, y no como 'bórralos todos'.
    """
    if conservar <= 0:
        return []

    sobrantes = [r["nombre"] for r in listar(directorio)[conservar:]]

    for nombre in sobrantes:
        borrar(directorio, nombre)

    return sobrantes
