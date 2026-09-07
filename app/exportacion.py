"""
Exportación descargable de lo que se puede mirar fuera del servidor.

Es lo contrario de un respaldo, y por eso son dos cosas distintas:

- El **respaldo** (app/respaldar.py) es la base entera —hashes de contraseñas,
  secretos TOTP, tokens de sesión— y **no se descarga desde el panel**. Se
  queda en el servidor.
- La **exportación** es esto: la auditoría y el historial de perfiles
  retirados, en CSV, para abrirlos en una hoja de cálculo. Nada de secretos, y
  por eso sí baja por HTTP.

La lista de lo que entra es explícita, tabla por tabla y columna por columna.
Si mañana alguien añade una columna con algo delicado a una tabla exportada, no
se cuela sola en el ZIP: hay que venir aquí a nombrarla.
"""

import csv
import io
import zipfile
from datetime import datetime

from . import db

# Qué se exporta. Columnas nombradas una a una: un 'SELECT *' convertiría
# cualquier columna futura en algo que sale del servidor sin que nadie lo
# decida.
COLUMNAS_AUDITORIA = ("id", "ts", "usuario", "accion", "objetivo", "resultado",
                      "detalle", "ip")
COLUMNAS_ARCHIVADOS = ("cn", "archivado", "por")

LEEME = """\
Exportación de BridgesMGR
=========================

Generada: %s

Qué lleva
---------
auditoria.csv            Acciones registradas en el panel: quién hizo qué,
                         cuándo, desde qué IP y con qué resultado.
clientes-archivados.csv  Perfiles retirados de la lista activa, con la fecha y
                         quién los retiró. El certificado sigue revocado en la
                         PKI; esto es solo estado del panel.

Qué NO lleva
------------
Ni contraseñas ni sus hashes, ni secretos de segundo factor, ni tokens de
sesión, ni certificados, ni claves, ni la configuración del servidor.

Esto no es un respaldo y no sirve para restaurar nada. Los respaldos de la base
se quedan en el servidor, en el directorio de respaldos, y se recogen por SSH.

Los archivos van en UTF-8 con BOM, para que una hoja de cálculo respete los
acentos al abrirlos con doble clic.
"""


def nombre_archivo(ahora=None):
    """ovpn-web-export-AAAAMMDD-HHMMSS.zip"""
    ahora = ahora or datetime.now()
    return "ovpn-web-export-%s.zip" % ahora.strftime("%Y%m%d-%H%M%S")


def _csv(columnas, filas):
    """
    Un CSV en bytes, en UTF-8 con BOM.

    El BOM es por Excel: sin él abre el archivo en la codificación del sistema
    y los acentos de la columna 'detalle' salen rotos. LibreOffice y pandas lo
    ignoran, así que no molesta a nadie.
    """
    buffer = io.StringIO()
    escritor = csv.writer(buffer, lineterminator="\n")
    escritor.writerow(columnas)

    for fila in filas:
        escritor.writerow([fila.get(c, "") if fila.get(c) is not None else ""
                           for c in columnas])

    return buffer.getvalue().encode("utf-8-sig")


def construir(ruta_db, ahora=None):
    """
    Devuelve (nombre, bytes) del ZIP listo para descargar.

    Se arma en memoria: son unos pocos miles de filas de texto, y escribirlo a
    disco obligaría a limpiar un temporal que, si algo falla a media descarga,
    se quedaría ahí con datos de auditoría dentro.
    """
    ahora = ahora or datetime.now()

    paquete = io.BytesIO()
    with zipfile.ZipFile(paquete, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("auditoria.csv",
                    _csv(COLUMNAS_AUDITORIA, db.volcar_auditoria(ruta_db)))
        zf.writestr("clientes-archivados.csv",
                    _csv(COLUMNAS_ARCHIVADOS, db.listar_archivados(ruta_db)))
        zf.writestr("LEEME.txt",
                    (LEEME % ahora.strftime("%Y-%m-%d %H:%M:%S")).encode("utf-8"))

    return nombre_archivo(ahora), paquete.getvalue()
