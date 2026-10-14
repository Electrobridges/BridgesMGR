"""
Aplicación de las políticas por cliente: de la base al servidor.

La base del panel es la fuente de verdad, y el archivo que lee OpenVPN es una
copia que escribe el helper. Para que no diverjan, cada cambio se aplica
PRIMERO en el servidor y solo se guarda si el helper lo acepta: así un fallo
—una IP dentro del pool, nftables sin instalar— deja todo como estaba en vez de
dejar en la base una política que el servidor no está aplicando.
"""

from . import db
from .core import easyrsa
from .core import politicas as pol


def documento(cfg, cambios=None, max_global=None):
    """
    El documento entero que se le pasa al helper.

    'cambios' son las políticas que se quieren guardar ({cn: politica}) y se
    superponen a las de la base. 'max_global' sustituye a la del ajuste.
    """
    ruta = cfg.seguridad.db_path
    todas = db.listar_politicas(ruta)
    todas.update(cambios or {})
    if max_global is None:
        max_global = db.max_sesion_global(ruta)
    return pol.documento(todas, max_global)


def aplicar(cfg, cambios=None, max_global=None, usuario=None):
    """
    Aplica en el servidor y, si sale bien, guarda en la base.

    Lanza pol.PoliticaInvalida si algo no valida en el panel y
    easyrsa.ErrorHelper si lo rechaza el helper, con su motivo.
    """
    doc = documento(cfg, cambios, max_global)
    resultado = easyrsa.aplicar_politicas(cfg, doc)

    ruta = cfg.seguridad.db_path
    for cn, politica in (cambios or {}).items():
        db.guardar_politica(ruta, cn, pol.normalizar(politica), usuario)
    if max_global is not None:
        db.guardar_ajuste(ruta, db.AJUSTE_MAX_SESION, str(max_global))

    return resultado


def reaplicar(cfg):
    """
    Vuelve a escribir en el servidor lo que dice la base, sin cambiar nada.

    Lo hace el vigilante al arrancar: después de reconstruir el servidor o de
    restaurar un respaldo de la base, el archivo de OpenVPN puede no coincidir
    con lo que el panel enseña. Sin políticas no se llama al helper, para no
    crear archivos en una instalación que no usa esto.
    """
    if not db.listar_politicas(cfg.seguridad.db_path) and \
            not db.max_sesion_global(cfg.seguridad.db_path):
        return None
    return easyrsa.aplicar_politicas(cfg, documento(cfg))
