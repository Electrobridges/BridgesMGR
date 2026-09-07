"""
Política de notificaciones: qué se avisa, por dónde y cuándo.

El envío en sí vive en core/notificaciones.py. Aquí se decide, se limita el
ritmo y se saca del camino del usuario.

Reparto deliberado entre los dos sitios donde se configura:

- **Los destinos van en config.yaml**, que es root:ovpnweb 0640: el panel lo lee
  y no lo escribe. Quien comprometa el panel no puede redirigir las alertas a su
  propio buzón ni a su propio canal.
- **Los interruptores van en la tabla `ajustes`**, editables desde el panel, para
  no exigir SSH cada vez que alguien quiere dejar de recibir una categoría.

Y el hueco que deja eso —un atacante podría callar las alertas— se cierra con
la regla del aviso previo: apagar un canal o una categoría **manda primero el
aviso de que se está apagando, por el canal que se apaga**, y solo después lo
guarda. El último mensaje que sale por ahí es el que delata que lo callaron.
"""

import queue
import threading

from . import db
from .core import notificaciones

# Categorías de suceso. Cadenas fijas: se guardan en `ajustes` y se comparan
# con lo que llega del formulario, así que no pueden ser texto libre.
SEGURIDAD = "seguridad"
CERTIFICADOS = "certificados"
SERVICIO = "servicio"
RECHAZOS = "rechazos"

CATEGORIAS = {
    SEGURIDAD: "Seguridad del panel",
    CERTIFICADOS: "Certificados y CA",
    SERVICIO: "Salud del servicio",
    RECHAZOS: "Rechazos de conexión a la VPN",
}

# Qué acción auditada cae en qué categoría. Lo que no está aquí no notifica:
# la lista es explícita para que añadir una acción nueva no empiece a llenar
# buzones sin que nadie lo haya decidido.
#
# Fuera quedan a propósito 'login' y 'logout' correctos —serían el grueso del
# ruido y no dicen nada— y 'cerrar_reparto', que es administrativo. Un login
# FALLIDO sí entra, porque es la primera señal de que alguien lo intenta.
ACCIONES = {
    # Seguridad del panel: cambia quién manda o cómo se entra
    "crear_usuario_panel": SEGURIDAD,
    "borrar_usuario_panel": SEGURIDAD,
    "cambiar_rol_panel": SEGURIDAD,
    "cambiar_password_panel": SEGURIDAD,
    "activar_usuario_panel": SEGURIDAD,
    "totp_restablecer": SEGURIDAD,
    "politica_totp_supervisor": SEGURIDAD,

    # Los datos del panel saliendo o desapareciendo. 'crear_respaldo' queda
    # fuera aposta: es lo único de esta lista que no resta nada, y avisar de
    # cada copia sería el correo diario que enseña a ignorar los demás.
    "exportar_datos": SEGURIDAD,
    "limpiar_base": SEGURIDAD,
    "borrar_respaldo": SEGURIDAD,
    "ajustar_respaldos": SEGURIDAD,

    # Certificados: cambia quién puede entrar en la VPN
    "crear_cliente": CERTIFICADOS,
    "revocar": CERTIFICADOS,
    "restaurar": CERTIFICADOS,
    "archivar": CERTIFICADOS,
    "desarchivar": CERTIFICADOS,
    "descargar_ovpn": CERTIFICADOS,
    "desconectar": CERTIFICADOS,
}

# Acciones que solo avisan cuando salen mal. Un login correcto es ruido; uno
# fallido es la primera señal de que alguien lo está intentando.
SOLO_SI_FALLA = {"login": SEGURIDAD}

# Lo que se considera grave y sale en rojo
GRAVES = {"revocar", "borrar_usuario_panel", "cambiar_rol_panel",
          "totp_restablecer", "designar_superusuario",
          # Destruyen registro o lo sacan del servidor: si alguien lo hace sin
          # haberlo acordado, el aviso tiene que llegar como los demás graves.
          "limpiar_base", "borrar_respaldo", "exportar_datos"}


def categoria_de(accion, resultado):
    if resultado != "ok" and accion in SOLO_SI_FALLA:
        return SOLO_SI_FALLA[accion]
    if resultado != "ok" and accion in ACCIONES:
        return ACCIONES[accion]
    if resultado == "ok":
        return ACCIONES.get(accion)
    return None


# Claves en la tabla `ajustes`
AJUSTE_CORREO = "notif_correo"
AJUSTE_DISCORD = "notif_discord"
AJUSTE_EVENTOS = "notif_eventos"

# Color del embed de Discord por gravedad
COLOR_AVISO = 0xFBBF24
COLOR_ALERTA = 0xF87171

# La cola es acotada: si el panel genera avisos más rápido de lo que el correo
# los traga —un ataque de fuerza bruta, por ejemplo— es mejor descartar y
# decirlo que hinchar la memoria del proceso.
MAX_COLA = 200

_cola = None
_hilo = None
_arranque = threading.Lock()


# ------------------------------------------------------------- ajustes

def canales_activos(ruta):
    return {
        "correo": db.obtener_ajuste(ruta, AJUSTE_CORREO, "no") == "si",
        "discord": db.obtener_ajuste(ruta, AJUSTE_DISCORD, "no") == "si",
    }


def eventos_activos(ruta):
    """Las categorías marcadas. Por defecto ninguna: esto se enciende a mano."""
    guardado = db.obtener_ajuste(ruta, AJUSTE_EVENTOS, "")
    return {c for c in guardado.split(",") if c in CATEGORIAS}


def guardar_ajustes(ruta, correo, discord, eventos):
    db.guardar_ajuste(ruta, AJUSTE_CORREO, "si" if correo else "no")
    db.guardar_ajuste(ruta, AJUSTE_DISCORD, "si" if discord else "no")
    db.guardar_ajuste(ruta, AJUSTE_EVENTOS,
                      ",".join(sorted(c for c in eventos if c in CATEGORIAS)))


def configurado(cfg, canal):
    """¿Hay destino para ese canal en el YAML? Sin él, activarlo no sirve."""
    n = cfg.notificaciones
    if canal == "correo":
        return bool(n.correo.servidor and [d for d in n.correo.destinatarios if d])
    return bool(n.discord.webhook)


# --------------------------------------------------------- envío diferido

def _trabajador():
    """
    Vacía la cola en segundo plano.

    Fuera del hilo que atiende la petición a propósito: un SMTP que tarda diez
    segundos no puede sumarse al tiempo que espera quien acaba de revocar un
    certificado. Los fallos se registran en la auditoría, que es donde se
    pueden consultar después; nada se traga en silencio.
    """
    while True:
        tarea = _cola.get()
        try:
            _entregar(*tarea)
        except Exception:  # noqa: BLE001 - un fallo aquí no puede matar el hilo
            pass
        finally:
            _cola.task_done()


def _asegurar_hilo():
    global _cola, _hilo
    with _arranque:
        if _cola is None:
            _cola = queue.Queue(maxsize=MAX_COLA)
        if _hilo is None or not _hilo.is_alive():
            _hilo = threading.Thread(target=_trabajador, name="notificaciones",
                                     daemon=True)
            _hilo.start()


def _entregar(cfg, canales, asunto, cuerpo, grave, ruta_db):
    fallos = []
    enviados = []

    if canales.get("correo"):
        try:
            notificaciones.enviar_correo(cfg.notificaciones.correo, asunto, cuerpo)
            enviados.append("correo")
        except notificaciones.ErrorNotificacion as e:
            fallos.append("correo: %s" % e)

    if canales.get("discord"):
        try:
            notificaciones.enviar_discord(
                cfg.notificaciones.discord.webhook, asunto, cuerpo,
                COLOR_ALERTA if grave else COLOR_AVISO,
            )
            enviados.append("discord")
        except notificaciones.ErrorNotificacion as e:
            fallos.append("discord: %s" % e)

    # Solo se audita lo que falla, y los envíos correctos no: si no, cada aviso
    # generaría una entrada de auditoría, y avisar de una revocación acabaría
    # duplicando el historial que se quiere vigilar.
    if fallos and ruta_db:
        db.registrar(ruta_db, usuario=None, accion="notificar", objetivo=asunto,
                     resultado="error", detalle="; ".join(fallos))

    return enviados, fallos


def avisar(cfg, categoria, asunto, cuerpo, grave=False):
    """
    Encola un aviso si esa categoría y algún canal están activos.

    No lanza nunca: notificar es un efecto secundario de una acción del panel y
    no puede tumbarla. Si el correo está caído, revocar un certificado tiene
    que seguir funcionando; el fallo queda en la auditoría.
    """
    ruta = cfg.seguridad.db_path

    try:
        if categoria not in eventos_activos(ruta):
            return False
        canales = {c: a and configurado(cfg, c)
                   for c, a in canales_activos(ruta).items()}
        if not any(canales.values()):
            return False
    except Exception:  # noqa: BLE001
        return False

    _asegurar_hilo()
    try:
        _cola.put_nowait((cfg, canales, asunto, cuerpo, grave, ruta))
        return True
    except queue.Full:
        db.registrar(ruta, usuario=None, accion="notificar", objetivo=asunto,
                     resultado="error", detalle="cola de notificaciones llena")
        return False


def avisar_ahora(cfg, canales, asunto, cuerpo, grave=False):
    """
    Envía sin pasar por la cola y devuelve (enviados, fallos).

    Existe para la regla del aviso previo: al apagar un canal hay que mandar el
    aviso **por ese canal y antes de guardar el cambio**, y para eso hace falta
    saber si salió. Es el único caso en el que esperar al envío está
    justificado, porque quien lo desactiva merece saber si el aviso llegó.
    """
    return _entregar(cfg, canales, asunto, cuerpo, grave, cfg.seguridad.db_path)


def aviso_de_apagado(cfg, usuario, ip, antes, ahora):
    """
    Texto del aviso previo a recortar la vigilancia.

    Se manda por los canales que estaban activos ANTES del cambio, no por los
    que quedan: si se apagan los dos, este mensaje es el último que sale.
    """
    lineas = [
        "Alguien acaba de reducir las notificaciones de este panel.",
        "",
        "Usuario: %s" % (usuario or "?"),
        "Desde:   %s" % (ip or "?"),
        "",
    ]

    apagados = [c for c in ("correo", "discord") if antes.get(c) and not ahora.get(c)]
    if apagados:
        lineas.append("Canales apagados: %s" % ", ".join(apagados))

    quitadas = sorted(antes.get("eventos", set()) - ahora.get("eventos", set()))
    if quitadas:
        lineas.append("Categorías que dejan de avisar: %s"
                      % ", ".join(CATEGORIAS.get(c, c) for c in quitadas))

    lineas += [
        "",
        "Si no has sido tú, este es el último aviso que vas a recibir por esta vía.",
    ]
    return "\n".join(lineas)
