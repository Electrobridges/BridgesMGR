"""
Transporte de las notificaciones: correo y Discord.

Solo el envío. Qué se manda y cuándo lo decide app/notificar.py; aquí no se
consulta la base ni se sabe nada de ajustes, para que esto se pruebe sin
levantar la web.

Sin dependencias nuevas: `smtplib` y `urllib.request` son de la biblioteca
estándar. Importa, porque este proyecto tiene una sola dependencia externa
aparte del marco web y no compensa gastar la segunda en esto.

**Es el primer código del panel que abre una conexión a internet.** Hasta ahora
solo hablaba con 127.0.0.1, con el disco y con sudo. Eso cambia el modelo de
amenaza: si alguien compromete el panel, gana una vía de salida que antes no
existía. De ahí tres reglas que no se relajan:

1. Tiempo de espera corto y siempre puesto. Un SMTP que no responde no puede
   dejar colgado un hilo del panel.
2. Nunca sale material sensible. Ni claves, ni contenido de .ovpn, ni la clave
   tls-crypt: solo el texto del suceso.
3. Los fallos se devuelven, no se tragan. Quien llama decide qué hacer con
   ellos, pero se entera.
"""

import json
import smtplib
import ssl
import urllib.error
import urllib.request
from email.message import EmailMessage

# Corto a propósito: esto corre detrás de una acción del usuario y no puede
# convertirse en una espera.
TIMEOUT = 10

# Discord corta los mensajes largos; se recorta aquí y se dice que se recortó.
MAX_DISCORD = 1900


class ErrorNotificacion(Exception):
    """No se pudo entregar. Lleva el motivo para que se pueda enseñar."""


def enviar_correo(cfg_correo, asunto, cuerpo):
    """
    Envía por SMTP. Devuelve el número de destinatarios.

    STARTTLS por defecto; con puerto 465 se usa SSL directo, que es lo que
    espera ese puerto. Sin usuario configurado no se autentica: hay relés de
    red local que no lo piden.
    """
    destinatarios = [d for d in (cfg_correo.destinatarios or []) if d]
    if not destinatarios:
        raise ErrorNotificacion("No hay destinatarios de correo configurados")
    if not cfg_correo.servidor:
        raise ErrorNotificacion("No hay servidor SMTP configurado")

    mensaje = EmailMessage()
    mensaje["Subject"] = asunto
    mensaje["From"] = cfg_correo.desde or (cfg_correo.usuario or "ovpn-web@localhost")
    mensaje["To"] = ", ".join(destinatarios)
    mensaje.set_content(cuerpo)

    try:
        if int(cfg_correo.puerto) == 465:
            contexto = ssl.create_default_context()
            with smtplib.SMTP_SSL(cfg_correo.servidor, int(cfg_correo.puerto),
                                  timeout=TIMEOUT, context=contexto) as s:
                if cfg_correo.usuario:
                    s.login(cfg_correo.usuario, cfg_correo.password or "")
                s.send_message(mensaje)
        else:
            with smtplib.SMTP(cfg_correo.servidor, int(cfg_correo.puerto),
                              timeout=TIMEOUT) as s:
                if cfg_correo.tls:
                    s.starttls(context=ssl.create_default_context())
                if cfg_correo.usuario:
                    s.login(cfg_correo.usuario, cfg_correo.password or "")
                s.send_message(mensaje)
    except (smtplib.SMTPException, OSError, ssl.SSLError) as e:
        raise ErrorNotificacion("SMTP: %s" % e)

    return len(destinatarios)


def enviar_discord(webhook, titulo, cuerpo, color=None):
    """
    Publica en un webhook de Discord.

    La URL del webhook ES la credencial: quien la tenga puede escribir en ese
    canal. Por eso vive en config.yaml, que el panel puede leer y no escribir.

    Se manda como 'embed' para que el título quede separado del cuerpo, y no
    con contenido suelto: un mensaje plano de varias líneas se lee peor en el
    móvil, que es donde se leen estas cosas.
    """
    if not webhook:
        raise ErrorNotificacion("No hay webhook de Discord configurado")
    if not webhook.startswith("https://"):
        raise ErrorNotificacion("El webhook de Discord debe ser una URL https")

    texto = cuerpo if len(cuerpo) <= MAX_DISCORD else (
        cuerpo[:MAX_DISCORD] + "\n… (recortado)"
    )

    carga = json.dumps({
        "embeds": [{
            "title": titulo,
            "description": texto,
            **({"color": color} if color is not None else {}),
        }]
    }).encode("utf-8")

    peticion = urllib.request.Request(
        webhook,
        data=carga,
        headers={"Content-Type": "application/json",
                 "User-Agent": "ovpn-web-panel"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(peticion, timeout=TIMEOUT) as r:
            # Discord responde 204 sin cuerpo cuando acepta
            if r.status >= 300:
                raise ErrorNotificacion("Discord respondió %d" % r.status)
    except urllib.error.HTTPError as e:
        raise ErrorNotificacion("Discord respondió %d" % e.code)
    except (urllib.error.URLError, OSError) as e:
        raise ErrorNotificacion("Discord: %s" % e)

    return 1
