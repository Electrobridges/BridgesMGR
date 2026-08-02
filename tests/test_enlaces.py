"""
Integridad entre plantillas y rutas.

Existe por un fallo real: las pestañas de Auditoría apuntaban a /auditoria
cuando el router lleva prefijo /admin. El panel se veía perfecto y los enlaces
daban 404, porque una URL escrita a mano en una plantilla no la comprueba nadie
—ni Python, ni Jinja, ni el navegador hasta que alguien pulsa.

Esto recorre TODAS las plantillas, saca todos los destinos y comprueba que la
aplicación los reconoce. Sin sesión, una ruta que existe responde 401, 403, 303
o 422; solo una que no existe responde 404. Con eso basta y no hace falta
autenticarse.
"""

import re
from pathlib import Path

import pytest

PLANTILLAS = Path(__file__).resolve().parents[1] / "app" / "templates"

# Qué atributo implica qué método
FUENTES = [
    (r'href="(/[^"#]*)"', "GET"),
    (r'hx-get="(/[^"]*)"', "GET"),
    (r'hx-post="(/[^"]*)"', "POST"),
    (r'action="(/[^"]*)"', "POST"),
]


def _destinos():
    """Todos los (url, método, plantilla) que aparecen en las plantillas"""
    encontrados = []
    for archivo in sorted(PLANTILLAS.rglob("*.html")):
        texto = archivo.read_text(encoding="utf-8")
        for patron, metodo in FUENTES:
            for m in re.finditer(patron, texto):
                url = m.group(1)
                if url.startswith("/static"):
                    continue
                # Un {{ ... }} de Jinja se sustituye por un segmento válido:
                # lo que se comprueba es la forma de la ruta, no el valor.
                prueba = re.sub(r'\{\{[^}]*\}\}', 'x', url).replace("&amp;", "&")
                encontrados.append((prueba, metodo, archivo.name))
    return sorted(set(encontrados))


DESTINOS = _destinos()


def test_hay_destinos_que_comprobar():
    """Si el barrido deja de encontrar nada, la prueba no estaría probando nada"""
    assert len(DESTINOS) > 20


@pytest.mark.parametrize("url,metodo,plantilla", DESTINOS,
                         ids=["%s %s" % (m, u) for u, m, _ in DESTINOS])
def test_el_destino_existe(cliente, url, metodo, plantilla):
    respuesta = cliente.request(metodo, url, follow_redirects=False)

    assert respuesta.status_code != 404, (
        "%s enlaza a %s %s y no hay ninguna ruta que lo atienda" % (plantilla, metodo, url)
    )


# ------------------------------------------------- el diálogo de confirmación

def test_el_script_de_confirmacion_se_sirve(cliente):
    """
    Va en /static y no en línea: la CSP es script-src 'self'.

    Si dejara de servirse, HTMX volvería a su confirm nativo —la guarda de las
    acciones destructivas no se pierde— pero el diálogo del panel sí.
    """
    respuesta = cliente.get("/static/confirmar.js")

    assert respuesta.status_code == 200
    assert "htmx:confirm" in respuesta.text


def test_la_pagina_trae_el_dialogo_y_el_script(como_admin):
    texto = como_admin.get("/clientes").text

    assert 'src="/static/confirmar.js"' in texto
    assert 'id="dialogo-confirmar"' in texto


def test_el_foco_arranca_en_cancelar(como_admin):
    """
    Casi todo lo que pasa por el diálogo es destructivo. Un Intro de más no
    puede ser lo que revoque un certificado.
    """
    import re

    texto = como_admin.get("/clientes").text
    dialogo = re.search(r'<dialog id="dialogo-confirmar".*?</dialog>', texto, re.S).group(0)
    autofocus = re.search(r'<button value="(\w+)"[^>]*autofocus', dialogo)

    assert autofocus and autofocus.group(1) == "no"


def test_las_confirmaciones_siguen_en_las_plantillas(cliente):
    """
    El diálogo sustituye la apariencia del confirm, no la confirmación. Si
    alguien quitara los hx-confirm creyendo que el modal ya los cubre, las
    acciones destructivas pasarían a ejecutarse a la primera.
    """
    destructivas = 0
    for archivo in PLANTILLAS.rglob("*.html"):
        destructivas += archivo.read_text(encoding="utf-8").count("hx-confirm")

    assert destructivas >= 8


# ------------------------------------------- doble disparo de una acción

def _controles_que_mutan():
    """Cada <button> o <form> con hx-post, con su plantilla"""
    encontrados = []
    for archivo in sorted(PLANTILLAS.rglob("*.html")):
        texto = archivo.read_text(encoding="utf-8")
        for m in re.finditer(r'<(button|form)\b[^>]*hx-post="([^"]+)"[^>]*>', texto, re.S):
            encontrados.append((archivo.name, m.group(2), m.group(1), m.group(0)))
    return encontrados


CONTROLES = _controles_que_mutan()


def test_hay_controles_que_comprobar():
    assert len(CONTROLES) > 15


@pytest.mark.parametrize("plantilla,url,etiqueta,bloque", CONTROLES,
                         ids=["%s %s" % (p, u) for p, u, _, _ in CONTROLES])
def test_ninguna_accion_se_puede_disparar_dos_veces(plantilla, url, etiqueta, bloque):
    """
    Todo control que mute tiene que desactivarse mientras la petición vuela.

    No es cosmético. El alta de segundo factor generaba un secreto por clic, y
    el segundo dejaba muerta la cuenta ya guardada en el móvil. 'restaurar' es
    igual de grave: reemite el certificado con una clave privada NUEVA, así que
    un segundo disparo mata el .ovpn que el panel acaba de decirte que
    descargues. hx-confirm no basta —se puede confirmar dos veces.

    Se comprueba en la plantilla y no en el navegador porque es donde se
    olvida: al añadir un botón nuevo copiando otro.
    """
    assert "hx-disabled-elt" in bloque, (
        "%s: el control de %s puede dispararse dos veces seguidas. "
        "Añade hx-disabled-elt=\"%s\"."
        % (plantilla, url, "this" if etiqueta == "button" else "find button")
    )


@pytest.mark.parametrize("plantilla,url,etiqueta,bloque", CONTROLES,
                         ids=["%s %s" % (p, u) for p, u, _, _ in CONTROLES])
def test_el_objetivo_desactivado_es_el_correcto(plantilla, url, etiqueta, bloque):
    """
    En un <form>, desactivar el propio form no hace nada: el atributo disabled
    no existe para <form>. Hay que apuntar a su botón de envío.
    """
    m = re.search(r'hx-disabled-elt="([^"]*)"', bloque)
    assert m, plantilla

    if etiqueta == "form":
        assert "button" in m.group(1), (
            "%s: hx-disabled-elt=\"%s\" en un <form> no desactiva nada. "
            "Usa \"find button\"." % (plantilla, m.group(1))
        )


# ------------------------------- formularios planos, sin HTMX de por medio

def _formularios_planos():
    """<form> sin hx-post: el navegador los envía por su cuenta"""
    encontrados = []
    for archivo in sorted(PLANTILLAS.rglob("*.html")):
        texto = archivo.read_text(encoding="utf-8")
        for m in re.finditer(r'<form\b[^>]*>', texto, re.S):
            bloque = m.group(0)
            if "hx-post" in bloque or 'method="dialog"' in bloque:
                continue
            accion = re.search(r'action="([^"]*)"', bloque)
            encontrados.append((archivo.name, accion.group(1) if accion else "(propia URL)"))
    return encontrados


PLANOS = _formularios_planos()


def test_los_formularios_planos_estan_cubiertos_por_el_script():
    """
    hx-disabled-elt no llega a los formularios de HTML corriente —entrar, el
    código de dos pasos, salir— y ahí el doble envío no es cosmético: en
    /login quema dos de los cinco intentos antes del bloqueo, y en
    /login/codigo el segundo encuentra el paso del TOTP ya consumido, cuenta un
    fallo y responde "Código incorrecto" a un código que era correcto.

    Los cubre confirmar.js escuchando el submit, así que lo que se comprueba es
    que ese manejador siga existiendo y que las páginas donde viven esos
    formularios carguen el script.
    """
    assert PLANOS, "el barrido no encuentra formularios planos: ¿cambió el marcado?"

    script = (Path(__file__).resolve().parents[1] /
              "app" / "static" / "confirmar.js").read_text(encoding="utf-8")

    assert 'addEventListener("submit"' in script
    assert "pageshow" in script, (
        "sin reactivar al volver con el botón de atrás, el navegador puede "
        "restaurar la página con el botón muerto"
    )


@pytest.mark.parametrize("ruta", ["/login"])
def test_las_paginas_sin_sesion_tambien_cargan_el_script(cliente, ruta):
    """
    El login se ve sin haber entrado, así que hereda de base.html igual que el
    resto. Si algún día dejara de heredar, su formulario se quedaría sin
    protección justo donde más duele.
    """
    texto = cliente.get(ruta).text

    assert 'src="/static/confirmar.js"' in texto
    assert "<form" in texto


def test_el_formulario_del_dialogo_no_lo_desactiva_el_script():
    """
    Regresión: el <dialog> de confirmación usa <form method="dialog">, y el
    manejador de submit lo trataba como un formulario normal y desactivaba sus
    botones. Bastaba usar el diálogo una vez para que la siguiente acción
    abriera un cuadro con "Continuar" y "Cancelar" muertos.

    Un method="dialog" no navega: solo cierra el diálogo. No hay doble envío
    del que protegerse.
    """
    script = (Path(__file__).resolve().parents[1] /
              "app" / "static" / "confirmar.js").read_text(encoding="utf-8")

    assert '"dialog"' in script, (
        "confirmar.js debe dejar fuera los <form method=\"dialog\"> o desactiva "
        "los botones de su propio diálogo de confirmación"
    )

    # Y el diálogo tiene que seguir usando method="dialog": es lo que le da el
    # returnValue y el cierre nativo con Escape.
    base = (PLANTILLAS / "base.html").read_text(encoding="utf-8")
    dialogo = re.search(r'<dialog id="dialogo-confirmar".*?</dialog>', base, re.S)
    assert dialogo and 'method="dialog"' in dialogo.group(0)
