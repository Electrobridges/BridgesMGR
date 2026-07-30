"""
Rutas de gestión de clientes VPN.

El helper privilegiado no existe en el entorno de pruebas, así que se sustituye
por dobles. Lo que se comprueba aquí es el comportamiento del panel: validación,
auditoría y traducción de errores.
"""

import pytest

from app import db
from app.core import easyrsa


@pytest.fixture
def helper_falso(monkeypatch):
    """Sustituye las llamadas al helper por respuestas controladas"""
    estado = {
        "validos": ["daniel", "portatil.oficina"],
        "revocados": ["antiguo-becario"],
        "llamadas": [],
        # Qué contraseña recibió cada emisión, para poder comprobar que llega
        # la que se pidió y que no llega ninguna cuando no se pide.
        "claves": {},
    }

    def listar(cfg):
        return {"validos": estado["validos"], "revocados": estado["revocados"]}

    def revocar(cfg, cn):
        estado["llamadas"].append(("revocar", cn))
        estado["validos"].remove(cn)
        estado["revocados"].append(cn)
        return {"ok": True}

    def crear(cfg, cn, clave=None):
        estado["llamadas"].append(("crear", cn))
        estado["claves"][cn] = clave
        estado["validos"].append(cn)
        return {"ok": True}

    def restaurar(cfg, cn, clave=None):
        estado["llamadas"].append(("restaurar", cn))
        estado["claves"][cn] = clave
        estado["revocados"].remove(cn)
        estado["validos"].append(cn)
        return {"ok": True}

    def ovpn(cfg, cn):
        estado["llamadas"].append(("ovpn", cn))
        return "client\nremote vpn.ejemplo.com 1194\n"

    for nombre, doble in [
        ("listar_certificados", listar), ("revocar", revocar), ("crear_cliente", crear),
        ("restaurar", restaurar), ("generar_ovpn", ovpn),
    ]:
        monkeypatch.setattr(easyrsa, nombre, doble)
        # Los routers importan el módulo, no las funciones sueltas, pero
        # panel.py sí importa dos por nombre: hay que parchear allí también
        for modulo in ("app.routers.clientes", "app.routers.panel"):
            import importlib
            mod = importlib.import_module(modulo)
            if hasattr(mod, nombre):
                monkeypatch.setattr(mod, nombre, doble)

    return estado


def test_tabla_lista_validos_y_revocados(como_admin, helper_falso):
    respuesta = como_admin.get("/clientes/tabla")

    assert respuesta.status_code == 200
    assert "daniel" in respuesta.text
    assert "antiguo-becario" in respuesta.text
    assert "revocado" in respuesta.text


def test_crear_cliente(como_admin, csrf_admin, helper_falso):
    respuesta = como_admin.post(
        "/clientes", data={"cn": "nuevo-portatil"}, headers={"X-CSRF-Token": csrf_admin}
    )

    assert respuesta.status_code == 200
    assert ("crear", "nuevo-portatil") in helper_falso["llamadas"]


@pytest.mark.parametrize("cn", ["con espacio", "../../etc/passwd", "cliente;id", "server"])
def test_cn_invalido_no_llega_al_helper(como_admin, csrf_admin, helper_falso, cn):
    """La validación debe cortar ANTES de invocar nada privilegiado"""
    respuesta = como_admin.post(
        "/clientes", data={"cn": cn}, headers={"X-CSRF-Token": csrf_admin}
    )

    assert respuesta.status_code == 400
    assert helper_falso["llamadas"] == []


def test_revocar_audita(como_admin, csrf_admin, helper_falso, cfg):
    respuesta = como_admin.post(
        "/clientes/daniel/revocar", headers={"X-CSRF-Token": csrf_admin}
    )

    assert respuesta.status_code == 200
    assert ("revocar", "daniel") in helper_falso["llamadas"]

    entradas = db.listar_auditoria(cfg.seguridad.db_path)
    assert any(e["accion"] == "revocar" and e["objetivo"] == "daniel"
               and e["resultado"] == "ok" for e in entradas)


def test_error_del_helper_se_muestra_y_audita(como_admin, csrf_admin, helper_falso,
                                              monkeypatch, cfg):
    def revocar_falla(cfg_, cn):
        raise easyrsa.ErrorHelper("easyrsa revoke falló: no such file")

    import app.routers.clientes as rc
    monkeypatch.setattr(rc.easyrsa, "revocar", revocar_falla)

    respuesta = como_admin.post(
        "/clientes/daniel/revocar", headers={"X-CSRF-Token": csrf_admin}
    )

    assert respuesta.status_code == 400
    assert "no such file" in respuesta.text

    entradas = db.listar_auditoria(cfg.seguridad.db_path)
    assert any(e["accion"] == "revocar" and e["resultado"] == "error" for e in entradas)


def test_la_pagina_pinta_el_formulario_sin_oob(como_admin, helper_falso):
    """
    El mismo partial se usa en dos modos y solo uno lleva hx-swap-oob.

    En la página sería un intercambio fuera de banda sin nada que intercambiar;
    el atributo tiene que aparecer solo cuando lo devuelve una acción.
    """
    respuesta = como_admin.get("/clientes")

    assert respuesta.status_code == 200
    assert 'id="form-crear-cliente"' in respuesta.text
    assert "hx-swap-oob" not in respuesta.text


def test_crear_devuelve_el_formulario_vacio(como_admin, csrf_admin, helper_falso):
    """
    Tras crear, la respuesta trae el formulario limpio con hx-swap-oob.

    Sin esto el nombre y las dos contraseñas se quedaban escritos: la del
    certificado a la vista en el navegador, y el botón invitando a crear el
    mismo CN por segunda vez. No se puede resolver con hx-on::after-request
    porque la CSP es script-src 'self' sin unsafe-eval.
    """
    respuesta = como_admin.post(
        "/clientes",
        data={"cn": "nuevo-portatil", "con_clave": "1",
              "clave": "contraseña-larga", "clave2": "contraseña-larga"},
        headers={"X-CSRF-Token": csrf_admin},
    )

    assert respuesta.status_code == 200
    assert 'hx-swap-oob="true"' in respuesta.text
    assert 'id="form-crear-cliente"' in respuesta.text

    # Ningún campo puede volver con lo que se tecleó
    assert "nuevo-portatil" not in respuesta.text.split('id="form-crear-cliente"')[1]
    assert "contraseña-larga" not in respuesta.text


def test_error_al_crear_no_vacia_el_formulario(como_admin, csrf_admin, helper_falso):
    """
    Ante un error, el formulario NO se toca: se conserva lo tecleado.

    Vaciarlo aquí obligaría a reescribir las dos contraseñas por una errata en
    el nombre. Por eso el fragmento va en aviso() y no en error_htmx().
    """
    respuesta = como_admin.post(
        "/clientes",
        data={"cn": "con espacio", "con_clave": "1",
              "clave": "contraseña-larga", "clave2": "contraseña-larga"},
        headers={"X-CSRF-Token": csrf_admin},
    )

    assert respuesta.status_code == 400
    assert "hx-swap-oob" not in respuesta.text


def test_descargar_ovpn(como_admin, helper_falso):
    respuesta = como_admin.get("/clientes/daniel/ovpn")

    assert respuesta.status_code == 200
    assert respuesta.headers["content-disposition"] == 'attachment; filename="daniel.ovpn"'
    assert "remote vpn.ejemplo.com 1194" in respuesta.text


def test_descarga_queda_auditada(como_admin, helper_falso, cfg):
    como_admin.get("/clientes/daniel/ovpn")

    entradas = db.listar_auditoria(cfg.seguridad.db_path)
    assert any(e["accion"] == "descargar_ovpn" and e["objetivo"] == "daniel"
               for e in entradas)


def test_conexiones_informan_el_fallo_del_management(como_admin):
    """
    El puerto de management está cerrado y no hay archivo de status: la tabla
    debe explicar por qué, no fingir que no hay nadie conectado.
    """
    respuesta = como_admin.get("/conexiones/tabla")

    assert respuesta.status_code == 200
    assert "Management interface" in respuesta.text
    assert "no disponible" in respuesta.text


# ------------------------------------- contraseña del certificado de cliente

CLAVE = "contrasena-del-certificado"


def test_crear_con_contrasena_la_pasa_al_helper(como_admin, csrf_admin, helper_falso):
    respuesta = como_admin.post(
        "/clientes",
        data={"cn": "movil", "con_clave": "1", "clave": CLAVE, "clave2": CLAVE},
        headers={"X-CSRF-Token": csrf_admin},
    )

    assert respuesta.status_code == 200
    assert helper_falso["claves"]["movil"] == CLAVE
    assert "cifrada" in respuesta.text


def test_sin_marcar_la_casilla_no_se_cifra(como_admin, csrf_admin, helper_falso):
    """
    Un navegador no envía las casillas sin marcar: la ausencia de 'con_clave'
    tiene que significar 'sin contraseña', no 'usa lo que venga en clave'.
    """
    respuesta = como_admin.post(
        "/clientes",
        data={"cn": "ruter", "clave": CLAVE, "clave2": CLAVE},
        headers={"X-CSRF-Token": csrf_admin},
    )

    assert respuesta.status_code == 200
    assert helper_falso["claves"]["ruter"] is None
    assert "sin contraseña" in respuesta.text


@pytest.mark.parametrize("datos,esperado", [
    ({"con_clave": "1", "clave": "", "clave2": ""}, "no escribiste ninguna"),
    ({"con_clave": "1", "clave": CLAVE, "clave2": "otra-distinta-larga"}, "no coinciden"),
    ({"con_clave": "1", "clave": "corta", "clave2": "corta"}, "al menos 12"),
])
def test_contrasenas_que_no_valen(como_admin, csrf_admin, helper_falso, datos, esperado):
    datos = dict(datos, cn="cliente-nuevo")
    respuesta = como_admin.post(
        "/clientes", data=datos, headers={"X-CSRF-Token": csrf_admin}
    )

    assert respuesta.status_code == 400
    assert esperado in respuesta.text
    assert "cliente-nuevo" not in helper_falso["claves"], "no debió llegar al helper"


def test_la_contrasena_no_queda_en_la_auditoria(como_admin, csrf_admin, helper_falso, cfg):
    """
    Lo que se registra es QUE lleva contraseña, nunca cuál. La auditoría la lee
    cualquier usuario autenticado, incluido un supervisor.
    """
    from app import db

    como_admin.post(
        "/clientes",
        data={"cn": "auditado", "con_clave": "1", "clave": CLAVE, "clave2": CLAVE},
        headers={"X-CSRF-Token": csrf_admin},
    )

    entradas = db.listar_auditoria(cfg.seguridad.db_path)
    texto = " ".join(str(v) for e in entradas for v in e.values())

    assert CLAVE not in texto, "la contraseña del certificado acabó en la auditoría"
    assert any(e["accion"] == "crear_cliente" and "cifrada" in (e["detalle"] or "")
               for e in entradas)


def test_restaurar_tambien_admite_contrasena(como_admin, csrf_admin, helper_falso):
    """Reemite una clave privada nueva, así que hay que volver a decidirlo"""
    respuesta = como_admin.post(
        "/clientes/antiguo-becario/restaurar",
        data={"con_clave": "1", "clave": CLAVE, "clave2": CLAVE},
        headers={"X-CSRF-Token": csrf_admin},
    )

    assert respuesta.status_code == 200
    assert helper_falso["claves"]["antiguo-becario"] == CLAVE
