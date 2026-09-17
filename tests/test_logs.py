"""
El visor de logs y su botón de «Actualizar».

Existe por un fallo real: pulsar el botón no cambiaba nada en pantalla cuando
el log no había crecido desde la carga anterior, así que parecía averiado. La
petición salía y el servidor respondía 200 —se comprobó en el journal—, pero
devolvía un fragmento idéntico al que ya estaba puesto, y un intercambio
invisible no se distingue de no haber hecho nada.

La regla que falta, y que estas pruebas vigilan: el fragmento dice SIEMPRE a
qué hora se leyó el log, que es lo único que separa «actualizado y sigue
igual» de «el botón no responde».
"""

from datetime import datetime

import pytest


@pytest.fixture
def log_escrito(cfg):
    """Un log con contenido, para que el visor tenga algo que enseñar"""
    with open(cfg.openvpn.log_path, "w", encoding="utf-8") as f:
        f.write("2026-09-17 18:46:30 Initialization Sequence Completed\n")
    return cfg.openvpn.log_path


def test_el_visor_dice_a_que_hora_leyo_el_log(cliente, como_admin, log_escrito):
    respuesta = cliente.get("/logs/contenido")

    assert respuesta.status_code == 200
    assert "Actualizado" in respuesta.text


def test_actualizar_con_el_log_intacto_se_nota_igual(
    cliente, como_admin, log_escrito, monkeypatch
):
    """
    El fallo tal cual lo vio el usuario: dos lecturas seguidas sin que el log
    cambie tienen que dar respuestas distinguibles. Si salen idénticas, el
    botón es invisible y no hay forma de saber que hizo algo.
    """
    horas = iter([
        datetime(2026, 9, 17, 18, 46, 42),
        datetime(2026, 9, 17, 18, 47, 11),
    ])
    monkeypatch.setattr("app.routers.panel._ahora", lambda: next(horas))

    primera = cliente.get("/logs/contenido").text
    segunda = cliente.get("/logs/contenido").text

    assert "18:46:42" in primera
    assert "18:47:11" in segunda
    assert primera != segunda


def test_el_visor_fechado_tambien_cuando_el_filtro_no_encuentra_nada(
    cliente, como_admin, log_escrito
):
    """
    Sin esto quedaría el mismo agujero por otra puerta: con un filtro que no
    casa, el visor enseña «sin líneas» y volvería a ser un fragmento fijo.
    """
    respuesta = cliente.get("/logs/contenido", params={"filtro": "no-existe-jamas"})

    assert respuesta.status_code == 200
    assert "Actualizado" in respuesta.text
