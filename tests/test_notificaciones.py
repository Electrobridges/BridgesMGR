"""
Notificaciones por correo y Discord.

Es la primera parte del panel que sale a internet, así que lo que más se
comprueba aquí no es que llegue el mensaje sino tres cosas que lo rodean:

- que un canal caído NO tumbe la acción que lo provocó,
- que nada sensible salga en el texto,
- y la regla del aviso previo: apagar la vigilancia manda antes el aviso de
  que se está apagando, por el canal que se apaga.

Nada de esto abre un socket: los transportes se sustituyen por dobles.
"""

import pytest

from app import db, notificar
from app.core import notificaciones


@pytest.fixture
def enviados(monkeypatch):
    """Captura lo que se habría enviado, sin tocar la red"""
    caja = {"correo": [], "discord": [], "fallar": set()}

    def correo(cfg_correo, asunto, cuerpo):
        if "correo" in caja["fallar"]:
            raise notificaciones.ErrorNotificacion("SMTP: conexión rechazada")
        caja["correo"].append((asunto, cuerpo))
        return 1

    def discord(webhook, titulo, cuerpo, color=None):
        if "discord" in caja["fallar"]:
            raise notificaciones.ErrorNotificacion("Discord respondió 404")
        caja["discord"].append((titulo, cuerpo))
        return 1

    monkeypatch.setattr(notificaciones, "enviar_correo", correo)
    monkeypatch.setattr(notificaciones, "enviar_discord", discord)
    return caja


@pytest.fixture
def con_destinos(cfg, usuarios):
    """Rellena el YAML como si hubiera destinos configurados"""
    cfg.notificaciones.correo.servidor = "smtp.ejemplo.com"
    cfg.notificaciones.correo.destinatarios = ["admin@ejemplo.com"]
    cfg.notificaciones.discord.webhook = "https://discord.com/api/webhooks/x/y"
    return cfg


def _todo_encendido(cfg):
    notificar.guardar_ajustes(cfg.seguridad.db_path, True, True,
                              set(notificar.CATEGORIAS))


# ------------------------------------------------------------- la política

def test_por_defecto_no_avisa_de_nada(con_destinos, enviados):
    """Se enciende a mano: nadie quiere que un panel recién instalado escriba"""
    notificar.avisar(con_destinos, notificar.CERTIFICADOS, "x", "y")
    notificar._cola.join() if notificar._cola else None

    assert enviados["correo"] == []
    assert enviados["discord"] == []


def test_sin_destino_en_el_yaml_no_se_envia(cfg, usuarios, enviados):
    """Un canal encendido sin servidor configurado no manda a ninguna parte"""
    _todo_encendido(cfg)

    assert notificar.avisar(cfg, notificar.CERTIFICADOS, "x", "y") is False


def test_una_categoria_apagada_no_avisa(con_destinos, enviados):
    notificar.guardar_ajustes(con_destinos.seguridad.db_path, True, True,
                              {notificar.SEGURIDAD})

    assert notificar.avisar(con_destinos, notificar.CERTIFICADOS, "x", "y") is False
    assert notificar.avisar(con_destinos, notificar.SEGURIDAD, "x", "y") is True


@pytest.mark.parametrize("accion,esperada", [
    ("revocar", notificar.CERTIFICADOS),
    ("crear_cliente", notificar.CERTIFICADOS),
    ("cambiar_rol_panel", notificar.SEGURIDAD),
    ("borrar_usuario_panel", notificar.SEGURIDAD),
    ("logout", None),
    ("cerrar_reparto", None),
])
def test_el_mapa_de_acciones(accion, esperada):
    assert notificar.categoria_de(accion, "ok") == esperada


def test_un_login_correcto_no_avisa_pero_uno_fallido_si():
    """El correcto sería el grueso del ruido; el fallido es la primera señal"""
    assert notificar.categoria_de("login", "ok") is None
    assert notificar.categoria_de("login", "error") == notificar.SEGURIDAD


# --------------------------------------------------- no tumbar la acción

def test_un_canal_caido_no_rompe_la_accion(como_admin, csrf_admin, con_destinos,
                                           enviados, monkeypatch):
    """
    Revocar tiene que seguir funcionando con el correo muerto. Si notificar
    pudiera tumbar la acción, la función de vigilancia se convertiría en un
    punto único de fallo del panel entero.
    """
    from app.core import easyrsa
    import app.routers.clientes as rc

    monkeypatch.setattr(rc.easyrsa, "revocar", lambda c, cn: {"ok": True})
    monkeypatch.setattr(rc.easyrsa, "listar_certificados",
                        lambda c: {"validos": ["daniel"], "revocados": []})
    _todo_encendido(con_destinos)
    enviados["fallar"] = {"correo", "discord"}

    respuesta = como_admin.post("/clientes/daniel/revocar",
                                headers={"X-CSRF-Token": csrf_admin})

    assert respuesta.status_code == 200


def test_el_fallo_de_entrega_queda_en_la_auditoria(con_destinos, enviados):
    """Nada se silencia: si no se pudo entregar, consta"""
    _todo_encendido(con_destinos)
    enviados["fallar"] = {"correo", "discord"}

    notificar.avisar_ahora(con_destinos, {"correo": True, "discord": True},
                           "prueba", "cuerpo")

    entradas = db.listar_auditoria(con_destinos.seguridad.db_path)
    assert any(e["accion"] == "notificar" and e["resultado"] == "error"
               for e in entradas)


# ------------------------------------------- la regla del aviso previo

def test_apagar_un_canal_avisa_antes_por_ese_canal(como_admin, csrf_admin,
                                                   con_destinos, enviados):
    """
    La pieza que sostiene todo el diseño.

    Los destinos viven en el YAML, que el panel no puede escribir, así que un
    atacante no puede desviar las alertas. Pero sí podría callarlas desde aquí,
    y por eso el último mensaje que sale por un canal es el que dice que lo
    están apagando.
    """
    _todo_encendido(con_destinos)

    respuesta = como_admin.post(
        "/configuracion/notificaciones",
        data={"eventos": list(notificar.CATEGORIAS)},   # sin 'correo' ni 'discord'
        headers={"X-CSRF-Token": csrf_admin},
    )

    assert respuesta.status_code == 200
    assert len(enviados["correo"]) == 1
    assert len(enviados["discord"]) == 1

    _, cuerpo = enviados["correo"][0]
    assert "reduce" in cuerpo.lower() or "reducir" in cuerpo.lower()
    assert "Canales apagados" in cuerpo
    assert "último aviso" in cuerpo

    # Y solo después se guarda
    canales = notificar.canales_activos(con_destinos.seguridad.db_path)
    assert canales == {"correo": False, "discord": False}


def test_quitar_una_categoria_tambien_avisa(como_admin, csrf_admin,
                                            con_destinos, enviados):
    _todo_encendido(con_destinos)

    como_admin.post(
        "/configuracion/notificaciones",
        data={"correo": "1", "discord": "1", "eventos": [notificar.SEGURIDAD]},
        headers={"X-CSRF-Token": csrf_admin},
    )

    assert enviados["correo"], "quitar categorías debe avisar igual que apagar un canal"
    _, cuerpo = enviados["correo"][0]
    assert "dejan de avisar" in cuerpo


def test_encender_mas_cosas_no_dispara_el_aviso(como_admin, csrf_admin,
                                                con_destinos, enviados):
    """Solo avisa lo que REDUCE la vigilancia. Ampliarla no es sospechoso."""
    notificar.guardar_ajustes(con_destinos.seguridad.db_path, False, False, set())

    como_admin.post(
        "/configuracion/notificaciones",
        data={"correo": "1", "discord": "1", "eventos": list(notificar.CATEGORIAS)},
        headers={"X-CSRF-Token": csrf_admin},
    )

    assert enviados["correo"] == []
    assert enviados["discord"] == []


def test_si_el_aviso_previo_no_sale_se_dice(como_admin, csrf_admin,
                                            con_destinos, enviados):
    """Guardar no se impide, pero no puede parecer que el aviso salió"""
    _todo_encendido(con_destinos)
    enviados["fallar"] = {"correo", "discord"}

    respuesta = como_admin.post(
        "/configuracion/notificaciones",
        data={"eventos": list(notificar.CATEGORIAS)},
        headers={"X-CSRF-Token": csrf_admin},
    )

    assert "no pudo entregarse" in respuesta.text


def test_un_supervisor_no_toca_los_ajustes(como_supervisor, csrf_supervisor,
                                           con_destinos):
    respuesta = como_supervisor.post(
        "/configuracion/notificaciones",
        data={"correo": "1"},
        headers={"X-CSRF-Token": csrf_supervisor},
    )

    assert respuesta.status_code == 403


# --------------------------------------------------------- el transporte

def test_discord_exige_https():
    """Un webhook en claro mandaría el aviso —y su contenido— sin cifrar"""
    with pytest.raises(notificaciones.ErrorNotificacion):
        notificaciones.enviar_discord("http://discord.com/x", "t", "c")


def test_sin_destinatarios_el_correo_falla_claro():
    from app.config import CorreoCfg

    with pytest.raises(notificaciones.ErrorNotificacion) as e:
        notificaciones.enviar_correo(CorreoCfg(servidor="x"), "a", "b")

    assert "destinatarios" in str(e.value)


def test_el_cuerpo_no_lleva_secretos(con_destinos, enviados, como_admin,
                                     csrf_admin, monkeypatch):
    """
    Lo que sale por el canal es el suceso, nunca material sensible: ni claves,
    ni contenido de .ovpn, ni la clave tls-crypt.
    """
    import app.routers.clientes as rc

    monkeypatch.setattr(rc.easyrsa, "crear_cliente", lambda c, cn, clave=None: {"ok": True})
    monkeypatch.setattr(rc.easyrsa, "listar_certificados",
                        lambda c: {"validos": [], "revocados": []})
    _todo_encendido(con_destinos)

    como_admin.post("/clientes", data={"cn": "nuevo", "con_clave": "1",
                                       "clave": "secreto-larguisimo",
                                       "clave2": "secreto-larguisimo"},
                    headers={"X-CSRF-Token": csrf_admin})
    if notificar._cola:
        notificar._cola.join()

    todo = " ".join(c for _, c in enviados["correo"]) + \
           " ".join(c for _, c in enviados["discord"])
    assert "secreto-larguisimo" not in todo
    assert "BEGIN" not in todo


# --------------------------------------------------- el aviso de prueba

def test_la_prueba_usa_los_canales_configurados_aunque_esten_apagados(
        como_admin, csrf_admin, con_destinos, enviados):
    """
    Lo normal es querer comprobar el destino ANTES de encender el canal. Si la
    prueba solo usara los activos, habría que encenderlo a ciegas primero.
    """
    notificar.guardar_ajustes(con_destinos.seguridad.db_path, False, False, set())

    respuesta = como_admin.post("/configuracion/notificaciones/probar",
                                headers={"X-CSRF-Token": csrf_admin})

    assert respuesta.status_code == 200
    assert len(enviados["correo"]) == 1
    assert len(enviados["discord"]) == 1
    assert "prueba" in enviados["discord"][0][1].lower()


def test_sin_destinos_la_prueba_dice_donde_configurarlos(como_admin, csrf_admin,
                                                         cfg, usuarios, enviados):
    respuesta = como_admin.post("/configuracion/notificaciones/probar",
                                headers={"X-CSRF-Token": csrf_admin})

    assert respuesta.status_code == 400
    assert "config.yaml" in respuesta.text


def test_la_prueba_enseña_el_error_del_canal(como_admin, csrf_admin,
                                             con_destinos, enviados):
    """El motivo exacto, no un 'no se pudo': es lo que permite arreglarlo"""
    enviados["fallar"] = {"correo", "discord"}

    respuesta = como_admin.post("/configuracion/notificaciones/probar",
                                headers={"X-CSRF-Token": csrf_admin})

    assert respuesta.status_code == 400
    assert "SMTP" in respuesta.text or "Discord" in respuesta.text


def test_un_canal_bien_y_otro_mal_se_distinguen(como_admin, csrf_admin,
                                                con_destinos, enviados):
    enviados["fallar"] = {"correo"}

    respuesta = como_admin.post("/configuracion/notificaciones/probar",
                                headers={"X-CSRF-Token": csrf_admin})

    assert respuesta.status_code == 200
    assert "discord" in respuesta.text
    assert "SMTP" in respuesta.text


def test_la_prueba_queda_auditada(como_admin, csrf_admin, con_destinos, enviados, ):
    como_admin.post("/configuracion/notificaciones/probar",
                    headers={"X-CSRF-Token": csrf_admin})

    entradas = db.listar_auditoria(con_destinos.seguridad.db_path)
    assert any(e["accion"] == "probar_notificaciones" for e in entradas)


def test_un_supervisor_no_puede_lanzarla(como_supervisor, csrf_supervisor,
                                         con_destinos, enviados):
    respuesta = como_supervisor.post("/configuracion/notificaciones/probar",
                                     headers={"X-CSRF-Token": csrf_supervisor})

    assert respuesta.status_code == 403
    assert enviados["discord"] == []
