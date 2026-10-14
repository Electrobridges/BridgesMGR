"""
Políticas por cliente desde el panel: formulario, rutas, vigilante y los
sucesos nuevos del historial de la VPN.

El helper no existe aquí: se sustituye por un doble que guarda el documento
que habría recibido, que es justo lo que interesa comprobar.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app import db, eventos, notificar, vigilante
from app.core import easyrsa, eventos_vpn, mgmt
from app.core import politicas as pol

DIRECTIVAS = [
    ["topology", "subnet"],
    ["server", "10.8.0.0", "255.255.255.0", "nopool"],
    ["ifconfig-pool", "10.8.0.2", "10.8.0.191", "255.255.255.0"],
    ["script-security", "2"],
    ["client-connect", "/usr/local/lib/ovpn-web/client-connect"],
]


@pytest.fixture
def helper(monkeypatch):
    estado = {"documentos": [], "validos": ["ana", "luis"], "revocados": ["viejo"],
              "revocar": [], "falla": None}

    def aplicar(cfg, doc):
        if estado["falla"]:
            raise easyrsa.ErrorHelper(estado["falla"])
        estado["documentos"].append(doc)
        return {"ok": True}

    def revocar(cfg, cn):
        estado["revocar"].append(cn)
        estado["validos"].remove(cn)
        estado["revocados"].append(cn)
        return {"ok": True}

    def crear(cfg, cn, clave=None):
        estado["validos"].append(cn)
        return {"ok": True}

    monkeypatch.setattr(easyrsa, "aplicar_politicas", aplicar)
    monkeypatch.setattr(easyrsa, "server_conf", lambda c: {"ruta": "x", "directivas": DIRECTIVAS})
    monkeypatch.setattr(easyrsa, "listar_certificados",
                        lambda c: {"validos": list(estado["validos"]),
                                   "revocados": list(estado["revocados"])})
    monkeypatch.setattr(easyrsa, "revocar", revocar)
    monkeypatch.setattr(easyrsa, "crear_cliente", crear)
    monkeypatch.setattr(easyrsa, "restaurar", lambda c, cn, clave=None: {"ok": True})
    return estado


FORMULARIO = {
    "ip_fija": "10.8.0.200",
    "destinos": "192.168.1.0/24\n\n192.168.1.10:443/tcp\n",
    "f1_dias": ["0", "1", "2", "3", "4"],
    "f1_desde": "08:00",
    "f1_hasta": "19:00",
    "f2_dias": ["5"],
    "f2_desde": "22:00",
    "f2_hasta": "00:00",
    "expira": "2099-01-31T18:00",
    "max_sesion_min": "480",
}


# ------------------------------------------------------------- rutas

def test_guardar_aplica_y_audita(como_admin, csrf_admin, helper, cfg):
    r = como_admin.post("/clientes/ana/politica", data=FORMULARIO,
                        headers={"X-CSRF-Token": csrf_admin})

    assert r.status_code == 200, r.text
    guardada = db.obtener_politica(cfg.seguridad.db_path, "ana")
    assert guardada["ip_fija"] == "10.8.0.200"
    assert guardada["destinos"] == ["192.168.1.0/24", "192.168.1.10/32:443/tcp"]
    # '00:00' como final de franja es medianoche
    assert guardada["horario"][1] == {"dias": [5], "desde": "22:00", "hasta": "24:00"}
    assert guardada["max_sesion_min"] == 480

    # Al helper le llega el documento entero, no el cambio suelto
    assert helper["documentos"][-1]["clientes"]["ana"] == guardada

    entrada = db.listar_auditoria(cfg.seguridad.db_path, limite=1)[0]
    assert entrada["accion"] == "politica_cliente" and entrada["objetivo"] == "ana"
    assert "IP 10.8.0.200" in entrada["detalle"]


def test_si_el_helper_la_rechaza_no_se_guarda(como_admin, csrf_admin, helper, cfg):
    """
    La base es la fuente de verdad y el archivo de OpenVPN su copia: guardar lo
    que el servidor no está aplicando haría que el panel enseñara un límite
    que no existe.
    """
    helper["falla"] = "10.8.0.200 está dentro del pool dinámico"
    r = como_admin.post("/clientes/ana/politica", data=FORMULARIO,
                        headers={"X-CSRF-Token": csrf_admin})

    assert r.status_code == 400
    assert "pool dinámico" in r.text
    assert db.obtener_politica(cfg.seguridad.db_path, "ana") is None


@pytest.mark.parametrize("cambio, mensaje", [
    ({"f1_desde": ""}, "inicio y de fin"),
    ({"f1_dias": []}, "ningún día"),
    ({"ip_fija": ""}, "IP fija"),
    ({"max_sesion_min": "mucho"}, "número de minutos"),
    ({"destinos": "10.0.0.1; reboot"}, "Destino no válido"),
])
def test_formularios_mal_rellenos(como_admin, csrf_admin, helper, cambio, mensaje):
    datos = dict(FORMULARIO, **cambio)
    r = como_admin.post("/clientes/ana/politica", data=datos,
                        headers={"X-CSRF-Token": csrf_admin})
    assert r.status_code == 400
    assert mensaje in r.text
    assert helper["documentos"] == []


def test_el_supervisor_ve_pero_no_cambia(como_supervisor, csrf_supervisor, helper):
    r = como_supervisor.get("/clientes/ana/politica")
    assert r.status_code == 200
    assert "disabled" in r.text

    r = como_supervisor.post("/clientes/ana/politica", data=FORMULARIO,
                             headers={"X-CSRF-Token": csrf_supervisor})
    assert r.status_code == 403
    assert helper["documentos"] == []


def test_la_pagina_avisa_si_el_script_no_esta_enganchado(como_admin, helper, monkeypatch):
    monkeypatch.setattr(easyrsa, "server_conf",
                        lambda c: {"ruta": "x", "directivas": DIRECTIVAS[:3]})
    r = como_admin.get("/clientes/ana/politica")
    assert "no se aplican al conectar" in r.text
    assert "10.8.0.192" in r.text  # el primer hueco libre fuera del pool


def test_la_tabla_resume_las_politicas(como_admin, csrf_admin, helper, cfg):
    como_admin.post("/clientes/ana/politica", data=FORMULARIO,
                    headers={"X-CSRF-Token": csrf_admin})
    r = como_admin.get("/clientes/tabla")
    assert "IP 10.8.0.200" in r.text
    assert "caduca 31/01/2099 18:00" in r.text


def test_duracion_global(como_admin, csrf_admin, helper, cfg):
    r = como_admin.post("/clientes/politicas/global", data={"max_sesion_min": "720"},
                        headers={"X-CSRF-Token": csrf_admin})
    assert r.status_code == 200, r.text
    assert db.max_sesion_global(cfg.seguridad.db_path) == 720
    assert helper["documentos"][-1]["global"] == {"max_sesion_min": 720}


def test_crear_con_caducidad_fija_la_politica_antes(como_admin, csrf_admin, helper, cfg):
    r = como_admin.post("/clientes", data={"cn": "proveedor", "caduca": "2099-12-31T12:00"},
                        headers={"X-CSRF-Token": csrf_admin})
    assert r.status_code == 200, r.text
    assert db.obtener_politica(cfg.seguridad.db_path, "proveedor")["expira"] == "2099-12-31T12:00"
    assert "proveedor" in helper["validos"]


def test_crear_con_caducidad_no_emite_si_no_se_puede_fijar(como_admin, csrf_admin, helper):
    """Un acceso pedido temporal no puede acabar siendo permanente por un fallo."""
    helper["falla"] = "nft no está"
    r = como_admin.post("/clientes", data={"cn": "proveedor", "caduca": "2099-12-31T12:00"},
                        headers={"X-CSRF-Token": csrf_admin})
    assert r.status_code == 400
    assert "proveedor" not in helper["validos"]


def test_crear_con_caducidad_pasada(como_admin, csrf_admin, helper):
    r = como_admin.post("/clientes", data={"cn": "proveedor", "caduca": "2001-01-01T00:00"},
                        headers={"X-CSRF-Token": csrf_admin})
    assert r.status_code == 400
    assert "futura" in r.text


def test_no_se_restaura_un_acceso_temporal_vencido(como_admin, csrf_admin, helper, cfg):
    db.guardar_politica(cfg.seguridad.db_path, "viejo",
                        pol.normalizar({"expira": "2001-01-01T00:00"}), "jefa")
    r = como_admin.post("/clientes/viejo/restaurar",
                        headers={"X-CSRF-Token": csrf_admin})
    assert r.status_code == 400
    assert "caducó" in r.text


def test_nadie_puede_llamarse_como_el_sistema(cfg):
    db.init_db(cfg.seguridad.db_path)
    with pytest.raises(ValueError, match="reservados"):
        db.crear_usuario(cfg.seguridad.db_path, notificar.ACTOR_SISTEMA, "x" * 12, "admin")


# ----------------------------------------------------------- vigilante

@pytest.fixture
def conectados(monkeypatch):
    estado = {"conexiones": [], "expulsados": []}

    monkeypatch.setattr(mgmt, "obtener_conexiones",
                        lambda h, p: [dict(c) for c in estado["conexiones"]])

    def kill(h, p, cn):
        estado["expulsados"].append(cn)
        return "SUCCESS"

    monkeypatch.setattr(mgmt, "desconectar_cliente", kill)
    return estado


def _conexion(cn, segundos):
    import time
    return {"user": cn, "connected_since_epoch": int(time.time()) - segundos}


def test_vigilante_expulsa_fuera_de_horario(cfg, helper, conectados):
    db.init_db(cfg.seguridad.db_path)
    db.guardar_politica(cfg.seguridad.db_path, "ana", pol.normalizar({
        "horario": [{"dias": [0, 1, 2, 3, 4], "desde": "08:00", "hasta": "19:00"}]}), "jefa")
    conectados["conexiones"] = [_conexion("ana", 60), _conexion("luis", 60)]

    vigilante._aplicar_politicas(cfg, ahora=datetime(2025, 10, 13, 19, 0))

    assert conectados["expulsados"] == ["ana"]
    entrada = db.listar_auditoria(cfg.seguridad.db_path, limite=1)[0]
    assert entrada["usuario"] == notificar.ACTOR_SISTEMA
    assert entrada["accion"] == "expulsar_politica"


def test_vigilante_corta_por_duracion_sin_notificar(cfg, helper, conectados, monkeypatch):
    avisos = []
    monkeypatch.setattr(notificar, "avisar", lambda *a, **k: avisos.append(a))
    db.init_db(cfg.seguridad.db_path)
    db.guardar_ajuste(cfg.seguridad.db_path, db.AJUSTE_MAX_SESION, "60")
    conectados["conexiones"] = [_conexion("ana", 3700), _conexion("luis", 100)]

    vigilante._aplicar_politicas(cfg, ahora=datetime(2025, 10, 13, 10, 0))

    assert conectados["expulsados"] == ["ana"]
    assert db.listar_auditoria(cfg.seguridad.db_path, limite=1)[0]["accion"] == "fin_sesion"
    # Es lo normal y esperado: avisar cada vez enseñaría a ignorar los avisos
    assert avisos == []


def test_vigilante_revoca_el_acceso_temporal_vencido(cfg, helper, conectados):
    db.init_db(cfg.seguridad.db_path)
    vigilante._caducados_confirmados.clear()
    db.guardar_politica(cfg.seguridad.db_path, "luis",
                        pol.normalizar({"expira": "2025-10-13T09:00"}), "jefa")
    conectados["conexiones"] = [_conexion("luis", 600)]

    ahora = datetime(2025, 10, 13, 10, 0)
    vigilante._aplicar_politicas(cfg, ahora=ahora)
    vigilante._aplicar_politicas(cfg, ahora=ahora)

    # Una sola revocación aunque pasen dos vueltas, y expulsado además
    assert helper["revocar"] == ["luis"]
    assert "luis" in conectados["expulsados"]
    acciones = [e["accion"] for e in db.listar_auditoria(cfg.seguridad.db_path)]
    assert "caducar_cliente" in acciones


def test_vigilante_sin_politicas_no_molesta(cfg, helper, conectados, monkeypatch):
    db.init_db(cfg.seguridad.db_path)

    def no(*a):
        raise AssertionError("no debería preguntar al management")
    monkeypatch.setattr(mgmt, "obtener_conexiones", no)

    vigilante._aplicar_politicas(cfg)


# --------------------------------------------------- sucesos de la VPN

def test_rechazo_por_politica_y_sesion_desplazada():
    lineas = [
        "ovpn-web client-connect: RECHAZO cn=ana motivo=fuera_de_horario",
        "2026-07-30 10:00:01 luis/203.0.113.7:4444 MULTI: new connection by client 'luis' "
        "will cause previous active sessions by this client to be dropped.  Remember to "
        "use the --duplicate-cn option if you want multiple clients using the same "
        "certificate or username to concurrently connect.",
    ]
    duplicada, rechazo = eventos_vpn.parse_eventos(lineas)

    assert rechazo["tipo"] == eventos_vpn.RECHAZO_POLITICA
    assert rechazo["cn"] == "ana" and rechazo["detalle"] == "fuera de su horario"
    assert rechazo["fallo"] is True

    assert duplicada["tipo"] == eventos_vpn.SESION_DUPLICADA
    assert duplicada["cn"] == "luis" and duplicada["ip"] == "203.0.113.7"
    assert duplicada["fallo"] is False


@pytest.mark.parametrize("ips, esperado", [
    (["1.1.1.1"], False),
    # Cambiar de red una vez y quedarse
    (["1.1.1.1", "2.2.2.2", "2.2.2.2"], False),
    # Siempre desde el mismo sitio: un cliente que reconecta en bucle
    (["1.1.1.1", "1.1.1.1", "1.1.1.1"], False),
    # Ir y volver: dos sitios peleándose
    (["1.1.1.1", "2.2.2.2", "1.1.1.1"], True),
    (["1.1.1.1", "2.2.2.2", "1.1.1.1", "2.2.2.2"], True),
])
def test_vaiven(ips, esperado):
    assert eventos.es_vaiven(ips) is esperado


def test_avisa_de_un_perfil_compartido_una_vez(cfg, monkeypatch):
    avisos = []
    monkeypatch.setattr(notificar, "avisar", lambda c, cat, asunto, cuerpo, grave=False:
                        avisos.append((cat, asunto, grave)))
    db.init_db(cfg.seguridad.db_path)
    db.guardar_eventos_vpn(cfg.seguridad.db_path, [
        {"ts": "", "tipo": eventos_vpn.SESION_DUPLICADA, "cn": "luis", "ip": ip,
         "puerto": "1", "detalle": None}
        for ip in ("1.1.1.1", "2.2.2.2", "1.1.1.1")
    ])

    ahora = datetime.now(timezone.utc)
    eventos.vigilar_perfiles_compartidos(cfg, ahora)
    eventos.vigilar_perfiles_compartidos(cfg, ahora + timedelta(minutes=5))

    assert len(avisos) == 1
    assert avisos[0][2] is True
    entrada = db.listar_auditoria(cfg.seguridad.db_path, limite=1)[0]
    assert entrada["accion"] == "perfil_compartido" and entrada["objetivo"] == "luis"
    assert "1.1.1.1, 2.2.2.2" in entrada["detalle"]


def test_filtro_de_sesiones_desplazadas(como_admin, cfg):
    db.guardar_eventos_vpn(cfg.seguridad.db_path, [
        {"ts": "", "tipo": eventos_vpn.SESION_DUPLICADA, "cn": "luis", "ip": "1.1.1.1",
         "puerto": "1", "detalle": None},
        {"ts": "", "tipo": eventos_vpn.CONEXION, "cn": "ana", "ip": "2.2.2.2",
         "puerto": "1", "detalle": None},
    ])
    r = como_admin.get("/admin/auditoria?fuente=vpn&filtro=duplicadas")
    assert r.status_code == 200
    assert "sesión desplazada" in r.text and "luis" in r.text
    assert "ana" not in r.text.split("<tbody>")[1]


def test_el_auth_failed_de_un_rechazo_propio_no_cuenta_como_otro_fallo():
    """
    Líneas reales de OpenVPN 2.6.19 tras un rechazo del script de dos pasos.
    Antes salían tres sucesos —el rechazo y dos «rechazo de certificado»— y
    los dos últimos sumaban para el bloqueo automático de IPs.
    """
    lineas = [
        "ovpn-web totp: RECHAZO cn=ana motivo=codigo_incorrecto",
        "127.0.0.1:60439 SENT CONTROL [UNDEF]: 'AUTH_FAILED' (status=1)",
        "127.0.0.1:60439 SENT CONTROL [ana]: 'AUTH_FAILED' (status=1)",
    ]
    e, = eventos_vpn.parse_eventos(lineas)
    assert e["tipo"] == eventos_vpn.RECHAZO_2FA
    # Y de paso sabe de dónde venía, que el script no lo sabe
    assert (e["ip"], e["puerto"]) == ("127.0.0.1", "60439")


def test_un_auth_failed_suelto_cuenta_una_vez():
    lineas = [
        "203.0.113.5:4444 SENT CONTROL [UNDEF]: 'AUTH_FAILED' (status=1)",
        "203.0.113.5:4444 SENT CONTROL [ana]: 'AUTH_FAILED' (status=1)",
    ]
    assert len(eventos_vpn.parse_eventos(lineas)) == 1
