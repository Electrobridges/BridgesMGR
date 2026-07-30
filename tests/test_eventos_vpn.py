"""
Sucesos de la VPN leídos del log de OpenVPN.

Las líneas de muestra son del formato real a 'verb 3'. Lo que más importa aquí
es el agrupamiento por 'ip:puerto': OpenVPN prefija con ese par las líneas de
una misma sesión, y es lo único que permite atar un rechazo con el CN que lo
provocó. Sin eso, un VERIFY ERROR es una IP suelta.
"""

import pytest

from app.core import eventos_vpn as ev


CONEXION_OK = """\
2026-07-30 10:00:01 192.168.1.50:49711 TLS: Initial packet from [AF_INET]192.168.1.50:49711
2026-07-30 10:00:01 192.168.1.50:49711 VERIFY OK: depth=1, CN=cn_EkNtP7tGJktvI2jk
2026-07-30 10:00:01 192.168.1.50:49711 VERIFY OK: depth=0, CN=daniel
2026-07-30 10:00:01 192.168.1.50:49711 [daniel] Peer Connection Initiated with [AF_INET]192.168.1.50:49711
2026-07-30 10:00:02 daniel/192.168.1.50:49711 MULTI: Learn: 10.8.0.2 -> daniel/192.168.1.50:49711
"""


def _ev(texto):
    return ev.parse_eventos(texto.splitlines())


def test_conexion_establecida():
    eventos = _ev(CONEXION_OK)

    assert len(eventos) == 1
    e = eventos[0]
    assert e["tipo"] == ev.CONEXION
    assert e["cn"] == "daniel"
    assert e["ip"] == "192.168.1.50"
    assert e["puerto"] == "49711"
    assert e["fallo"] is False


def test_certificado_revocado_se_atribuye_a_su_cn():
    """
    El VERIFY ERROR no siempre trae el CN, pero el VERIFY OK de depth=0 sí lo
    trajo unas líneas antes, en la misma sesión.
    """
    eventos = _ev("""\
2026-07-30 10:05:00 192.168.1.77:51001 VERIFY OK: depth=1, CN=cn_EkNtP7tGJktvI2jk
2026-07-30 10:05:00 192.168.1.77:51001 VERIFY ERROR: depth=0, error=certificate revoked: CN=antiguo-becario
2026-07-30 10:05:00 192.168.1.77:51001 TLS Error: TLS handshake failed
""")

    revocado = [e for e in eventos if e["tipo"] == ev.RECHAZO_REVOCADO]
    assert len(revocado) == 1
    assert revocado[0]["cn"] == "antiguo-becario"
    assert revocado[0]["ip"] == "192.168.1.77"
    assert revocado[0]["fallo"] is True


def test_clave_tls_crypt_que_no_coincide():
    """
    El síntoma de un cliente con el perfil anterior a una rotación. Merece
    mensaje propio: el genérico de TLS manda a mirar donde no es.
    """
    eventos = _ev(
        "2026-07-30 10:10:00 192.168.1.90:52000 TLS Error: TLS key negotiation "
        "failed to occur within 60 seconds (check your network connectivity)\n"
    )

    assert eventos[0]["tipo"] == ev.RECHAZO_CLAVE
    assert "tls-crypt" in eventos[0]["detalle"]


def test_un_rechazo_temprano_no_inventa_cn():
    """
    Si la conexión muere antes de presentar certificado, no hay CN. La columna
    queda vacía: rellenarla sería mentir en una auditoría.
    """
    eventos = _ev(
        "2026-07-30 10:15:00 203.0.113.9:40000 TLS Error: TLS handshake failed\n"
    )

    assert eventos[0]["tipo"] == ev.RECHAZO_TLS
    assert eventos[0]["cn"] == ""
    assert eventos[0]["ip"] == "203.0.113.9"


def test_desconexion():
    eventos = _ev(
        "2026-07-30 11:00:00 daniel/192.168.1.50:49711 SIGTERM[soft,remote-exit] "
        "received, client-instance exiting\n"
    )

    assert eventos[0]["tipo"] == ev.DESCONEXION
    assert eventos[0]["cn"] == "daniel"


def test_sucesos_del_servidor_sin_sesion():
    eventos = _ev("""\
2026-07-30 09:00:00 Initialization Sequence Completed
2026-07-30 09:30:00 CRL: loaded 1 CRLs from file /etc/openvpn/easy-rsa/pki/crl.pem
""")

    tipos = {e["tipo"] for e in eventos}
    assert tipos == {ev.ARRANQUE, ev.CRL}
    assert all(e["ip"] == "" for e in eventos)


def test_el_mas_reciente_va_primero():
    eventos = _ev("""\
2026-07-30 09:00:00 Initialization Sequence Completed
2026-07-30 10:00:01 192.168.1.50:49711 [daniel] Peer Connection Initiated with [AF_INET]192.168.1.50:49711
""")

    assert eventos[0]["tipo"] == ev.CONEXION
    assert eventos[1]["tipo"] == ev.ARRANQUE


def test_dos_sesiones_no_se_mezclan():
    """Cada 'ip:puerto' es una sesión: el CN de una no puede saltar a la otra"""
    eventos = _ev("""\
2026-07-30 10:00:00 192.168.1.50:1111 VERIFY OK: depth=0, CN=daniel
2026-07-30 10:00:01 192.168.1.99:2222 TLS Error: TLS handshake failed
""")

    assert eventos[0]["cn"] == ""


def test_las_lineas_que_no_interesan_se_ignoran():
    eventos = _ev("""\
2026-07-30 10:00:00 192.168.1.50:1111 PUSH: Received control message: 'PUSH_REQUEST'
2026-07-30 10:00:00 us=123456 Cipher negotiation enabled
basura sin fecha
""")

    assert eventos == []


# ------------------------------------------------------- lectura del archivo

class _Cfg:
    def __init__(self, ruta):
        self.openvpn = type("O", (), {"log_path": ruta})()


def test_avisa_si_no_existe_el_log(tmp_path):
    eventos, avisos = ev.leer_eventos(_Cfg(str(tmp_path / "no-existe.log")))

    assert eventos == []
    assert avisos and "log-append" in avisos[0]


def test_avisa_si_no_hay_ruta_configurada():
    eventos, avisos = ev.leer_eventos(_Cfg(""))

    assert eventos == []
    assert avisos


def test_avisa_si_hay_log_pero_nada_reconocible(tmp_path):
    """
    Un 'verb' bajo no escribe estas líneas, y una tabla vacía se parecería a
    «no ha entrado nadie». Hay que decir cuál de las dos cosas es.
    """
    log = tmp_path / "openvpn.log"
    log.write_text("2026-07-30 10:00:00 us=1 Cipher negotiation enabled\n", encoding="utf-8")

    eventos, avisos = ev.leer_eventos(_Cfg(str(log)))

    assert eventos == []
    assert avisos and "verb" in avisos[0]


def test_lee_el_final_del_archivo(tmp_path):
    log = tmp_path / "openvpn.log"
    log.write_text(CONEXION_OK, encoding="utf-8")

    eventos, avisos = ev.leer_eventos(_Cfg(str(log)))

    assert avisos == []
    assert eventos[0]["cn"] == "daniel"


def test_respeta_el_limite(tmp_path):
    log = tmp_path / "openvpn.log"
    log.write_text(CONEXION_OK * 50, encoding="utf-8")

    eventos, _ = ev.leer_eventos(_Cfg(str(log)), limite=7)

    assert len(eventos) == 7


# ------------------------------------------------------------ la página

@pytest.fixture
def log_vpn(cfg):
    """Escribe un log con una conexión y un rechazo por revocación"""
    ruta = cfg.openvpn.log_path
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(CONEXION_OK)
        f.write("2026-07-30 10:05:00 192.168.1.77:51001 VERIFY ERROR: depth=0, "
                "error=certificate revoked: CN=antiguo-becario\n")
    return ruta


def test_la_pestana_del_panel_es_la_de_por_defecto(como_admin):
    texto = como_admin.get("/admin/auditoria").text

    assert "Panel web" in texto
    assert "acciones registradas en el panel" in texto


def test_la_pestana_de_vpn_muestra_los_sucesos(como_admin, log_vpn):
    texto = como_admin.get("/admin/auditoria?fuente=vpn").text

    assert "conexión establecida" in texto
    assert "rechazado: revocado" in texto
    assert "daniel" in texto
    assert "192.168.1.50" in texto
    assert "antiguo-becario" in texto


def test_el_filtro_de_rechazos(como_admin, log_vpn):
    texto = como_admin.get("/admin/auditoria?fuente=vpn&filtro=fallos").text

    assert "rechazado: revocado" in texto
    assert "conexión establecida" not in texto


def test_el_filtro_de_conexiones(como_admin, log_vpn):
    texto = como_admin.get("/admin/auditoria?fuente=vpn&filtro=conexiones").text

    assert "conexión establecida" in texto
    assert "rechazado" not in texto


def test_un_supervisor_puede_consultarla(como_supervisor, log_vpn):
    """La auditoría es de consulta: el rol supervisor entra"""
    assert como_supervisor.get("/admin/auditoria?fuente=vpn").status_code == 200


def test_si_no_se_puede_leer_el_log_se_dice(como_admin, cfg):
    """Un permiso mal puesto no puede parecerse a «no ha entrado nadie»"""
    import os

    if os.path.exists(cfg.openvpn.log_path):
        os.remove(cfg.openvpn.log_path)

    texto = como_admin.get("/admin/auditoria?fuente=vpn").text

    assert "log-append" in texto
