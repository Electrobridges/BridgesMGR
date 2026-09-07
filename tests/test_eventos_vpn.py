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

    assert 'aria-current="page"' in texto
    # El filtro de 'Certificados' solo existe en la pestaña del panel
    assert "filtro=certificados" in texto
    assert "filtro=conexiones" not in texto


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


# ------------------------------------------------------------ sesiones

def _conecta(ts, cn, ip, puerto):
    return ("%s %s:%s [%s] Peer Connection Initiated with [AF_INET]%s:%s\n"
            % (ts, ip, puerto, cn, ip, puerto))


def _desconecta(ts, cn, ip, puerto):
    return ("%s %s/%s:%s SIGTERM[soft,remote-exit] received, client-instance "
            "exiting\n" % (ts, cn, ip, puerto))


def _ses(texto):
    return ev.emparejar_sesiones(ev.parse_eventos(texto.splitlines()))


def test_una_sesion_cerrada_dice_cuando_entro_cuando_salio_y_cuanto_duro():
    """Es justo lo que el log tenía repartido en dos líneas sin relación"""
    sesiones = _ses(
        _conecta("2026-07-30 10:00:00", "daniel", "192.168.1.50", "49711")
        + _desconecta("2026-07-30 12:33:00", "daniel", "192.168.1.50", "49711")
    )

    assert len(sesiones) == 1
    s = sesiones[0]
    assert s["estado"] == ev.CERRADA
    assert s["cn"] == "daniel"
    assert s["inicio"] == "2026-07-30 10:00:00"
    assert s["fin"] == "2026-07-30 12:33:00"
    assert s["segundos"] == 9180


def test_una_sesion_sin_desconexion_sigue_abierta():
    sesiones = _ses(_conecta("2026-07-30 10:00:00", "daniel", "192.168.1.50", "49711"))

    assert sesiones[0]["estado"] == ev.ABIERTA
    assert sesiones[0]["fin"] == ""
    assert sesiones[0]["segundos"] is None


def test_un_arranque_del_servidor_no_deja_sesiones_en_curso():
    """
    Si OpenVPN arrancó después, lo de antes no puede seguir conectado. Sin
    esto, una sesión de hace semanas se enseñaría como 'en curso' para siempre.
    """
    sesiones = _ses(
        _conecta("2026-07-30 10:00:00", "daniel", "192.168.1.50", "49711")
        + "2026-07-30 15:00:00 Initialization Sequence Completed\n"
    )

    assert sesiones[0]["estado"] == ev.INTERRUMPIDA
    assert sesiones[0]["segundos"] is None


def test_una_salida_sin_su_entrada_no_inventa_la_duracion():
    """
    Pasa en cuanto la conexión queda por detrás del tramo de log que se lee.
    Consta que salió; no consta cuánto estuvo, y eso no se rellena.
    """
    sesiones = _ses(_desconecta("2026-07-30 12:33:00", "daniel", "192.168.1.50", "49711"))

    s = sesiones[0]
    assert s["estado"] == ev.SIN_INICIO
    assert s["inicio"] == ""
    assert s["fin"] == "2026-07-30 12:33:00"
    assert s["segundos"] is None
    assert s["cn"] == "daniel"


def test_dos_clientes_a_la_vez_no_se_mezclan():
    sesiones = _ses(
        _conecta("2026-07-30 10:00:00", "daniel", "192.168.1.50", "49711")
        + _conecta("2026-07-30 10:10:00", "marta", "192.168.1.77", "51001")
        + _desconecta("2026-07-30 10:20:00", "marta", "192.168.1.77", "51001")
        + _desconecta("2026-07-30 11:00:00", "daniel", "192.168.1.50", "49711")
    )

    por_cn = {s["cn"]: s for s in sesiones}
    assert por_cn["daniel"]["segundos"] == 3600
    assert por_cn["marta"]["segundos"] == 600


def test_una_reconexion_es_una_sesion_aparte():
    """El mismo cliente dos veces son dos filas, no una con la suma"""
    sesiones = _ses(
        _conecta("2026-07-30 10:00:00", "daniel", "192.168.1.50", "49711")
        + _desconecta("2026-07-30 10:30:00", "daniel", "192.168.1.50", "49711")
        + _conecta("2026-07-30 11:00:00", "daniel", "192.168.1.50", "49712")
        + _desconecta("2026-07-30 11:15:00", "daniel", "192.168.1.50", "49712")
    )

    assert len(sesiones) == 2
    assert [s["segundos"] for s in sesiones] == [900, 1800]


def test_volver_a_ver_el_mismo_puerto_cierra_la_sesion_anterior():
    """
    El puerto de origen no se reutiliza mientras la sesión vive, así que verlo
    conectar otra vez significa que la anterior acabó sin dejar constancia.
    """
    sesiones = _ses(
        _conecta("2026-07-30 10:00:00", "daniel", "192.168.1.50", "49711")
        + _conecta("2026-07-30 14:00:00", "daniel", "192.168.1.50", "49711")
    )

    assert len(sesiones) == 2
    assert sesiones[0]["estado"] == ev.ABIERTA          # la de las 14:00
    assert sesiones[1]["estado"] == ev.INTERRUMPIDA     # la de las 10:00


def test_no_se_da_una_duracion_negativa():
    """
    Si al servidor le cambian la hora entre las dos líneas, sale una diferencia
    negativa. Un hueco declarado es mejor que un número imposible.
    """
    sesiones = _ses(
        _conecta("2026-07-30 12:00:00", "daniel", "192.168.1.50", "49711")
        + _desconecta("2026-07-30 10:00:00", "daniel", "192.168.1.50", "49711")
    )

    assert sesiones[0]["estado"] == ev.CERRADA
    assert sesiones[0]["segundos"] is None


def test_la_sesion_mas_reciente_va_primero():
    sesiones = _ses(
        _conecta("2026-07-30 08:00:00", "antigua", "192.168.1.50", "1111")
        + _desconecta("2026-07-30 08:30:00", "antigua", "192.168.1.50", "1111")
        + _conecta("2026-07-30 20:00:00", "reciente", "192.168.1.50", "2222")
        + _desconecta("2026-07-30 20:30:00", "reciente", "192.168.1.50", "2222")
    )

    assert [s["cn"] for s in sesiones] == ["reciente", "antigua"]


@pytest.mark.parametrize("segundos, esperado", [
    (0, "0 s"),
    (45, "45 s"),
    (60, "1 min"),
    (90, "1 min 30 s"),
    (3600, "1 h"),
    (9180, "2 h 33 min"),
    (86400, "1 d"),
    (100800, "1 d 4 h"),
    (None, ""),
])
def test_formatear_duracion(segundos, esperado):
    assert ev.formatear_duracion(segundos) == esperado


def test_leer_sesiones_avisa_si_el_log_no_llega_al_principio(tmp_path):
    """Una duración ausente tiene que explicarse, no quedarse en un guion"""
    log = tmp_path / "openvpn.log"
    log.write_text(
        _desconecta("2026-07-30 12:33:00", "daniel", "192.168.1.50", "49711"),
        encoding="utf-8",
    )

    sesiones, avisos = ev.leer_sesiones(_Cfg(str(log)))

    assert sesiones[0]["estado"] == ev.SIN_INICIO
    assert avisos and "solo consta la salida" in avisos[0]


# ------------------------------------------------- la vista de sesiones

@pytest.fixture
def log_con_sesiones(cfg):
    """Una sesión cerrada de 2 h 33 min y otra que sigue abierta"""
    with open(cfg.openvpn.log_path, "w", encoding="utf-8") as f:
        f.write(_conecta("2026-07-30 10:00:00", "daniel", "192.168.1.50", "49711"))
        f.write(_desconecta("2026-07-30 12:33:00", "daniel", "192.168.1.50", "49711"))
        f.write(_conecta("2026-07-30 13:00:00", "marta", "192.168.1.77", "51001"))
    return cfg.openvpn.log_path


def test_la_vista_de_sesiones_da_la_duracion(como_admin, log_con_sesiones):
    texto = como_admin.get("/admin/auditoria?fuente=vpn&filtro=sesiones").text

    assert "2 h 33 min" in texto
    assert "2026-07-30 10:00:00" in texto
    assert "2026-07-30 12:33:00" in texto


def test_la_vista_de_sesiones_distingue_a_quien_sigue_dentro(como_admin, log_con_sesiones):
    texto = como_admin.get("/admin/auditoria?fuente=vpn&filtro=sesiones").text

    assert "sigue conectado" in texto
    assert "marta" in texto


def test_el_filtro_de_conexiones_incluye_las_desconexiones(como_admin, log_con_sesiones):
    """
    Una desconexión es la otra mitad de la conexión que cierra. Enseñando solo
    las entradas, una sesión terminada parece seguir abierta, y la salida no
    aparecía en ninguna pestaña salvo 'Todo', mezclada con arranques y CRL.
    """
    texto = como_admin.get("/admin/auditoria?fuente=vpn&filtro=conexiones").text

    assert "conexión establecida" in texto
    assert "desconexión" in texto
    assert "2026-07-30 12:33:00" in texto


def test_el_filtro_de_conexiones_deja_fuera_lo_que_no_es_del_cliente(como_admin, cfg):
    """Entradas y salidas, no el resto del log: un arranque no es una conexión"""
    with open(cfg.openvpn.log_path, "w", encoding="utf-8") as f:
        f.write(_conecta("2026-07-30 10:00:00", "daniel", "192.168.1.50", "49711"))
        f.write("2026-07-30 09:00:00 Initialization Sequence Completed\n")

    texto = como_admin.get("/admin/auditoria?fuente=vpn&filtro=conexiones").text

    assert "conexión establecida" in texto
    assert "servidor arrancado" not in texto


def test_un_filtro_inventado_cae_en_todo(como_admin, log_con_sesiones):
    """La vista sale de la URL, así que cualquiera puede escribir lo que quiera"""
    texto = como_admin.get("/admin/auditoria?fuente=vpn&filtro=loquesea").text

    assert "conexión establecida" in texto
    assert "Duración" not in texto


# ------------------------------------------ logs sin marca de tiempo

# La unidad que Debian empaqueta para OpenVPN arranca el servidor con
# '--suppress-timestamps', así que ninguna línea lleva fecha. No es un caso
# raro: es lo que sale de un 'apt install openvpn' sin tocar nada, y el
# server.conf no puede desactivarlo. Estas líneas son literales de un servidor
# Debian 13 con la unidad de paquete.
SIN_FECHA = """\
127.0.0.1:57176 TLS: Initial packet from [AF_INET]127.0.0.1:57176
127.0.0.1:57176 VERIFY OK: depth=0, CN=alfa2
127.0.0.1:57176 [alfa2] Peer Connection Initiated with [AF_INET]127.0.0.1:57176
alfa2/127.0.0.1:57176 SIGTERM[soft,remote-exit] received, client-instance exiting
"""


def test_una_linea_sin_fecha_se_reconoce_igual():
    """
    Exigir la fecha como prefijo dejaba fuera el log entero de una Debian de
    paquete: cero sucesos con el log lleno de conexiones.
    """
    eventos = _ev(SIN_FECHA)

    assert [e["tipo"] for e in eventos] == [ev.DESCONEXION, ev.CONEXION]
    assert eventos[1]["cn"] == "alfa2"
    assert eventos[1]["ip"] == "127.0.0.1"
    assert eventos[1]["puerto"] == "57176"
    assert eventos[1]["ts"] == ""


def test_una_sesion_sin_fechas_se_empareja_pero_no_inventa_la_duracion():
    """
    El emparejado va por 'ip:puerto', que sigue estando. La duración no: sin
    fecha no hay resta posible, y aquí se dice en vez de rellenarla.
    """
    sesiones = _ses(SIN_FECHA)

    assert len(sesiones) == 1
    s = sesiones[0]
    assert s["estado"] == ev.CERRADA
    assert s["cn"] == "alfa2"
    assert s["segundos"] is None


def test_avisa_de_que_el_log_no_lleva_fecha_y_dice_como_arreglarlo(tmp_path):
    """
    El aviso de 'verb bajo' mandaba a mirar el server.conf, donde no está el
    problema ni la solución. Con 'verb 3' puesto, el log se ve lleno y la culpa
    parece del panel.
    """
    log = tmp_path / "openvpn.log"
    log.write_text(SIN_FECHA, encoding="utf-8")

    eventos, avisos = ev.leer_eventos(_Cfg(str(log)))

    assert eventos, "los sucesos tienen que salir igual"
    assert avisos and "suppress-timestamps" in avisos[0]


def test_un_log_con_fechas_no_da_ese_aviso(tmp_path):
    log = tmp_path / "openvpn.log"
    log.write_text(CONEXION_OK, encoding="utf-8")

    _, avisos = ev.leer_eventos(_Cfg(str(log)))

    assert not any("suppress-timestamps" in a for a in avisos)


def test_la_vista_de_sesiones_no_miente_con_un_log_sin_fechas(como_admin, cfg):
    """
    Sin fecha la sesión se empareja pero no tiene duración. Decir «no consta su
    entrada» sería falso: consta, lo que falta es el cuándo.
    """
    with open(cfg.openvpn.log_path, "w", encoding="utf-8") as f:
        f.write(SIN_FECHA)

    texto = como_admin.get("/admin/auditoria?fuente=vpn&filtro=sesiones").text

    assert "alfa2" in texto
    assert "sin fecha en el log" in texto
    assert "no consta su entrada" not in texto
