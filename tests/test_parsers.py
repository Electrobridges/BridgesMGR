"""
Parsers de status.

El caso que motivó todo esto: OpenVPN 2.5.11 escribe el archivo de
status-version 3 separado por TAB, no por coma.
"""

import time

import pytest

from app.core.conexiones import (
    anotar_duraciones,
    leer_status,
    obtener_conexiones,
    resumen_trafico,
    segundos_conectado,
    top_por_trafico,
)
from app.core.parsers import (
    format_bytes,
    parse_fecha_conexion,
    parse_status_text,
    parse_v1_output,
    parse_v3_output,
)

V3_TAB = "\n".join([
    "TITLE\tOpenVPN 2.5.11 x86_64-pc-linux-gnu",
    "TIME\t2025-12-26 21:59:36\t1766786376",
    "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address"
    "\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)",
    "CLIENT_LIST\tadministrador-daniel\t192.168.1.50:54321\t10.8.0.2\t\t184320\t942080"
    "\t2025-12-26 21:40:11\t1766785211\tUNDEF\t3\t0",
    "ROUTING_TABLE\t10.8.0.2\tadministrador-daniel\t192.168.1.50:54321"
    "\t2025-12-26 21:59:30\t1766786370",
    "GLOBAL_STATS\tMax bcast/mcast queue length\t0",
    "END",
])

# El management puede devolver coma y dejar vacía la dirección virtual
V3_COMA = "\n".join([
    "TITLE,OpenVPN 2.5.11 x86_64-pc-linux-gnu",
    "CLIENT_LIST,administrador-daniel,192.168.1.50:54321,,,184320,942080,"
    "2025-12-26 21:40:11,1766785211,UNDEF,3,0",
    "ROUTING_TABLE,10.8.0.2,administrador-daniel,192.168.1.50:54321,"
    "2025-12-26 21:59:30,1766786370",
    "END",
])

V1 = "\n".join([
    "OpenVPN CLIENT LIST",
    "Updated,Fri Dec 26 21:59:36 2025",
    "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since",
    "administrador-daniel,192.168.1.50:54321,184320,942080,Fri Dec 26 21:40:11 2025",
    "ROUTING TABLE",
    "END",
])


@pytest.mark.parametrize("texto,ip_virtual", [
    (V3_TAB, "10.8.0.2"),
    (V3_COMA, "10.8.0.2"),
])
def test_v3_ambos_separadores(texto, ip_virtual):
    conexiones = parse_v3_output(texto)

    assert len(conexiones) == 1
    c = conexiones[0]
    assert c["user"] == "administrador-daniel"
    assert c["real_ip"] == "192.168.1.50:54321"
    assert c["bytes_recv"] == 184320
    assert c["bytes_sent"] == 942080
    # Cuando CLIENT_LIST no trae la IP virtual, se cruza con ROUTING_TABLE
    assert c["virtual_ip"] == ip_virtual


def test_v1_formato_antiguo():
    conexiones = parse_v1_output(V1)

    assert len(conexiones) == 1
    assert conexiones[0]["user"] == "administrador-daniel"
    assert conexiones[0]["bytes_recv"] == 184320
    # v1 no expone la dirección virtual
    assert conexiones[0]["virtual_ip"] == "N/A"


@pytest.mark.parametrize("texto,esperado", [(V3_TAB, "10.8.0.2"), (V1, "N/A")])
def test_deteccion_de_formato(texto, esperado):
    conexiones = parse_status_text(texto)
    assert conexiones[0]["virtual_ip"] == esperado


def test_status_vacio_no_revienta():
    assert parse_status_text("") == []
    assert parse_status_text("TITLE\tOpenVPN\nEND") == []


def test_lineas_incompletas_se_ignoran():
    """Un CLIENT_LIST truncado no debe tumbar la lectura entera"""
    texto = "CLIENT_LIST\tsolo\tdos\nCLIENT_LIST\tbueno\t1.2.3.4\t10.8.0.9\t\t10\t20\tayer\nEND"
    conexiones = parse_v3_output(texto)

    assert len(conexiones) == 1
    assert conexiones[0]["user"] == "bueno"


def test_bytes_no_numericos_valen_cero():
    texto = "CLIENT_LIST\tx\t1.2.3.4\t10.8.0.9\t\tNaN\t-5\tayer\nEND"
    c = parse_v3_output(texto)[0]

    assert c["bytes_recv"] == 0
    assert c["bytes_sent"] == 0


def test_leer_status_desde_archivo(tmp_path):
    ruta = tmp_path / "status.log"
    ruta.write_text(V3_TAB, encoding="utf-8")

    assert leer_status(str(ruta))[0]["user"] == "administrador-daniel"


def test_resumen_y_top():
    conexiones = [
        {"user": "a", "bytes_recv": 100, "bytes_sent": 50},
        {"user": "b", "bytes_recv": 900, "bytes_sent": 100},
    ]

    resumen = resumen_trafico(conexiones)
    assert resumen == {
        "conectados": 2, "bytes_recv": 1000, "bytes_sent": 150, "bytes_total": 1150,
    }
    assert [c["user"] for c in top_por_trafico(conexiones)] == ["b", "a"]


@pytest.mark.parametrize("valor,esperado", [
    (0, "0.00 B"),
    (1024, "1.00 KB"),
    (1536, "1.50 KB"),
    (1048576, "1.00 MB"),
    ("no-numero", "no-numero"),
])
def test_format_bytes(valor, esperado):
    assert format_bytes(valor) == esperado


# ------------------------------------------- cuánto lleva conectado cada uno

def test_v3_prefiere_el_time_t_para_saber_cuando_empezo():
    """
    La columna 'Connected Since (time_t)' es un instante absoluto; la fecha de
    al lado es hora local y se lee mal en cuanto la zona no coincide.
    """
    c = parse_v3_output(V3_TAB)[0]

    assert c["connected_since_epoch"] == 1766785211


def test_v3_sin_time_t_recae_en_la_fecha_escrita():
    """Un status v3 antiguo no trae la columna del epoch, y aun así hay dato"""
    texto = ("CLIENT_LIST\tdaniel\t192.168.1.50:54321\t10.8.0.2\t\t10\t20"
             "\t2025-12-26 21:40:11\nEND")

    c = parse_v3_output(texto)[0]

    assert c["connected_since_epoch"] == int(
        time.mktime((2025, 12, 26, 21, 40, 11, 0, 1, -1))
    )


def test_v1_saca_el_instante_de_la_fecha_de_ctime():
    """El formato antiguo solo tiene la fecha larga: 'Fri Dec 26 21:40:11 2025'"""
    c = parse_v1_output(V1)[0]

    assert c["connected_since_epoch"] == int(
        time.mktime((2025, 12, 26, 21, 40, 11, 0, 1, -1))
    )


@pytest.mark.parametrize("texto", [
    "",
    "N/A",
    "ayer",
    "2025-13-99 21:40:11",
    "Fri Xxx 26 21:40:11 2025",
])
def test_una_fecha_ilegible_no_inventa_el_instante(texto):
    """Mejor decir que no se sabe que dar una hora inventada"""
    assert parse_fecha_conexion(texto) is None


def test_el_tiempo_conectado_es_la_diferencia_con_ahora():
    conexion = {"connected_since_epoch": 1766785211}

    assert segundos_conectado(conexion, ahora=1766785211 + 9180) == 9180


def test_no_se_da_un_tiempo_conectado_negativo():
    """
    Si al servidor le cambian la hora, la resta sale negativa. Un hueco
    declarado es mejor que un número imposible, igual que en las sesiones.
    """
    conexion = {"connected_since_epoch": 1766785211}

    assert segundos_conectado(conexion, ahora=1766785211 - 60) is None


def test_sin_instante_de_conexion_no_hay_tiempo():
    assert segundos_conectado({"connected_since_epoch": None}) is None
    assert segundos_conectado({}) is None


def test_anotar_duraciones_marca_todas_las_conexiones():
    conexiones = anotar_duraciones([
        {"user": "a", "connected_since_epoch": 1766785211},
        {"user": "b", "connected_since_epoch": None},
    ], ahora=1766785211 + 45)

    assert conexiones[0]["connected_seconds"] == 45
    assert conexiones[1]["connected_seconds"] is None


def test_obtener_conexiones_ya_trae_el_tiempo_conectado(cfg):
    """
    El cálculo cuelga del punto de entrada único, así que ninguna vista tiene
    que mirar el reloj por su cuenta.
    """
    hace_una_hora = int(time.time()) - 3600
    with open(cfg.openvpn.status_path, "w", encoding="utf-8") as f:
        f.write("CLIENT_LIST\tdaniel\t192.168.1.50:54321\t10.8.0.2\t\t10\t20"
                "\t2025-12-26 21:40:11\t%d\nEND" % hace_una_hora)

    conexiones, fuente, _errores = obtener_conexiones(cfg)

    # mgmt_port apunta a un puerto cerrado, así que se llega por el archivo
    assert fuente == "status"
    assert 3595 <= conexiones[0]["connected_seconds"] <= 3605
