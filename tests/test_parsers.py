"""
Parsers de status.

El caso que motivó todo esto: OpenVPN 2.5.11 escribe el archivo de
status-version 3 separado por TAB, no por coma.
"""

import pytest

from app.core.conexiones import leer_status, resumen_trafico, top_por_trafico
from app.core.parsers import format_bytes, parse_status_text, parse_v1_output, parse_v3_output

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
