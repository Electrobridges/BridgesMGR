"""
Parseo de la salida de status de OpenVPN.

Portado desde OpenVPN-Manager-CLI. El detalle importante: OpenVPN 2.5.x
escribe el archivo de status-version 3 separado por TAB, mientras que el
management interface puede devolver la misma información separada por coma.
Todo pasa por _split_row() para soportar ambos.
"""

import time


def _split_row(line):
    """
    Divide una línea por TAB si los hay, si no por coma.

    OpenVPN status-version 3 usa TAB en el archivo de status, pero el
    management interface puede devolver coma. Soportamos ambos.
    """
    if '\t' in line:
        return line.split('\t')
    return line.split(',')


# Nombres de mes en inglés, que es como los escribe OpenVPN: usa el ctime() de
# C, ajeno al locale del panel. Tabla propia y no strptime('%b') porque ese sí
# mira el locale del proceso, y bastaría un LC_TIME español para que la fecha
# dejara de leerse y el tiempo de conexión se vaciara sin decir por qué.
_MESES = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12,
}


def parse_fecha_conexion(texto):
    """
    Convierte a epoch la fecha con la que OpenVPN marca una conexión.

    Acepta los dos formatos que aparecen: '2025-12-26 21:40:11' (status v3) y
    'Fri Dec 26 21:40:11 2025' (v1, el ctime de C). Devuelve None si no encaja
    con ninguno —incluido el 'N/A' de un v1 sin fecha—, para que quien llame
    pueda decir que no lo sabe en vez de inventarse una hora.

    Se interpreta como **hora local**, que es con la que escribe el servidor
    OpenVPN, o sea esta misma máquina. En v3 casi nunca hace falta llegar aquí
    porque la línea trae el epoch, que es inmune a la zona y al horario de
    verano.
    """
    if not texto:
        return None

    partes = texto.split()

    try:
        if len(partes) == 2:
            anio, mes, dia = [int(x) for x in partes[0].split('-')]
            hora, minuto, segundo = [int(x) for x in partes[1].split(':')]
        elif len(partes) == 5:
            mes = _MESES[partes[1]]
            dia = int(partes[2])
            hora, minuto, segundo = [int(x) for x in partes[3].split(':')]
            anio = int(partes[4])
        else:
            return None
    except (KeyError, ValueError):
        return None

    # Los rangos se comprueban a mano porque mktime **normaliza** en vez de
    # protestar: el mes 13 del 2025 le sale abril del 2026 tan tranquilo, y una
    # fecha imposible acabaría mostrándose como un tiempo de conexión creíble.
    if not (1 <= mes <= 12 and 1 <= dia <= 31 and 0 <= hora <= 23
            and 0 <= minuto <= 59 and 0 <= segundo <= 59):
        return None

    try:
        # tm_isdst=-1: que mktime resuelva el horario de verano según la fecha
        return int(time.mktime((anio, mes, dia, hora, minuto, segundo, 0, 1, -1)))
    except (OverflowError, ValueError):
        return None


def _epoch_v3(parts):
    """
    Instante de la conexión en una línea CLIENT_LIST.

    OpenVPN pone 'Connected Since (time_t)' en la novena columna; es un
    instante absoluto y por eso se prefiere. Cuando no está —línea corta, o un
    status v3 antiguo— se recae en la fecha escrita.
    """
    if len(parts) >= 9 and parts[8].isdigit():
        return int(parts[8])

    return parse_fecha_conexion(parts[7])


def parse_v3_output(text):
    """
    Parsea el formato status-version 3 (CLIENT_LIST / ROUTING_TABLE).

    Funciona tanto con separador TAB (archivo) como coma (management).
    Devuelve una lista de dicts con las claves:
        user, real_ip, virtual_ip, bytes_recv, bytes_sent, connected_since,
        connected_since_epoch
    """
    connections = []
    routing = {}

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        parts = _split_row(line)
        if not parts:
            continue

        tag = parts[0]

        if tag == 'CLIENT_LIST':
            if len(parts) >= 8:
                connections.append({
                    'user': parts[1],
                    'real_ip': parts[2],
                    'virtual_ip': parts[3] if parts[3] else 'N/A',
                    'bytes_recv': int(parts[5]) if parts[5].isdigit() else 0,
                    'bytes_sent': int(parts[6]) if parts[6].isdigit() else 0,
                    'connected_since': parts[7],
                    'connected_since_epoch': _epoch_v3(parts),
                })
        elif tag == 'ROUTING_TABLE':
            if len(parts) >= 3:
                routing[parts[2]] = parts[1]

    # La IP virtual solo aparece en la tabla de rutas en algunas versiones
    for c in connections:
        if c['virtual_ip'] == 'N/A' and c['user'] in routing:
            c['virtual_ip'] = routing[c['user']]

    return connections


def parse_v1_output(text):
    """
    Parsea el formato antiguo status-version 1 ("OpenVPN CLIENT LIST").

    Este formato no expone la dirección virtual, que queda como 'N/A'.
    """
    connections = []
    in_client_section = False

    for raw in text.splitlines():
        line = raw.strip()

        if line.startswith('Common Name,'):
            in_client_section = True
            continue

        if line.startswith('ROUTING'):
            break

        if in_client_section and line:
            parts = line.split(',')
            if len(parts) >= 4:
                connections.append({
                    'user': parts[0],
                    'real_ip': parts[1],
                    'bytes_recv': int(parts[2]) if parts[2].isdigit() else 0,
                    'bytes_sent': int(parts[3]) if parts[3].isdigit() else 0,
                    'connected_since': parts[4] if len(parts) > 4 else 'N/A',
                    'connected_since_epoch': (
                        parse_fecha_conexion(parts[4]) if len(parts) > 4 else None
                    ),
                    'virtual_ip': 'N/A',
                })

    return connections


def parse_status_text(text):
    """Detecta la versión del formato y delega en el parser adecuado"""
    if 'CLIENT_LIST' in text:
        return parse_v3_output(text)
    return parse_v1_output(text)


def format_bytes(bytes_val):
    """Convierte bytes a formato legible"""
    try:
        b = float(bytes_val)
    except (TypeError, ValueError):
        return str(bytes_val)

    for unit in ['B', 'KB', 'MB', 'GB']:
        if b < 1024:
            return "%.2f %s" % (b, unit)
        b /= 1024

    return "%.2f TB" % b
