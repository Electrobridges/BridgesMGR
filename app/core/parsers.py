"""
Parseo de la salida de status de OpenVPN.

Portado desde OpenVPN-Manager-CLI. El detalle importante: OpenVPN 2.5.x
escribe el archivo de status-version 3 separado por TAB, mientras que el
management interface puede devolver la misma información separada por coma.
Todo pasa por _split_row() para soportar ambos.
"""


def _split_row(line):
    """
    Divide una línea por TAB si los hay, si no por coma.

    OpenVPN status-version 3 usa TAB en el archivo de status, pero el
    management interface puede devolver coma. Soportamos ambos.
    """
    if '\t' in line:
        return line.split('\t')
    return line.split(',')


def parse_v3_output(text):
    """
    Parsea el formato status-version 3 (CLIENT_LIST / ROUTING_TABLE).

    Funciona tanto con separador TAB (archivo) como coma (management).
    Devuelve una lista de dicts con las claves:
        user, real_ip, virtual_ip, bytes_recv, bytes_sent, connected_since
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
