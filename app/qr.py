"""
Códigos QR para el alta del segundo factor.

Es la única dependencia externa del panel además del propio marco web, y se
eligió a conciencia: un codificador QR son unas trescientas líneas de
Reed-Solomon y tablas de capacidad por versión que tienen que estar exactas, y
su modo de fallo —"no escanea"— solo se descubre con un móvil delante. Nada de
eso es auditable de un vistazo, que era el motivo de escribir el TOTP a mano
(ver app/core/totp.py, cuarenta líneas de hmac).

'segno' es Python puro, sin dependencias propias en 3.10+, y genera el SVG sin
pasar por Pillow ni por ningún binario.

El QR se sirve como data: URI dentro de un <img>. Dos motivos: la CSP ya
admite `img-src 'self' data:` sin tocarla, y dentro de un <img> el SVG se
dibuja en modo restringido, sin scripts ni referencias externas.
"""

import base64
import io

try:
    import segno
except ImportError:                                  # pragma: no cover
    segno = None

# Azul del sistema en vez de negro puro: contraste de sobra sobre blanco
# (~17:1) y no desentona con el resto del panel.
OSCURO = "#081731"
CLARO = "#ffffff"


class QRNoDisponible(RuntimeError):
    """Falta 'segno'. Se avisa en pantalla en vez de dejar un hueco mudo."""


def disponible():
    return segno is not None


def data_uri(texto, escala=5, borde=3):
    """
    Devuelve el QR de 'texto' como data: URI de un SVG, listo para un <img>.

    'borde' es la zona de silencio en módulos. El estándar pide 4; con 3 los
    lectores de móvil van sobrados y la imagen ocupa menos en pantalla.
    """
    if segno is None:
        raise QRNoDisponible(
            "Falta el paquete 'segno'. Instálalo con "
            "'pip install -r requirements.txt' para ver el QR; mientras tanto, "
            "da de alta la cuenta escribiendo la clave a mano."
        )

    codigo = segno.make(texto, error="m")

    buffer = io.BytesIO()
    codigo.save(
        buffer,
        kind="svg",
        scale=escala,
        border=borde,
        dark=OSCURO,
        light=CLARO,
        xmldecl=False,      # dentro de un data: URI no aporta nada
        svgclass=None,      # sin clases: el SVG no hereda el CSS del panel
        lineclass=None,
        omitsize=True,      # que lo escale el <img>, no el propio SVG
    )

    codificado = base64.b64encode(buffer.getvalue()).decode("ascii")
    return "data:image/svg+xml;base64,%s" % codificado
