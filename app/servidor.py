"""
Arranque del servidor.

Existe para que host, puerto y certificados salgan de config.yaml y no haya
que repetirlos en la unidad de systemd (dos fuentes de verdad que se
desincronizan al primer cambio).

    python -m app.servidor
"""

import os
import sys

import uvicorn

from .config import cargar_config


def main():
    cfg = cargar_config()
    srv = cfg.servidor

    opciones = {
        "factory": True,
        "host": srv.host_bind,
        "port": srv.puerto,
        "access_log": True,
        # No anunciamos la versión del servidor ni confiamos en cabeceras de
        # proxy: el panel escucha directo, sin nada delante.
        "server_header": False,
        "proxy_headers": False,
        "forwarded_allow_ips": "",
    }

    usa_tls = bool(srv.tls_cert and srv.tls_key)

    if usa_tls:
        for ruta in (srv.tls_cert, srv.tls_key):
            if not os.path.isfile(ruta):
                sys.exit("No se encontró el archivo TLS: %s" % ruta)
        opciones["ssl_certfile"] = srv.tls_cert
        opciones["ssl_keyfile"] = srv.tls_key

    esquema = "https" if usa_tls else "http"
    print("OpenVPN Manager Web escuchando en %s://%s:%d" % (esquema, srv.host_bind, srv.puerto))

    if not usa_tls:
        print("AVISO: TLS desactivado. Las credenciales viajarán en claro.", file=sys.stderr)

    # Aquí y no en crear_app(): las pruebas construyen la aplicación cientos de
    # veces y no deben levantar un hilo cada vez. Vigila lo que nadie provoca
    # —que la CRL caduque, que OpenVPN se caiga— y solo avisa si la categoría
    # 'salud del servicio' está encendida.
    from . import vigilante
    vigilante.arrancar(cfg)

    uvicorn.run("app.main:crear_app", **opciones)


if __name__ == "__main__":
    main()
