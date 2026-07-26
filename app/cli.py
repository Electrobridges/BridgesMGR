"""
Utilidad de línea de comandos para administrar las cuentas del panel.

Es la única forma de crear el primer administrador: el panel no tiene registro
abierto ni usuario por defecto, a propósito.

    python -m app.cli crear-usuario daniel --rol admin
    python -m app.cli listar-usuarios
    python -m app.cli cambiar-password daniel
    python -m app.cli purgar-sesiones
"""

import argparse
import getpass
import sys

from . import db
from .config import cargar_config


def _password_interactiva():
    p1 = getpass.getpass("Contraseña (mín. 12 caracteres): ")
    p2 = getpass.getpass("Repite la contraseña: ")

    if p1 != p2:
        sys.exit("Las contraseñas no coinciden")
    if len(p1) < 12:
        sys.exit("La contraseña debe tener al menos 12 caracteres")

    return p1


def cmd_crear_usuario(cfg, args):
    password = _password_interactiva()
    db.crear_usuario(cfg.seguridad.db_path, args.usuario, password, args.rol)
    print("Usuario '%s' creado con rol %s." % (args.usuario, args.rol))


def cmd_listar_usuarios(cfg, args):
    usuarios = db.listar_usuarios(cfg.seguridad.db_path)

    if not usuarios:
        print("No hay usuarios. Crea el primero con: python -m app.cli crear-usuario <nombre> --rol admin")
        return

    print("%-24s %-8s %-12s %s" % ("USUARIO", "ROL", "ESTADO", "CREADO"))
    for u in usuarios:
        print("%-24s %-8s %-12s %s" % (
            u["usuario"], u["rol"],
            "activo" if u["activo"] else "desactivado",
            u["creado"][:19].replace("T", " "),
        ))


def cmd_cambiar_password(cfg, args):
    password = _password_interactiva()
    db.cambiar_password(cfg.seguridad.db_path, args.usuario, password)

    registro = db.obtener_usuario(cfg.seguridad.db_path, args.usuario)
    if registro:
        db.borrar_sesiones_de(cfg.seguridad.db_path, registro["id"])

    print("Contraseña de '%s' actualizada y sesiones cerradas." % args.usuario)


def cmd_purgar_sesiones(cfg, args):
    db.purgar_sesiones(cfg.seguridad.db_path)
    print("Sesiones caducadas eliminadas.")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m app.cli",
        description="Administración de cuentas del panel OpenVPN Manager Web",
    )
    parser.add_argument("--config", help="Ruta a config.yaml (por defecto /etc/ovpn-web/config.yaml)")

    subs = parser.add_subparsers(dest="comando", required=True)

    p = subs.add_parser("crear-usuario", help="Crea una cuenta de acceso al panel")
    p.add_argument("usuario")
    p.add_argument("--rol", choices=db.ROLES, default="lector")
    p.set_defaults(func=cmd_crear_usuario)

    p = subs.add_parser("listar-usuarios", help="Lista las cuentas del panel")
    p.set_defaults(func=cmd_listar_usuarios)

    p = subs.add_parser("cambiar-password", help="Cambia la contraseña de una cuenta")
    p.add_argument("usuario")
    p.set_defaults(func=cmd_cambiar_password)

    p = subs.add_parser("purgar-sesiones", help="Borra las sesiones caducadas")
    p.set_defaults(func=cmd_purgar_sesiones)

    args = parser.parse_args(argv)
    cfg = cargar_config(args.config)
    db.init_db(cfg.seguridad.db_path)

    try:
        args.func(cfg, args)
    except ValueError as e:
        sys.exit("Error: %s" % e)


if __name__ == "__main__":
    main()
