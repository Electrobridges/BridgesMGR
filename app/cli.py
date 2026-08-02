"""
Utilidad de línea de comandos para administrar las cuentas del panel.

Es la única forma de crear la primera cuenta: el panel no tiene registro
abierto ni usuario por defecto, a propósito. Y esa primera cuenta es el
superusuario de la instalación, se pida el rol que se pida.

También es la única salida cuando el superusuario se queda fuera: desde el
panel nadie puede tocarle la contraseña ni el segundo factor, así que la
recuperación exige estar dentro del servidor.

    python -m app.cli crear-usuario daniel --rol admin
    python -m app.cli listar-usuarios
    python -m app.cli cambiar-password daniel
    python -m app.cli designar-superusuario daniel
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
    _, concedido = db.crear_usuario(cfg.seguridad.db_path, args.usuario, password, args.rol)

    print("Usuario '%s' creado con rol %s." % (args.usuario, concedido))

    # Se anuncia el rol concedido, no el pedido: en una base vacía el primero
    # nace superusuario aunque se pidiera otra cosa, y hay que decirlo.
    if concedido == db.ROL_SUPER and concedido != args.rol:
        print("Es la primera cuenta de la instalación, así que es el superusuario:")
        print("desde el panel nadie podrá cambiarle el rol, desactivarla, borrarla")
        print("ni tocarle la contraseña o el segundo factor. Solo ella misma, o esta CLI.")


def cmd_listar_usuarios(cfg, args):
    usuarios = db.listar_usuarios(cfg.seguridad.db_path)

    if not usuarios:
        print("No hay usuarios. Crea el primero con: python -m app.cli crear-usuario <nombre> --rol admin")
        print("Será el superusuario de la instalación.")
        return

    print("%-24s %-13s %-12s %-6s %s" % ("USUARIO", "ROL", "ESTADO", "2FA", "CREADO"))
    for u in usuarios:
        print("%-24s %-13s %-12s %-6s %s" % (
            u["usuario"], u["rol"],
            "activo" if u["activo"] else "desactivado",
            "sí" if u["totp_activado"] else "no",
            u["creado"][:19].replace("T", " "),
        ))

    if db.exigir_totp_supervisor(cfg.seguridad.db_path):
        print("\nEl segundo factor es obligatorio para el rol supervisor.")


def cmd_superusuario(cfg, args):
    """
    Designa el superusuario de la instalación.

    Desde el panel no se puede, a propósito: allí es fijo. Aquí sí, porque para
    llegar a esta CLI hay que estar dentro del servidor, que es más autoridad
    que cualquier rol. Sirve para dos casos que si no se quedan sin arreglo: una
    base que se migró sin ningún admin al que ascender, y otra en la que el
    ascenso recayó en la cuenta equivocada.
    """
    ruta = cfg.seguridad.db_path

    if args.exigir_confirmacion:
        actual = db.obtener_usuario(ruta, args.usuario)
        print("Esto le da a '%s' el mando de la instalación." % args.usuario)
        if actual:
            print("Rol actual de '%s': %s" % (args.usuario, actual["rol"]))
        if input("Escribe 'si' para confirmar: ").strip().lower() != "si":
            sys.exit("Cancelado.")

    _, anterior = db.designar_superusuario(ruta, args.usuario)

    # Cambia el rol de dos cuentas: las dos vuelven a entrar, igual que cuando
    # el cambio lo hace el panel.
    for afectado in (args.usuario, anterior):
        registro = db.obtener_usuario(ruta, afectado) if afectado else None
        if registro:
            db.borrar_sesiones_de(ruta, registro["id"])

    db.registrar(ruta, None, "designar_superusuario", args.usuario,
                 detalle="antes: %s, desde la CLI" % (anterior or "nadie"))

    if anterior:
        print("'%s' pasa a admin y '%s' es el nuevo superusuario." % (anterior, args.usuario))
    else:
        print("'%s' es el superusuario. No había ninguno." % args.usuario)
    print("Las sesiones de las cuentas afectadas se han cerrado.")


def cmd_totp_restablecer(cfg, args):
    """
    Salida de emergencia: quien pierde el móvil se queda fuera del panel.

    Un admin puede hacerlo desde /admin/usuarios, pero si el que se ha quedado
    fuera es el superusuario —al que el panel no deja tocar— o el único
    administrador, solo queda esta vía, desde el servidor.
    """
    registro = db.obtener_usuario(cfg.seguridad.db_path, args.usuario)
    if not registro:
        sys.exit("No existe el usuario '%s'" % args.usuario)

    db.desactivar_totp(cfg.seguridad.db_path, args.usuario)
    db.borrar_sesiones_de(cfg.seguridad.db_path, registro["id"])
    db.registrar(
        cfg.seguridad.db_path, args.usuario, "totp_restablecer", args.usuario,
        detalle="desde la CLI",
    )

    print("Segundo factor de '%s' restablecido y sus sesiones cerradas." % args.usuario)
    print("Entrará solo con la contraseña hasta que vuelva a activarlo.")


def cmd_politica_totp(cfg, args):
    ruta = cfg.seguridad.db_path

    if args.exigir is None:
        estado = "sí" if db.exigir_totp_supervisor(ruta) else "no"
        print("Segundo factor obligatorio para el rol supervisor: %s" % estado)
        return

    activar = args.exigir == "si"
    db.guardar_ajuste(ruta, db.AJUSTE_EXIGIR_TOTP_SUPERVISOR, "1" if activar else "0")
    db.registrar(
        ruta, None, "politica_totp_supervisor", db.ROL_SUPERVISOR,
        detalle=("exigido" if activar else "no exigido") + " desde la CLI",
    )

    if activar:
        print("Segundo factor exigido al rol supervisor. Los que no lo tengan solo")
        print("podrán entrar a su perfil hasta activarlo.")
    else:
        print("El segundo factor deja de ser obligatorio para el rol supervisor.")


def cmd_cambiar_password(cfg, args):
    password = _password_interactiva()
    db.cambiar_password(cfg.seguridad.db_path, args.usuario, password)

    registro = db.obtener_usuario(cfg.seguridad.db_path, args.usuario)
    if registro:
        db.borrar_sesiones_de(cfg.seguridad.db_path, registro["id"])

    print("Contraseña de '%s' actualizada y sesiones cerradas." % args.usuario)


def cmd_marcar_reparto(cfg, args):
    """
    Deja el aviso de perfiles pendientes de repartir en la base del panel.

    Lo llama deploy/reconstruir-ca.sh al terminar, con `sudo -u ovpnweb`. Que
    lo escriba ovpnweb y no root no es un detalle: si root tocara la base,
    SQLite dejaría archivos -wal y -shm de root en /var/lib/ovpn-web y las
    escrituras siguientes del panel fallarían con un permiso denegado que no
    menciona a root por ningún lado.
    """
    reparto = db.abrir_reparto(cfg.seguridad.db_path, args.motivo, args.cn,
                               detalle=args.detalle)
    print("Aviso de reparto #%d abierto para %d cliente(s)."
          % (reparto, len(set(args.cn))))
    print("Aparecerá en Clientes VPN hasta que alguien lo dé por hecho.")


def cmd_purgar_sesiones(cfg, args):
    db.purgar_sesiones(cfg.seguridad.db_path)
    db.purgar_logins_pendientes(cfg.seguridad.db_path)
    print("Sesiones y verificaciones caducadas eliminadas.")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m app.cli",
        description="Administración de cuentas del panel OpenVPN Manager Web",
    )
    parser.add_argument("--config", help="Ruta a config.yaml (por defecto /etc/ovpn-web/config.yaml)")

    subs = parser.add_subparsers(dest="comando", required=True)

    p = subs.add_parser("crear-usuario", help="Crea una cuenta de acceso al panel")
    p.add_argument("usuario")
    # ROLES_ASIGNABLES y no ROLES: el de superusuario no se pide, lo da ser el
    # primero. Ofrecerlo aquí sería prometer algo que la base rechaza.
    p.add_argument("--rol", choices=db.ROLES_ASIGNABLES, default=db.ROL_SUPERVISOR)
    p.set_defaults(func=cmd_crear_usuario)

    p = subs.add_parser("listar-usuarios", help="Lista las cuentas del panel")
    p.set_defaults(func=cmd_listar_usuarios)

    p = subs.add_parser("cambiar-password", help="Cambia la contraseña de una cuenta")
    p.add_argument("usuario")
    p.set_defaults(func=cmd_cambiar_password)

    p = subs.add_parser("purgar-sesiones", help="Borra las sesiones caducadas")
    p.set_defaults(func=cmd_purgar_sesiones)

    p = subs.add_parser(
        "marcar-reparto",
        help="Anota que estos clientes necesitan un perfil nuevo",
    )
    p.add_argument("motivo", choices=sorted(db.MOTIVOS))
    p.add_argument("cn", nargs="+")
    p.add_argument("--detalle", default=None)
    p.set_defaults(func=cmd_marcar_reparto)

    p = subs.add_parser(
        "designar-superusuario",
        help="Traslada el rol de superusuario a otra cuenta (solo desde el servidor)",
    )
    p.add_argument("usuario")
    p.add_argument("--si", dest="exigir_confirmacion", action="store_false",
                   help="No preguntar antes de hacerlo")
    p.set_defaults(func=cmd_superusuario, exigir_confirmacion=True)

    p = subs.add_parser(
        "totp-restablecer",
        help="Quita el segundo factor a una cuenta que se ha quedado fuera",
    )
    p.add_argument("usuario")
    p.set_defaults(func=cmd_totp_restablecer)

    p = subs.add_parser(
        "politica-totp",
        help="Consulta o cambia si el segundo factor es obligatorio para el rol supervisor",
    )
    p.add_argument("--exigir", choices=("si", "no"),
                   help="Sin este argumento solo muestra el estado actual")
    p.set_defaults(func=cmd_politica_totp)

    args = parser.parse_args(argv)
    cfg = cargar_config(args.config)
    db.init_db(cfg.seguridad.db_path)

    try:
        args.func(cfg, args)
    except ValueError as e:
        sys.exit("Error: %s" % e)


if __name__ == "__main__":
    main()
