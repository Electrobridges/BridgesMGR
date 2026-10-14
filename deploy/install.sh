#!/usr/bin/env bash
#
# Instalador de OpenVPN Manager Web para Debian/Ubuntu.
# Ejecutar como root DESDE la raíz del repo clonado:  sudo bash deploy/install.sh
#
# Es idempotente: puedes volver a lanzarlo para actualizar sin perder la base
# de datos ni la configuración.
#
# Si no encuentra un servidor OpenVPN montado, ofrece montarlo con
# deploy/instalar-openvpn.sh y luego rellena la configuración con lo que ese
# script haya decidido. Con --sin-openvpn se salta el ofrecimiento; con
# --con-openvpn lo monta sin preguntar.

# -E para que la trampa de ERR también salte dentro de las funciones.
set -Eeuo pipefail

DESTINO=/opt/ovpn-web
CONFIG_DIR=/etc/ovpn-web
DATOS_DIR=/var/lib/ovpn-web
HELPER=/usr/local/sbin/ovpn-web-helper
HOOK_CLIENT_CONNECT=/usr/local/lib/ovpn-web/client-connect
VERIFICAR_TOTP=/usr/local/lib/ovpn-web/verificar-totp
GRUPO_VPN=ovpnweb-vpn
ESTADO_TOTP=/var/lib/ovpn-web-vpn
USUARIO=ovpnweb
HTMX_VERSION=2.0.4
HTMX_URL="https://unpkg.com/htmx.org@${HTMX_VERSION}/dist/htmx.min.js"

# Lo que deja instalar-openvpn.sh para no tener que adivinar sus decisiones.
HECHOS_VPN=/run/ovpn-web-instalacion.env

# Un servidor OpenVPN se da por montado si tiene PKI y configuración.
PKI_ESPERADA=/etc/openvpn/easy-rsa/pki/ca.crt

# Todo lo que sale por pantalla queda también aquí, con fecha. Cuando una
# actualización falla, lo que se ve en la terminal ya se ha ido con el scroll
# o con la sesión SSH; esto no.
REGISTRO=/var/log/ovpn-web-instalacion.log
CERROJO=/run/ovpn-web-instalacion.lock

# Lo que hay que tener del repo para instalar. Se comprueba antes de tocar
# nada: un clon incompleto debe parar al principio, no a mitad.
NECESARIOS=(
  app/main.py requirements.txt deploy/ovpn-web-helper deploy/ovpn-web-client-connect
  deploy/ovpn-web-verificar-totp deploy/ovpn-web-acceso.service deploy/ovpn-web.service
  deploy/ovpnweb.sudoers deploy/config.ejemplo.yaml
)
PAQUETES=(python3 python3-venv python3-pip python3-yaml openssl curl ca-certificates nftables)

OPENVPN=preguntar          # preguntar | si | no
ASUMIR_SI=0
HTMX_CONFIAR=0
ARGS_VPN=()

rojo()  { printf '\033[31m%s\033[0m\n' "$*"; }
amar()  { printf '\033[33m%s\033[0m\n' "$*"; }
verde() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m==>\033[0m %s\n' "$*"; }

# ------------------------------------------------- fallos y avisos
#
# Dos clases de problema, y no se tratan igual:
#
#   - Lo que impide instalar (un archivo del repo que falta, pip que no puede
#     instalar las dependencias, un HTMX cuyo hash no cuadra) PARA, y dice en
#     qué paso, en qué línea, con qué orden y qué mirar.
#   - Lo que no lo impide (sin red para apt pero con los paquetes ya puestos,
#     el CDN de HTMX caído con un HTMX válido ya instalado, pip sin poder
#     actualizarse a sí mismo) AVISA y sigue. Y se repite todo junto al final,
#     porque un aviso en mitad de trescientas líneas no lo lee nadie.
#
# Volver a lanzar el instalador después de un fallo es siempre seguro.
PASO="preparación"
PISTA=""
AVISOS=()

paso() {
  PASO=$1
  PISTA=""
  info "$1"
}

aviso_final() {
  amar "  AVISO: $1"
  AVISOS+=("$1")
}

al_fallar() {
  local codigo=$1 linea=$2 orden=$3
  trap - ERR
  echo
  rojo "════════ LA INSTALACIÓN SE HA DETENIDO ════════"
  echo "  Paso:     $PASO"
  echo "  Línea:    $linea de deploy/install.sh"
  echo "  Orden:    $orden"
  echo "  Código:   $codigo"
  [[ -n $PISTA ]] && echo "  Qué mirar: $PISTA"
  echo "  Registro completo: $REGISTRO"
  echo
  echo "  Corregido el motivo, vuelve a lanzar el instalador: es seguro repetirlo."
  if [[ ${VUELTA_ATRAS:-0} == 1 ]]; then
    echo "  Se ha vuelto a la versión anterior y el panel corre con ella."
    echo "  La que falló está en $DESTINO/app.fallida, por si hay que mirarla."
  elif [[ ${APP_CAMBIADA:-0} == 0 ]]; then
    echo "  El panel en marcha NO se ha tocado: sigue con la versión anterior."
  fi
  exit "$codigo"
}
trap 'al_fallar $? $LINENO "$BASH_COMMAND"' ERR

# Para lo que no se puede arreglar sobre la marcha y no es un comando que
# falle por sí solo (una comprobación propia que no se cumple).
morir() {
  PISTA=${2:-$PISTA}
  rojo "$1"
  al_fallar 1 "${BASH_LINENO[0]}" "(comprobación del instalador) $1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --con-openvpn) OPENVPN=si; shift ;;
    --sin-openvpn) OPENVPN=no; shift ;;
    --si)          ASUMIR_SI=1; ARGS_VPN+=(--si); shift ;;
    --htmx-confiar) HTMX_CONFIAR=1; shift ;;
    --salida)      ARGS_VPN+=(--salida "${2:-}"); shift 2 ;;
    --host)        ARGS_VPN+=(--host "${2:-}"); shift 2 ;;
    -h|--help)
      cat <<'FIN'
Uso: sudo bash deploy/install.sh [opciones]

  --con-openvpn     Monta el servidor OpenVPN sin preguntar, si falta
  --sin-openvpn     No ofrecer montarlo (ya tienes uno, o lo harás aparte)
  --salida lan|todo Se le pasa a instalar-openvpn.sh (ver su --help)
  --host <destino>  Idem: por dónde llegan los clientes a la VPN
  --si              No preguntar nada
  --htmx-confiar    Aceptar el HTMX del CDN y fijar su hash. Solo para subir
                    de versión a conciencia: sin esto, si falta el hash
                    esperado la instalación aborta.
  -h, --help        Esta ayuda
FIN
      exit 0 ;;
    *) rojo "Opción desconocida: $1"; exit 1 ;;
  esac
done

[[ $EUID -eq 0 ]] || { rojo "Ejecuta como root"; exit 1; }
[[ -f app/main.py ]] || { rojo "Lanza el script desde la raíz del repo"; exit 1; }

# Dos instalaciones a la vez se pisarían el venv y la copia de la aplicación.
exec 9>"$CERROJO"
flock -n 9 || { rojo "Ya hay otra instalación en marcha (cerrojo $CERROJO)."; exit 1; }

touch "$REGISTRO" && chmod 0600 "$REGISTRO"
exec > >(tee -a "$REGISTRO") 2>&1
echo
echo "════════ $(date '+%Y-%m-%d %H:%M:%S') · install.sh $* ════════"
echo "  Repo:   $(pwd) · commit $(git rev-parse --short HEAD 2>/dev/null || echo 'desconocido')"
echo "  Sistema: $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || uname -sr)"
echo "  Registro: $REGISTRO"
echo

# --------------------------------------------------- comprobaciones previas
paso "Comprobaciones previas"
for archivo in "${NECESARIOS[@]}"; do
  [[ -f $archivo ]] || morir "Falta $archivo en el repo." \
    "El clon está incompleto: 'git status' y 'git pull', o clónalo de nuevo."
done

# Espacio: el venv son unos 150 MB y se guarda una copia de la versión
# anterior para poder volver atrás. Por debajo de 100 MB no se empieza.
LIBRE_MB=$(df -Pm "$(dirname "$DESTINO")" 2>/dev/null | awk 'NR==2 {print $4}' || true)
if [[ -n ${LIBRE_MB:-} ]]; then
  if (( LIBRE_MB < 100 )); then
    morir "Solo quedan ${LIBRE_MB} MB libres en $(dirname "$DESTINO")." "Libera espacio y repite."
  elif (( LIBRE_MB < 400 )); then
    aviso_final "Quedan ${LIBRE_MB} MB libres en $(dirname "$DESTINO"); la instalación puede quedarse corta."
  fi
fi

VERSION_ANTERIOR=""
if [[ -f "$DESTINO/app/__init__.py" ]]; then
  VERSION_ANTERIOR=$(sed -n 's/^__version__ = "\([^"]*\)"/\1/p' "$DESTINO/app/__init__.py")
  info "Actualización: hay instalada la versión ${VERSION_ANTERIOR:-desconocida}"
fi

# --------------------------------------------------- servidor OpenVPN
# Va lo primero para que todas las preguntas caigan juntas al principio, en vez
# de esperar cinco minutos de venv y encontrarse otra.
rm -f "$HECHOS_VPN"

VPN_PREEXISTENTE=0

if [[ -f "$PKI_ESPERADA" ]]; then
  info "Servidor OpenVPN detectado: no se toca"
  # Se comprueba al final, cuando ya exista config.yaml con qué contrastarlo.
  VPN_PREEXISTENTE=1
elif [[ "$OPENVPN" == "no" ]]; then
  amar "Sin servidor OpenVPN y con --sin-openvpn: se instala solo el panel."
else
  echo
  amar "No hay ningún servidor OpenVPN montado en esta máquina."
  echo "  Sin él el panel arranca, pero no tiene nada que administrar: no hay"
  echo "  PKI que listar ni conexiones que mostrar."
  echo

  MONTAR=0
  if [[ "$OPENVPN" == "si" || "$ASUMIR_SI" == "1" ]]; then
    MONTAR=1
  else
    read -rp "¿Montarlo ahora? [S/n]: " respuesta
    [[ "${respuesta,,}" == "n" || "${respuesta,,}" == "no" ]] || MONTAR=1
  fi

  if [[ "$MONTAR" == "1" ]]; then
    [[ -f deploy/instalar-openvpn.sh ]] || { rojo "Falta deploy/instalar-openvpn.sh"; exit 1; }
    bash deploy/instalar-openvpn.sh "${ARGS_VPN[@]+"${ARGS_VPN[@]}"}"
  else
    amar "De acuerdo. Tendrás que ajustar /etc/ovpn-web/config.yaml a mano."
  fi
fi

# --------------------------------------------------------------- paquetes
# Solo se instala lo que falta. Si todo está y no hay red para apt —un mirror
# caído, una LAN sin salida—, actualizar el panel no tiene por qué fallar.
paso "Dependencias del sistema"
FALTAN=()
for paquete in "${PAQUETES[@]}"; do
  dpkg -s "$paquete" >/dev/null 2>&1 || FALTAN+=("$paquete")
done

if (( ${#FALTAN[@]} )); then
  PISTA="apt no puede descargar: revisa la red y /etc/apt/sources.list, o instala a mano: apt-get install ${FALTAN[*]}"
  info "Faltan: ${FALTAN[*]}"
  apt-get update -qq
  apt-get install -y --no-install-recommends "${FALTAN[@]}"
else
  verde "Todas las dependencias del sistema ya están instaladas"
fi

# Python 3.9 es el mínimo del panel (Debian 11). Se mira ahora porque antes
# de apt podía no estar instalado.
PISTA="Hace falta Python 3.9 o posterior (Debian 11, Ubuntu 20.04 o más nuevos)."
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
  || morir "Python $(python3 -V 2>&1) es demasiado antiguo."

# --------------------------------------------------------------- usuario
paso "Usuario y grupos del sistema"
if ! id -u "$USUARIO" >/dev/null 2>&1; then
  info "Creando usuario de sistema '$USUARIO'"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$USUARIO"
fi

# Grupo 'adm' es el dueño de /var/log en Debian: así el panel lee los logs de
# OpenVPN sin pasar por el helper privilegiado.
info "Añadiendo '$USUARIO' al grupo adm (lectura de logs)"
usermod -aG adm "$USUARIO"

# --------------------------------------------------------------- archivos
# La versión nueva se prepara al lado, en app.nuevo, y solo sustituye a la que
# corre cuando todo lo demás —HTMX, dependencias— ha salido bien. Antes se
# copiaba encima con 'cp -r': un fallo a mitad dejaba mezcladas las dos
# versiones, y los archivos que la nueva ya no trae se quedaban para siempre.
paso "Preparando la versión nueva de la aplicación"
mkdir -p "$DESTINO"
rm -rf "$DESTINO/app.nuevo"
cp -r app "$DESTINO/app.nuevo"
find "$DESTINO/app.nuevo" -name __pycache__ -type d -prune -exec rm -rf {} +
cp requirements.txt "$DESTINO/"

paso "Helper privilegiado y scripts de OpenVPN"
info "Instalando el helper privilegiado en $HELPER"
install -o root -g root -m 0750 deploy/ovpn-web-helper "$HELPER"

# Lo ejecuta OpenVPN en cada conexión para aplicar las políticas por cliente.
# Fuera de ReadWritePaths y de root: el panel decide las políticas, pero no
# puede cambiar el código que OpenVPN corre con ellas.
info "Instalando el script de políticas en $HOOK_CLIENT_CONNECT"
install -d -o root -g root -m 0755 "$(dirname "$HOOK_CLIENT_CONNECT")"
install -o root -g root -m 0755 deploy/ovpn-web-client-connect "$HOOK_CLIENT_CONNECT"
install -o root -g root -m 0755 deploy/ovpn-web-verificar-totp "$VERIFICAR_TOTP"

# Verificación en dos pasos de la VPN. El grupo es el que tiene que llevar
# OpenVPN ('group ovpnweb-vpn' en el server.conf) para leer los secretos; el
# directorio es donde el script anota el último código aceptado.
getent group "$GRUPO_VPN" >/dev/null || groupadd --system "$GRUPO_VPN"
install -d -o root -g "$GRUPO_VPN" -m 0770 "$ESTADO_TOTP"

# Recarga las reglas de acceso por cliente al arrancar la máquina. Las escribe
# el helper en /etc/openvpn/ovpn-web/acceso.nft; sin esta unidad se perderían
# en el primer reinicio y los clientes limitados volverían a llegar a todo.
install -m 0644 deploy/ovpn-web-acceso.service /etc/systemd/system/ovpn-web-acceso.service

# --------------------------------------------------------------- htmx
# El panel tiene una CSP estricta (script-src 'self'), así que HTMX se sirve
# desde local. Y justo por eso hay que verificarlo: un archivo servido desde
# el propio panel pasa la CSP, así que un HTMX manipulado sería JavaScript
# arbitrario ejecutándose con la sesión del administrador.
#
# El hash esperado va en deploy/htmx.sha256, versionado en el repo. Si falta,
# esto ABORTA en vez de guardar lo que devuelva el CDN: aceptar a ciegas un
# script de una red ajena es exactamente lo que la verificación evita. Para el
# caso legítimo de subir de versión está --htmx-confiar, que hay que teclear a
# conciencia.
paso "HTMX $HTMX_VERSION"
HTMX_INSTALADO="$DESTINO/app/static/htmx.min.js"
HASH_ESPERADO=""
[[ -f deploy/htmx.sha256 ]] && HASH_ESPERADO=$(tr -d '[:space:]' < deploy/htmx.sha256)

TMP_HTMX=$(mktemp)
if curl -fsSL --retry 2 --max-time 60 "$HTMX_URL" -o "$TMP_HTMX"; then
  HASH_ACTUAL=$(sha256sum "$TMP_HTMX" | cut -d' ' -f1)

  if [[ -n $HASH_ESPERADO ]]; then
    if [[ "$HASH_ACTUAL" != "$HASH_ESPERADO" ]]; then
      rm -f "$TMP_HTMX"
      rojo "El hash de HTMX no coincide con deploy/htmx.sha256"
      rojo "  esperado: $HASH_ESPERADO"
      rojo "  obtenido: $HASH_ACTUAL"
      morir "Revísalo antes de continuar." \
        "Puede ser un CDN manipulado o una versión distinta. No sigas sin entender por qué."
    fi
    verde "Hash de HTMX verificado"
  elif [[ "$HTMX_CONFIAR" == "1" ]]; then
    echo "$HASH_ACTUAL" > deploy/htmx.sha256
    amar "Hash de HTMX aceptado sin verificar (--htmx-confiar): $HASH_ACTUAL"
    echo "    Súbelo al repo AHORA, o la próxima instalación volverá a confiar a ciegas."
  else
    rm -f "$TMP_HTMX"
    rojo "Falta deploy/htmx.sha256 y no se acepta lo que devuelva el CDN sin más."
    echo
    echo "  HTMX se sirve desde el propio panel, así que la CSP lo da por bueno:"
    echo "  un archivo manipulado sería JavaScript corriendo con tu sesión de"
    echo "  administrador. Por eso se verifica contra un hash del repo."
    echo
    echo "  El hash obtenido ahora ha sido:"
    echo "      $HASH_ACTUAL"
    echo
    echo "  Si tu copia del repo debería traer ese archivo, es que el clon está"
    echo "  incompleto. Si estás subiendo de versión a conciencia, compáralo con"
    echo "  el que publica htmx y repite con:"
    echo "      sudo bash deploy/install.sh --htmx-confiar"
    morir "Sin hash de HTMX con el que comparar."
  fi
  install -m 0644 "$TMP_HTMX" "$DESTINO/app.nuevo/static/htmx.min.js"
elif [[ -n $HASH_ESPERADO && -f $HTMX_INSTALADO ]] \
     && [[ $(sha256sum "$HTMX_INSTALADO" | cut -d' ' -f1) == "$HASH_ESPERADO" ]]; then
  # Sin red hacia el CDN pero con el mismo HTMX ya instalado y verificado: no
  # hay nada que descargar, y una actualización no tiene por qué fallar por esto.
  aviso_final "No se pudo descargar HTMX; se conserva el instalado, que coincide con el hash esperado."
  install -m 0644 "$HTMX_INSTALADO" "$DESTINO/app.nuevo/static/htmx.min.js"
else
  rm -f "$TMP_HTMX"
  morir "No se pudo descargar HTMX de $HTMX_URL y no hay uno válido instalado." \
    "Sin HTMX el panel no funciona. Comprueba la salida a internet: curl -I $HTMX_URL"
fi
rm -f "$TMP_HTMX"

# --------------------------------------------------------------- venv
# requirements.txt es un lock: versiones exactas y el SHA-256 de cada artefacto,
# generado de requirements.in. Con --require-hashes, si PyPI o un espejo
# devuelven algo distinto de lo que se probó, pip aborta en vez de instalarlo.
# Es la misma idea que el hash de HTMX, aplicada a las 30 dependencias.
paso "Entorno virtual y dependencias de Python"
PISTA="¿Está instalado python3-venv? apt-get install python3-venv"
python3 -m venv "$DESTINO/venv"

# Única descarga que no va con hash fijado, y conviene saberlo: el pip que trae
# Debian 11 es de 2020 y tropieza con metadatos de paquetes actuales. Se
# actualiza desde PyPI con TLS y nada más. Si no puede, se sigue con el que
# hay: a menudo basta, y si no, el paso siguiente lo dirá.
if ! "$DESTINO/venv/bin/pip" install --quiet --upgrade pip; then
  aviso_final "No se pudo actualizar pip; se sigue con el que trae el venv."
fi

PISTA="pip no pudo instalar las dependencias: mira el error justo encima (red hacia PyPI, un hash que no cuadra, falta de espacio). El panel en marcha no se ha tocado."
if grep -q -- "--hash=sha256:" "$DESTINO/requirements.txt"; then
  info "Instalando dependencias con hashes verificados"
  "$DESTINO/venv/bin/pip" install --quiet --require-hashes -r "$DESTINO/requirements.txt"
  verde "Dependencias verificadas contra el lock"
else
  amar "requirements.txt no lleva hashes: se instala sin verificar integridad."
  echo "    Regenera el lock con:  uv pip compile requirements.in \\"
  echo "        --python-version 3.9 --generate-hashes -o requirements.txt"
  "$DESTINO/venv/bin/pip" install --quiet -r "$DESTINO/requirements.txt"
fi

# Comprobación de humo: que la versión nueva al menos importa con las
# dependencias recién instaladas. Un error de sintaxis o una dependencia que
# falta se ven aquí, con la versión anterior todavía en marcha, y no después
# de reiniciar el panel.
if ! (cd "$DESTINO" && "$DESTINO/venv/bin/python" -c "
import importlib.util, sys
spec = importlib.util.spec_from_file_location('app', 'app.nuevo/__init__.py',
                                              submodule_search_locations=['app.nuevo'])
mod = importlib.util.module_from_spec(spec); sys.modules['app'] = mod; spec.loader.exec_module(mod)
import app.main, app.vigilante, app.cli
print('  La versión nueva importa bien:', mod.__version__)
"); then
  morir "La versión nueva no arranca con estas dependencias." \
    "El error de Python está justo encima. El panel en marcha no se ha tocado."
fi

# Y que el config.yaml que ya hay se pueda cargar con ESTE código. Una clave
# que la versión nueva no conoce, o una errata, tumbaría el panel al
# reiniciarlo; mejor pararse aquí, con la versión anterior todavía en marcha
# y el motivo delante.
if [[ -f "$CONFIG_DIR/config.yaml" ]]; then
  if ! ERROR_CFG=$(cd "$DESTINO" && OVPN_WEB_CONFIG="$CONFIG_DIR/config.yaml" \
       "$DESTINO/venv/bin/python" -c "
import importlib.util, sys
spec = importlib.util.spec_from_file_location('app', 'app.nuevo/__init__.py',
                                              submodule_search_locations=['app.nuevo'])
mod = importlib.util.module_from_spec(spec); sys.modules['app'] = mod; spec.loader.exec_module(mod)
from app.config import cargar_config
cargar_config()
" 2>&1); then
    echo "$ERROR_CFG" | tail -3 | sed 's/^/    /'
    morir "$CONFIG_DIR/config.yaml no se puede cargar con la versión nueva." \
      "Corrige la clave que dice el error (docs/configuracion.md lista todas) y repite. El panel en marcha no se ha tocado."
  fi
fi

# --------------------------------------------------------------- cambio
# Ahora sí: la nueva pasa a ser la que corre y la anterior se guarda al lado,
# para poder volver a ella si el panel no arranca. Solo se conserva una.
paso "Instalando la versión nueva"
rm -rf "$DESTINO/app.anterior"
[[ -d "$DESTINO/app" ]] && mv "$DESTINO/app" "$DESTINO/app.anterior"
mv "$DESTINO/app.nuevo" "$DESTINO/app"
APP_CAMBIADA=1

# --------------------------------------------------------------- config
paso "Configuración"
mkdir -p "$CONFIG_DIR/tls" "$DATOS_DIR"

IP_LAN=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || true)
IP_LAN=${IP_LAN:-127.0.0.1}

# Reescribe una clave del YAML dejando intactos los comentarios: la mitad del
# valor de config.ejemplo.yaml está en ellos, y un volcado con un parser de
# YAML se los llevaría por delante.
fijar_clave() {
  local archivo=$1 clave=$2 valor=$3 comillas=${4:-si}
  [[ -n "$valor" ]] || return 0

  if [[ "$valor" == *'|'* || "$valor" == *$'\n'* ]]; then
    amar "Valor con caracteres raros para '$clave'; se deja el de ejemplo"
    return 0
  fi

  if [[ "$comillas" == "si" ]]; then
    sed -i -E "s|^([[:space:]]*${clave}:).*|\\1 \"${valor}\"|" "$archivo"
  else
    sed -i -E "s|^([[:space:]]*${clave}:).*|\\1 ${valor}|" "$archivo"
  fi
}

if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
  info "Instalando configuración de ejemplo"
  install -o root -g "$USUARIO" -m 0640 deploy/config.ejemplo.yaml "$CONFIG_DIR/config.yaml"
  CONFIG_NUEVA=1

  fijar_clave "$CONFIG_DIR/config.yaml" host_bind "$IP_LAN"

  # Si acabamos de montar la VPN, sus decisiones ya están tomadas: no tiene
  # sentido pedirle a nadie que las copie a mano de una pantalla a un archivo.
  if [[ -f "$HECHOS_VPN" ]]; then
    # shellcheck disable=SC1090
    . "$HECHOS_VPN"
    info "Rellenando la configuración con lo que montó instalar-openvpn.sh"
    fijar_clave "$CONFIG_DIR/config.yaml" remote_host   "${OVPN_REMOTE_HOST:-}"
    fijar_clave "$CONFIG_DIR/config.yaml" remote_puerto "${OVPN_REMOTE_PUERTO:-}" no
    fijar_clave "$CONFIG_DIR/config.yaml" proto         "${OVPN_PROTO:-}"
    fijar_clave "$CONFIG_DIR/config.yaml" servicio      "${OVPN_UNIDAD:-}"
    # La VPN recién montada usa GCM; el ejemplo trae CBC por compatibilidad.
    fijar_clave "$CONFIG_DIR/config.yaml" cipher        "AES-256-GCM"
    CONFIG_RELLENA=1
  else
    CONFIG_RELLENA=0
  fi
else
  info "Conservando $CONFIG_DIR/config.yaml existente"
  chown root:"$USUARIO" "$CONFIG_DIR/config.yaml"
  chmod 0640 "$CONFIG_DIR/config.yaml"
  CONFIG_NUEVA=0
  CONFIG_RELLENA=0

  if [[ -f "$HECHOS_VPN" ]]; then
    amar "Se ha montado una VPN nueva pero ya había config.yaml: no se toca."
    echo "  Revisa a mano que estas claves cuadran con el servidor recién montado:"
    sed 's/^/      /' "$HECHOS_VPN"
  fi
fi

# --------------------------------------------------------------- TLS
paso "Certificado TLS del panel"
if [[ ! -f "$CONFIG_DIR/tls/cert.pem" ]]; then
  info "Generando certificado autofirmado para $IP_LAN (10 años)"

  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$CONFIG_DIR/tls/key.pem" \
    -out "$CONFIG_DIR/tls/cert.pem" \
    -subj "/CN=$IP_LAN/O=OpenVPN Manager Web" \
    -addext "subjectAltName=IP:$IP_LAN,IP:127.0.0.1" 2>/dev/null

  verde "Certificado creado. El navegador avisará de que es autofirmado: es esperado."
fi

chown -R root:"$USUARIO" "$CONFIG_DIR"
chmod 0750 "$CONFIG_DIR" "$CONFIG_DIR/tls"
chmod 0640 "$CONFIG_DIR/tls/cert.pem" "$CONFIG_DIR/tls/key.pem"

chown -R "$USUARIO":"$USUARIO" "$DATOS_DIR"
chmod 0750 "$DATOS_DIR"
chown -R root:root "$DESTINO"

# --------------------------------------------------------------- sudoers
paso "Regla de sudo"
PISTA="visudo rechaza deploy/ovpnweb.sudoers: no se instala, para no romper sudo. ¿Lo has editado?"
visudo -c -f deploy/ovpnweb.sudoers >/dev/null
install -o root -g root -m 0440 deploy/ovpnweb.sudoers /etc/sudoers.d/ovpnweb

# --------------------------------------------------------------- systemd
paso "Servicio systemd"
install -m 0644 deploy/ovpn-web.service /etc/systemd/system/ovpn-web.service
systemctl daemon-reload
systemctl enable ovpn-web >/dev/null
systemctl enable ovpn-web-acceso >/dev/null

# Si el panel ya corría, esto es una actualización: el código nuevo está en
# disco pero el proceso sigue siendo el viejo, y sin reiniciarlo se cree haber
# subido de versión sin haberlo hecho. Pasó dos veces seguidas en producción
# y se descubrió mirando ActiveEnterTimestamp. En una instalación nueva no se
# arranca: la configuración aún no está revisada y no existe ninguna cuenta.
PANEL_REINICIADO=0
case "$(systemctl is-active ovpn-web 2>/dev/null || true)" in
  active|activating|reloading)
    info "El panel ya corría: reiniciándolo con el código nuevo"
    systemctl restart ovpn-web
    PANEL_REINICIADO=1
    ;;
  failed)
    amar "El panel estaba en estado 'failed': se arranca con el código nuevo"
    systemctl restart ovpn-web
    PANEL_REINICIADO=1
    ;;
esac
# Espera a que el panel esté de verdad en pie. La unidad es Type=simple:
# systemd la da por activa en cuanto lanza el proceso, así que preguntar al
# instante diría "activo" también de un código que revienta al importar. Se
# dejan pasar unos segundos —un fallo de arranque cae en uno o dos— y luego se
# comprueba de verdad. Con Restart=on-failure el estado entre intentos es
# 'activating', que is-active tampoco da por bueno.
panel_en_pie() {
  sleep 4
  for _ in 1 2 3 4 5 6; do
    systemctl is-active --quiet ovpn-web && return 0
    sleep 1
  done
  systemctl is-active --quiet ovpn-web
}

if [[ "$PANEL_REINICIADO" == "1" ]]; then
  if panel_en_pie; then
    verde "Panel reiniciado y activo"
    # Lo que quedó de una actualización fallida anterior ya no hace falta.
    rm -rf "$DESTINO/app.fallida"
  else
    rojo "El panel no arranca con el código nuevo. Lo último que dijo:"
    journalctl -u ovpn-web -n 30 --no-pager 2>/dev/null | sed 's/^/    /' || true

    # Volver atrás: un panel caído es peor que uno sin actualizar. La versión
    # que falla se deja en app.fallida para poder mirarla.
    if [[ -d "$DESTINO/app.anterior" ]]; then
      amar "Volviendo a la versión anterior (${VERSION_ANTERIOR:-desconocida})…"
      rm -rf "$DESTINO/app.fallida"
      mv "$DESTINO/app" "$DESTINO/app.fallida"
      mv "$DESTINO/app.anterior" "$DESTINO/app"
      systemctl restart ovpn-web || true
      if panel_en_pie; then
        amar "El panel vuelve a correr con la versión anterior. La nueva está en $DESTINO/app.fallida."
        VUELTA_ATRAS=1
      else
        rojo "Tampoco arranca la versión anterior: el problema no es del código nuevo."
        echo "  Lo más probable es config.yaml o la base de datos. Mira:"
        echo "      journalctl -u ovpn-web -n 50 --no-pager"
      fi
    fi
    PISTA="journalctl -u ovpn-web -n 50 --no-pager  (registro: $REGISTRO)"
    morir "La actualización no se ha completado."
  fi
fi

# ------------------------------------------------- historial ya rotado
# El panel guarda los sucesos de la VPN según se escriben, pero de antes de
# tener esa función no tiene nada, y en el disco sí que hay: logrotate conserva
# unas ocho semanas de openvpn.log.N(.gz) que se iban a borrar sin que nadie
# las hubiera leído. Esto las recupera.
#
# Va en cada actualización y no solo en la primera porque es idempotente por
# construcción —solo entra lo anterior al suceso más antiguo que ya hay—, así
# que a partir de la segunda vez no hace nada y lo dice en una línea. Y si
# falla no se para la instalación: es historia vieja, no el servicio.
#
# Como el usuario del panel y no como root: la base es suya, y un -wal o un
# -journal que quedara de root la dejaría sin poder escribir.
if [[ -f "$CONFIG_DIR/config.yaml" ]]; then
  info "Recuperando el historial de la VPN de los logs ya rotados"
  if ! (cd "$DESTINO" && sudo -u "$USUARIO" venv/bin/python -m app.cli importar-eventos); then
    amar "No se pudo recuperar el historial de los logs rotados."
    echo "  No afecta al panel; lo de ahora en adelante se guarda igual. Míralo con:"
    echo "      cd $DESTINO && sudo -u $USUARIO venv/bin/python -m app.cli importar-eventos"
  fi
fi

# ---------------------------------------------------------- fechas del log
# Esto es lo único que alcanza a un servidor ya instalado: instalar-openvpn.sh
# solo pasa al montar la VPN, y el añadido hace falta en cualquier máquina
# cuyo OpenVPN venga de un paquete. Es idempotente y solo reinicia si de
# verdad ha cambiado algo, así que una actualización rutinaria no corta a
# nadie: el corte ocurre una vez por servidor, la primera.
#
# -f y no -x: el bit de ejecución no sobrevive a un clon hecho desde Windows.
if [[ -f "$(dirname "$0")/fechas-log.sh" ]]; then
  if ! bash "$(dirname "$0")/fechas-log.sh" --reiniciar; then
    amar "El log de OpenVPN se queda sin fecha: la vista de sesiones no podrá"
    echo "  dar duraciones. Revísalo con:"
    echo "      sudo bash deploy/comprobar-servidor.sh"
  fi
fi

echo
# La versión sale de app/__init__.py, que es lo que acaba de copiarse: lo que
# se imprime es lo que hay en disco, no lo que dice el clon. Sin esto, saber
# qué versión corre un servidor obligaba a comparar hashes contra git.
VERSION_PANEL=$(sed -n 's/^__version__ = "\([^"]*\)"/\1/p' "$DESTINO/app/__init__.py")
if [[ -n $VERSION_ANTERIOR ]]; then
  verde "Actualización completada: BridgesMGR ${VERSION_ANTERIOR} → ${VERSION_PANEL:-desconocida}."
  echo "  La versión anterior queda en $DESTINO/app.anterior por si hay que volver a ella."
else
  verde "Instalación completada: BridgesMGR ${VERSION_PANEL:-versión desconocida}."
fi
echo
if [[ "$CONFIG_NUEVA" == "1" && "$CONFIG_RELLENA" == "1" ]]; then
  echo "La configuración ya está rellena con lo que se acaba de montar."
  echo "Repásala de todas formas, sobre todo cliente_ovpn.remote_host:"
  echo "    nano $CONFIG_DIR/config.yaml"
  echo
elif [[ "$CONFIG_NUEVA" == "1" ]]; then
  echo "SIGUIENTE PASO OBLIGATORIO — revisa la configuración:"
  echo "    nano $CONFIG_DIR/config.yaml"
  echo "  Ajusta al menos: servidor.host_bind, openvpn.status_path,"
  echo "  openvpn.servicio y cliente_ovpn.remote_host."
  echo
fi
# Solo en una instalación nueva: en una actualización ya hay cuentas y esto
# era ruido que se leía justo antes del "arranca el panel".
if [[ "$CONFIG_NUEVA" == "1" ]]; then
  echo "Crea el primer administrador:"
  echo "    cd $DESTINO && sudo -u $USUARIO venv/bin/python -m app.cli crear-usuario TU_USUARIO --rol admin"
  echo "    (la primera cuenta es el superusuario de la instalacion)"
  echo
fi
if [[ "$PANEL_REINICIADO" == "1" ]]; then
  echo "El panel ya está corriendo con esta versión."
else
  echo "Arranca el panel:"
  echo "    systemctl start ovpn-web && systemctl status ovpn-web"
fi
echo
echo "Y ábrelo en:  https://<IP_DEL_SERVIDOR>:55443"

# Un OpenVPN que ya existía casi nunca encaja con lo que el panel espera: rutas
# relativas, la CRL duplicada, otro nombre de unidad, los logs sin permisos. Y
# varios de esos desajustes no dan la cara hasta que hace falta —revocar y que
# no surta efecto. Mejor decirlo aquí que descubrirlo el día malo.
# -f y no -x: el bit de ejecución no sobrevive a un clon hecho desde Windows,
# donde no existe. instalar-openvpn.sh tampoco lo tiene y nunca hizo falta,
# porque los dos se invocan con 'bash'. Con -x esto se saltaba en silencio.
if [[ "$VPN_PREEXISTENTE" == "1" && -f "$(dirname "$0")/comprobar-servidor.sh" ]]; then
  echo
  info "Tu servidor OpenVPN ya existía: comprobando que encaja con el panel"
  echo
  if bash "$(dirname "$0")/comprobar-servidor.sh"; then
    :
  else
    echo
    rojo "Hay problemas CRÍTICOS que resolver antes de usar el panel."
    echo "  El panel está instalado y arrancará, pero alguna función no hará"
    echo "  lo que dice. Vuelve a lanzar la comprobación cuando los corrijas:"
    echo "      sudo bash deploy/comprobar-servidor.sh"
  fi
fi

# ------------------------------------------------------------ resumen
# Lo que no paró la instalación pero hay que mirar, todo junto y al final.
if (( ${#AVISOS[@]} )); then
  echo
  amar "════════ ${#AVISOS[@]} AVISO(S) QUE REVISAR ════════"
  for a in "${AVISOS[@]}"; do
    amar "  · $a"
  done
fi
echo
echo "Registro completo de esta instalación: $REGISTRO"
