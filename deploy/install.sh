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

set -euo pipefail

DESTINO=/opt/ovpn-web
CONFIG_DIR=/etc/ovpn-web
DATOS_DIR=/var/lib/ovpn-web
HELPER=/usr/local/sbin/ovpn-web-helper
USUARIO=ovpnweb
HTMX_VERSION=2.0.4
HTMX_URL="https://unpkg.com/htmx.org@${HTMX_VERSION}/dist/htmx.min.js"

# Lo que deja instalar-openvpn.sh para no tener que adivinar sus decisiones.
HECHOS_VPN=/run/ovpn-web-instalacion.env

# Un servidor OpenVPN se da por montado si tiene PKI y configuración.
PKI_ESPERADA=/etc/openvpn/easy-rsa/pki/ca.crt

OPENVPN=preguntar          # preguntar | si | no
ASUMIR_SI=0
HTMX_CONFIAR=0
ARGS_VPN=()

rojo()  { printf '\033[31m%s\033[0m\n' "$*"; }
amar()  { printf '\033[33m%s\033[0m\n' "$*"; }
verde() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m==>\033[0m %s\n' "$*"; }

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

# --------------------------------------------------- servidor OpenVPN
# Va lo primero para que todas las preguntas caigan juntas al principio, en vez
# de esperar cinco minutos de venv y encontrarse otra.
rm -f "$HECHOS_VPN"

if [[ -f "$PKI_ESPERADA" ]]; then
  info "Servidor OpenVPN detectado: no se toca"
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
info "Instalando dependencias del sistema"
apt-get update -qq
apt-get install -y --no-install-recommends \
  python3 python3-venv python3-pip python3-yaml openssl curl ca-certificates

# --------------------------------------------------------------- usuario
if ! id -u "$USUARIO" >/dev/null 2>&1; then
  info "Creando usuario de sistema '$USUARIO'"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$USUARIO"
fi

# Grupo 'adm' es el dueño de /var/log en Debian: así el panel lee los logs de
# OpenVPN sin pasar por el helper privilegiado.
info "Añadiendo '$USUARIO' al grupo adm (lectura de logs)"
usermod -aG adm "$USUARIO"

# --------------------------------------------------------------- archivos
info "Copiando la aplicación a $DESTINO"
mkdir -p "$DESTINO"
cp -r app "$DESTINO/"
cp requirements.txt "$DESTINO/"

info "Instalando el helper privilegiado en $HELPER"
install -o root -g root -m 0750 deploy/ovpn-web-helper "$HELPER"

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
info "Obteniendo HTMX $HTMX_VERSION"
TMP_HTMX=$(mktemp)
curl -fsSL "$HTMX_URL" -o "$TMP_HTMX"
HASH_ACTUAL=$(sha256sum "$TMP_HTMX" | cut -d' ' -f1)

if [[ -f deploy/htmx.sha256 ]]; then
  HASH_ESPERADO=$(tr -d '[:space:]' < deploy/htmx.sha256)
  if [[ "$HASH_ACTUAL" != "$HASH_ESPERADO" ]]; then
    rm -f "$TMP_HTMX"
    rojo "El hash de HTMX no coincide con deploy/htmx.sha256"
    rojo "  esperado: $HASH_ESPERADO"
    rojo "  obtenido: $HASH_ACTUAL"
    rojo "Revísalo antes de continuar."
    exit 1
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
  exit 1
fi

install -m 0644 "$TMP_HTMX" "$DESTINO/app/static/htmx.min.js"
rm -f "$TMP_HTMX"

# --------------------------------------------------------------- venv
# requirements.txt es un lock: versiones exactas y el SHA-256 de cada artefacto,
# generado de requirements.in. Con --require-hashes, si PyPI o un espejo
# devuelven algo distinto de lo que se probó, pip aborta en vez de instalarlo.
# Es la misma idea que el hash de HTMX, aplicada a las 30 dependencias.
info "Creando entorno virtual"
python3 -m venv "$DESTINO/venv"

# Única descarga que no va con hash fijado, y conviene saberlo: el pip que trae
# Debian 11 es de 2020 y tropieza con metadatos de paquetes actuales. Se
# actualiza desde PyPI con TLS y nada más.
"$DESTINO/venv/bin/pip" install --quiet --upgrade pip

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

# --------------------------------------------------------------- config
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
info "Instalando regla de sudo"
visudo -c -f deploy/ovpnweb.sudoers >/dev/null
install -o root -g root -m 0440 deploy/ovpnweb.sudoers /etc/sudoers.d/ovpnweb

# --------------------------------------------------------------- systemd
info "Instalando servicio systemd"
install -m 0644 deploy/ovpn-web.service /etc/systemd/system/ovpn-web.service
systemctl daemon-reload
systemctl enable ovpn-web >/dev/null

echo
verde "Instalación completada."
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
echo "Crea el primer administrador:"
echo "    cd $DESTINO && sudo -u $USUARIO venv/bin/python -m app.cli crear-usuario TU_USUARIO --rol admin"
echo "    (la primera cuenta es el superusuario de la instalacion)"
echo
echo "Arranca el panel:"
echo "    systemctl start ovpn-web && systemctl status ovpn-web"
echo
echo "Y ábrelo en:  https://<IP_DEL_SERVIDOR>:55443"
