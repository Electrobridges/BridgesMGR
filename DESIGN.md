---
name: OpenVPN Manager Web
description: Panel de operación VPN con la identidad Electrobridges — navy profundo, cian de instrumento, Poppins.
colors:
  navy-abismo: "#081731"
  navy-superficie: "#0b1b34"
  navy-elevado: "#0f2544"
  navy-tinta: "#03132b"
  cian-marca: "#10c4d8"
  cian-instrumento: "#83ebf5"
  cian-hondo: "#087ea5"
  blanco: "#ffffff"
  texto-segundo: "rgba(255,255,255,0.72)"
  texto-tenue: "rgba(255,255,255,0.62)"
  texto-apagado: "rgba(255,255,255,0.5)"
  linea: "rgba(255,255,255,0.08)"
  linea-fuerte: "rgba(255,255,255,0.14)"
  verde-enlace: "#5bf1a8"
  ambar-alerta: "#fbbf24"
  rojo-corte: "#f87171"
  azul-dato: "#60a5fa"
typography:
  display:
    fontFamily: "Poppins, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1.6rem"
    fontWeight: 800
    lineHeight: 1.1
    letterSpacing: "-0.03em"
  headline:
    fontFamily: "Poppins, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1.05rem"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "-0.01em"
  metric:
    fontFamily: "Poppins, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1.75rem"
    fontWeight: 800
    lineHeight: 1.1
    letterSpacing: "-0.03em"
  nav:
    fontFamily: "Poppins, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.9rem"
    fontWeight: 600
  body:
    fontFamily: "Poppins, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.9375rem"
    fontWeight: 400
    lineHeight: 1.55
  label:
    fontFamily: "Poppins, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.72rem"
    fontWeight: 600
    letterSpacing: "0.12em"
  mono:
    fontFamily: "ui-monospace, 'Cascadia Code', Consolas, monospace"
    fontSize: "0.82rem"
    lineHeight: 1.45
rounded:
  sm: "8px"
  md: "12px"
  lg: "14px"
  full: "999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "16px"
  lg: "24px"
  xl: "32px"
components:
  button-primary:
    backgroundColor: "{colors.cian-marca}"
    textColor: "{colors.navy-tinta}"
    rounded: "{rounded.lg}"
    padding: "10px 18px"
  button-primary-hover:
    backgroundColor: "{colors.cian-instrumento}"
    textColor: "{colors.navy-tinta}"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.texto-segundo}"
    rounded: "{rounded.lg}"
    padding: "9px 17px"
  button-ghost-hover:
    backgroundColor: "{colors.navy-elevado}"
    textColor: "{colors.blanco}"
  card:
    backgroundColor: "{colors.navy-superficie}"
    rounded: "{rounded.md}"
    padding: "18px"
  input:
    backgroundColor: "{colors.navy-abismo}"
    textColor: "{colors.blanco}"
    rounded: "{rounded.sm}"
    padding: "9px 12px"
  badge:
    rounded: "{rounded.full}"
    padding: "2px 10px"
    typography: "{typography.label}"
---

# Design System: OpenVPN Manager Web

## Overview

**Creative North Star: "El Puente de Mando"**

Un puente de mando de noche. La sala está a oscuras a propósito para que lo único
que brille sean los instrumentos, y cada instrumento dice una cosa cierta sobre un
enlace que está vivo ahí fuera. El nombre de la casa —Electrobridges— ya describe
el trabajo: vigilar puentes entre puntos. Este panel es la consola desde la que se
vigilan.

De ahí salen las tres decisiones que mandan. El fondo es navy profundo y **no
compite**: no hay gradientes, ni glows, ni cristal esmerilado en las zonas de
trabajo. El cian es luz de instrumento y por eso es escaso: marca dónde estás,
qué acción es la principal y poco más. Y la profundidad se construye con líneas
de 1px, nunca con sombras pesadas, porque una tabla de conexiones tiene que
leerse como un panel de lecturas, no como una pila de tarjetas flotantes.

Hereda la identidad de `electrobridges.com` —su navy, su cian, su Poppins de
peso alto con tracking negativo— pero rechaza explícitamente lo que ese sitio
usa para persuadir: los glows radiales, los gradientes de héroe y los
`backdrop-filter`. Ahí venden; aquí se opera.

**Key Characteristics:**
- Navy profundo constante, sin gradientes en zonas de trabajo
- Cian de instrumento, escaso y siempre significativo
- Profundidad por línea de 1px, jamás por sombra pesada
- Poppins 800 con tracking `-0.03em` en cifras y títulos
- Densidad alta: es una consola, no una landing

## Colors

Paleta de sala oscura: un navy que se aparta y un cian que señala.

### Primary
- **Cian Marca** (`#10c4d8`): la luz de instrumento. Acción principal, enlace de
  navegación activo, anillo de foco y el subrayado que crece bajo la navegación.
  Sobre el fondo abismo da 8,41:1.
- **Cian Instrumento** (`#83ebf5`): variante clara para títulos de sección y
  hover del botón principal. 12,88:1 sobre el fondo. Es el cian que *se lee*,
  frente al cian que *señala*.
- **Cian Hondo** (`#087ea5`): solo para texto oscuro sobre relleno cian claro.

### Neutral
- **Navy Abismo** (`#081731`): fondo de página y de campos de formulario. El
  campo es más oscuro que la tarjeta que lo contiene: hundido, no elevado.
- **Navy Superficie** (`#0b1b34`): tarjetas, tablas, barra superior, visor de log.
- **Navy Elevado** (`#0f2544`): cabeceras de tabla, fila en hover, botón fantasma
  en hover.
- **Navy Tinta** (`#03132b`): texto sobre relleno cian. Nunca como fondo de zona.
- **Blanco** (`#ffffff`) y sus velos al 72% / 62% / 50%: jerarquía de texto
  completa. El 50% es el suelo absoluto — por debajo se cae de 4,5:1.
- **Línea** (`rgba(255,255,255,0.08)`) y **Línea Fuerte** (`rgba(255,255,255,0.14)`):
  toda la separación del sistema.

### Semantic
- **Verde Enlace** (`#5bf1a8`): sesión conectada, certificado válido, acción con éxito.
- **Ámbar Alerta** (`#fbbf24`): rol admin, aviso de log, advertencia.
- **Rojo Corte** (`#f87171`): revocado, error, acción destructiva.
- **Azul Dato** (`#60a5fa`): informativo neutro.

Los cuatro están calibrados para el fondo navy, no tomados de una escala genérica:
dan 12,39 / 10,68 / 6,45 / 7,01 sobre `#081731`.

### Named Rules

**La Regla de la Luz Escasa.** El cian marca ocupa menos del 10% de cualquier
pantalla. Si aparece en dos sitios que compiten, uno de los dos está mal: en cada
vista hay **una** acción principal y **un** elemento de navegación activo.

**La Regla del Fondo Mudo.** Ningún gradiente, glow ni `backdrop-filter` en zonas
de lectura o trabajo. El sitio de marketing los usa para persuadir; el panel no
tiene a quién persuadir.

**La Regla del Color que No Habla Solo.** Ningún estado se comunica únicamente
por color. El color acompaña siempre a una palabra o a un glifo — incluidos los
niveles del visor de log.

## Typography

**Display / Body / Label:** Poppins (autoalojada en `/static/fuentes/`, pesos 400, 600 y 800)
**Mono:** `ui-monospace, 'Cascadia Code', Consolas, monospace`

**Character:** Poppins geométrica y de peso alto es la firma de Electrobridges.
En el panel esa voz se usa con disciplina: 800 con tracking `-0.03em` reservado a
cifras y títulos, donde la compacidad se lee como precisión; 400 para todo el
cuerpo. La mono aparece únicamente donde hay dato literal —rutas, salida de log,
IPs—, jamás como disfraz de "técnico".

### Hierarchy
- **Display** (800, 1.6rem, 1.1, `-0.03em`): título de página, uno por vista.
- **Headline** (600, 1.05rem, `-0.01em`): títulos de sección, en cian instrumento.
- **Cifra** (800, 1.75rem, `-0.03em`, `tabular-nums`): el valor de una tarjeta de estado.
- **Body** (400, 0.9375rem, 1.55): todo el texto corrido y las celdas.
- **Label** (600, 0.72rem, `0.12em`, mayúsculas): etiquetas de tarjeta y cabeceras
  de tabla. El tracking ancho viene de los `eyebrow` del sitio de marca.
- **Mono** (0.82rem, 1.45): visor de log, rutas de archivo.

### Named Rules

**La Regla de las Cifras Fijas.** Todo número que se refresque solo lleva
`font-variant-numeric: tabular-nums`. Las tablas de tráfico se actualizan cada 10
segundos y las cifras no pueden bailar.

**La Regla del Eyebrow Contenido.** El label en mayúsculas con tracking ancho es
etiqueta de dato —tarjeta y cabecera de tabla—, nunca decoración sobre una
sección. Un eyebrow encima de cada bloque es gramática que nadie eligió.

## Layout

Contenedor centrado de 1200px máximo con 24px de aire lateral (16px por debajo de
700px). Ritmo de espaciado en base 8. Las tarjetas de estado usan
`repeat(auto-fit, minmax(190px, 1fr))`, así que se reorganizan sin consultar
breakpoints. Más espacio encima de un título que debajo: 32px arriba, 12px abajo.

Un único breakpoint en 700px, coherente con `PRODUCT.md`: el escenario confirmado
es escritorio en LAN, así que el responsive protege de una ventana estrecha, no
de un teléfono. Las tablas anchas scrollean **dentro de su contenedor**; la
página nunca scrollea en horizontal.

## Elevation & Depth

Este sistema es **plano por definición**. La profundidad la construyen tres capas
tonales de navy —abismo, superficie, elevado— separadas por líneas de 1px. No hay
sombras en reposo en ninguna superficie.

La única sombra del sistema es el anillo de foco, y no es decorativa: es la señal
de dónde está el teclado.

### Shadow Vocabulary
- **Anillo de foco** (`box-shadow: 0 0 0 3px rgba(16,196,216,0.35)`): exclusivo de
  `:focus-visible`, sobre cualquier control.

### Named Rules

**La Regla de la Línea, no la Sombra.** Tarjetas, tablas, campos y avisos se
separan con `1px solid` de los tokens de línea. Si algo necesita destacar más, se
sube un escalón tonal de navy — no se le pone sombra.

**La Regla del Campo Hundido.** Los campos de formulario van más oscuros que la
superficie que los contiene (`navy-abismo` dentro de `navy-superficie`). Se
hunden; no flotan.

## Shapes

Radios heredados del sitio de marca, donde los botones son de 14px: `8px` en
campos y controles pequeños, `12px` en tarjetas y tablas, `14px` en botones, y
`999px` en insignias de estado y rol.

Ninguna tarjeta lleva borde de color grueso en un lado. La separación es un borde
completo de 1px; el color de estado vive en la insignia y en el texto, que es
donde se lee.

## Iconography

Material Design Icons, variantes `Outline` —la geometría se copia de
[react-icons](https://react-icons.github.io/react-icons/) (`react-icons/md`),
que las publica como `path`—. El `path` se pega en línea en la plantilla: aquí
no hay React ni empaquetador, y la CSP `'self'` descarta tipografías de iconos y
sprites remotos. Un icono nuevo se saca de ahí, no se dibuja a mano, para que el
conjunto mantenga una sola métrica.

Se usan como fondo, nunca como control: cian al 3,5% en las esquinas de login y
verificación, con `aria-hidden` y `pointer-events: none`. Son formas rellenas de
trazo ~2 sobre el `viewBox` de 24, más pesadas que un trazo dibujado a mano a
igual opacidad — de ahí el 3,5%.

Licencia Apache-2.0, la misma del proyecto; queda anotada en NOTICE.

## Components

### Buttons
- **Shape:** esquinas de 14px (`{rounded.lg}`), 10px 18px de relleno, peso 600.
- **Primary:** relleno cian marca con texto navy tinta — **8,76:1**. Hover pasa a
  cian instrumento; se aclara, no se difumina.
- **Ghost:** transparente con borde de línea fuerte y texto al 72%. Hover lleva el
  fondo a navy elevado y el texto a blanco.
- **Danger:** ghost cuyo borde y texto pasan a rojo corte en hover. Lo destructivo
  no se anuncia en reposo, se confirma al acercarse.
- **Focus:** todos comparten el anillo de foco cian en `:focus-visible`.

### Cards / Containers
- **Corner:** 12px. **Background:** navy superficie. **Border:** 1px línea.
- **Padding:** 18px. **Shadow:** ninguna, en ningún estado.
- La etiqueta va arriba en label de 0.72rem con tracking ancho; la cifra debajo en
  800 con `tabular-nums`.

### Inputs / Fields
- Fondo navy abismo, borde 1px línea fuerte, esquinas de 8px.
- **Focus:** borde a cian marca más el anillo de 3px. El `outline` nativo se
  sustituye, nunca se elimina sin reemplazo.
- Placeholder al 50% de blanco: el suelo de 4,5:1, no por debajo.

### Navigation
- Enlaces en 0.9rem peso 600, texto al 72%.
- **Activo y hover:** barra de 2px en cian marca que crece bajo el enlace, tomada
  literalmente del `.main-nav a::after` del sitio de marca. Es el gesto que más
  reconocible hace al panel como Electrobridges.
- El activo además sube el texto a blanco.

### Badges
- Píldora de 999px, label de 0.72rem con tracking `0.12em`, borde 1px del color
  semántico y fondo del mismo color al 12%.
- **Siempre con palabra dentro** (`válido`, `revocado`, `conectado`): la píldora
  no comunica por color.

### Alerts
- Borde completo de 1px del color semántico, fondo del mismo al 10%, esquinas de
  8px, y un glifo antepuesto (`✓ ✕ ⚠ ℹ`) para que el estado sobreviva al daltonismo.
- Contenedor con `aria-live`: toda acción HTMX aterriza ahí y debe anunciarse.

### Log Viewer (signature)
Bloque mono sobre navy superficie con 65vh de alto máximo, borde de línea fuerte
y una separación de 1,1rem con su barra de filtros. Cada línea lleva su nivel en
color **y** un prefijo de un carácter en un `::before` de ancho fijo, de modo que
error, aviso, conexión e info se distinguen sin ver el tono.

Es el único sitio del panel donde el texto va en **blanco pleno** (17,2:1) en vez
del 72% del cuerpo, y `info` sube al 72% en vez del 50% del resto de lo tenue
(9,3:1). No es un capricho de contraste: un log no se ojea, se lee buscando una
línea concreta y a menudo con el servidor caído. `info` además es el grueso de lo
que se lee, así que en el mínimo del sistema dejaba la pantalla apagada.

El borde va en línea fuerte porque el visor se apoya en el mismo navy que las
tarjetas: es lo único que dice dónde empieza. Bajarlo a navy tinta daría más
separación y **no se hace** — tinta es color de texto sobre relleno cian, nunca
fondo de zona.

## Do's and Don'ts

### Do:
- **Do** construir toda separación con `1px solid var(--linea)` y los tres
  escalones de navy.
- **Do** usar `tabular-nums` en cualquier cifra que se refresque sola.
- **Do** acompañar todo color de estado con una palabra o un glifo.
- **Do** poner `:focus-visible` con el anillo cian en cada control interactivo,
  botones y enlaces de navegación incluidos.
- **Do** reservar Poppins 800 para cifras y títulos; el cuerpo va en 400.

### Don't:
- **Don't** usar gradientes, glows radiales ni `backdrop-filter` en el panel. Son
  del sitio de marketing y aquí estorban a la lectura.
- **Don't** poner `border-left` de color por encima de 1px en tarjetas o avisos.
- **Don't** bajar ningún texto por debajo de `rgba(255,255,255,0.5)` sobre navy.
- **Don't** añadir sombras en reposo: el anillo de foco es la única del sistema.
- **Don't** usar mono fuera de log, rutas e IPs.
- **Don't** cargar nada remoto —fuente, icono, script—: la CSP es `'self'` y
  Poppins va autoalojada en `/static/fuentes/`.
