# Imágenes de marca

Isotipo de **BridgesMGR** —escudo con llave— en sus dos variantes. Se sirven
desde `/static/imagenes/`.

| Archivo | Qué es | Dónde se usa |
|---|---|---|
| `bridgesmgr-oscuro-transparente.png` | 960×960, escudo cian con llave blanca | Barra superior y login |
| `bridgesmgr-claro-transparente.png` | 960×960, escudo navy con llave cian | Fondos claros: documentación, impresión |
| `BridgesMGR Logo-selection-oscuro.png` | 192×192, con fondo navy | Sin usar |
| `BridgesMGR Logo-selection-claro.png` | 484×484, con fondo blanco | Sin usar |

## `favicon/`

Set recortado a cada tamaño, no reducido por el navegador: a 16 px, encoger el
PNG de 960 convierte la llave en una mancha.

| Archivo | Para qué |
|---|---|
| `favicon.ico` | Pestaña; lo piden los navegadores antiguos y algunos lo buscan solos |
| `favicon-32x32.png`, `favicon-16x16.png` | Pestaña en navegadores actuales |
| `apple-touch-icon.png` | 180×180, iOS al añadir a la pantalla de inicio |
| `android-chrome-192x192.png`, `-512x512.png` | Android, vía el manifest |
| `site.webmanifest` | Nombre, colores y los dos iconos de Android |

Todo se declara en el `<head>` de `base.html`, del que heredan también `login`
y `login_totp`. Un solo sitio.

Dos cosas del manifest que el generador deja mal y hay que revisar si se
regenera: las rutas salen apuntando a la raíz (`/android-chrome-192x192.png`) y
tienen que ir bajo `/static/imagenes/favicon/`, y los colores salen en blanco
cuando aquí van en Navy Abismo (`#081731`), que es el fondo real del panel.

El nombre se compone en la propia página, no va en la imagen: *Bridges* en
blanco y *MGR* en Cian Marca (`#10c4d8`), Poppins ExtraBold. Lo hace la regla
`.marca strong span` de `estilo.css`, según [DESIGN.md](../../../DESIGN.md).

## Por qué la variante oscura también vale de favicon

El escudo es cian opaco y la llave recorta en blanco **sobre** el escudo, así
que se lee igual en una pestaña clara que en una oscura. Por eso el fondo
transparente no da problemas aquí.

## Si añades o cambias archivos

- **Nada de referencias externas** dentro de un SVG (`<image>`, `xlink:href`,
  `@import`): la CSP del panel es `'self'` y las bloquea; el logo saldría roto.
- En los SVG, **convierte el texto a contornos**. Un `<text>` con
  `font-family: Poppins` se ve bien dentro de la página, pero dentro de un
  `<img>` o de un favicon la fuente no está cargada y cae a la del sistema.
- Si cambias un nombre de archivo, hay que tocar también `base.html`,
  `login.html` y `login_totp.html`.

- Si añades un tamaño nuevo al favicon, decláralo en `base.html` **y**
  añádelo a `site.webmanifest` si es para Android. Un archivo suelto que nadie
  referencia no lo usa ningún navegador.
