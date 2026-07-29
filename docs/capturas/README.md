# Capturas del panel

Van aquí, y desde aquí las enlaza el [README principal](../../README.md).

## ⚠️ Antes de subir ninguna

El repositorio es **público**. Una captura de un panel de administración
enseña más de lo que parece, y una vez publicada queda en el historial de git
aunque después se borre el archivo.

Repasa cada imagen buscando:

- **IPs reales** — la de la LAN en la barra del navegador, las IP reales de los
  clientes en la tabla de conexiones, la IP pública en *Configuración*.
- **Nombres de clientes VPN** — si son nombres de personas o de equipos de un
  cliente tuyo, no van.
- **Nombres de cuentas del panel** y a qué rol pertenecen.
- **Rutas del servidor** en *Configuración* y en *Logs*, que dibujan el mapa de
  la instalación.
- **El contenido del visor de logs**, que suele traer IPs y CN a puñados.

Lo más limpio es tomarlas de una instalación de pruebas con datos inventados,
no de una real con los nombres tapados: un recuadro negro encima sigue dejando
el texto si la imagen se recorta mal, y el nombre del archivo o los metadatos
pueden delatar el resto.

## Qué hay y qué falta

| Archivo | Página | Estado |
|---|---|---|
| `clientes.png` | `/clientes` | **En el README.** Falta que se vea un revocado; los dos que hay quedan por debajo del corte |
| `login.png` | `/login` | **En el README.** Completa |
| `panel.png` | `/` | Hecha, sin usar: salió con el tráfico a cero y sin nadie conectado. Repetir con datos plausibles |
| `conexiones.png` | `/conexiones` | Hecha, sin usar: salió vacía. Repetir con dos o tres clientes conectados, con tráfico |
| `perfil.png` | `/perfil` | Hecha, sin usar. Si se repite con el 2FA a medio activar, **el QR codifica un secreto TOTP real**: reactívalo después, o tómala con una cuenta de usar y tirar |
| `logs.png` | `/logs` | Falta. El visor con los cuatro niveles de color a la vista |
| `usuarios.png` | `/admin/usuarios` | Falta. Los tres roles, con el superusuario blindado |

## Cómo tomarlas, paso a paso

Redimensionar la ventana a ojo no vale: el ancho de la ventana no es el del
área de página, porque se lleva los bordes y la barra de desplazamiento. Chrome
tiene una forma exacta.

1. Abre la página en Chrome y pulsa **Ctrl+0** — el zoom tiene que estar al
   100%, o todo saldrá a otra escala sin que se note.
2. **F12** para abrir DevTools.
3. **Ctrl+Shift+M** activa la barra de dispositivo (el icono de móvil/tableta).
4. Arriba aparece un desplegable de dispositivo: elige **Responsive** y escribe
   **1440 × 900** en las dos casillas de al lado.
5. **Ctrl+Shift+P**, escribe `screenshot` y elige:
   - **Capture screenshot** — solo lo que se ve. Es el que quieres casi siempre.
   - **Capture full size screenshot** — la página entera incluyendo el scroll.
     Útil solo para la tabla de clientes si quieres enseñarla completa; en las
     demás sale una imagen larguísima que en el README se ve diminuta.
6. Se guarda en tu carpeta de Descargas. Renómbrala según la tabla de arriba.

Sale a 1440 px exactos, **sin la barra del navegador** — así que el aviso de
«No seguro» del certificado autofirmado tampoco aparece, que es lo que quieres
para el README.

### Detalles que cambian el resultado

- **Por qué 1440.** `.contenido` tiene `max-width: 1200px` centrado, así que a
  1440 el panel se ve con sus márgenes naturales. Más ancho solo añade fondo
  vacío; por debajo de 700 px entra el responsive y ya no representa el uso real
  (el panel es para escritorio en la LAN).
- **Nitidez.** En la barra de dispositivo hay un campo de DPR. A `2` la imagen
  sale a 2880 px y el texto se ve más limpio en pantallas retina, a cambio de
  cuadruplicar el peso. Para un README, 1x va bien.
- **PNG, no JPG**: hay texto pequeño sobre navy y mucho contraste; el JPG lo
  emborrona y deja halos alrededor de las letras.
- Si alguna pasa de ~500 KB, pásala por un optimizador. El repositorio se clona
  entero en cada instalación.

## Al añadirlas

Enlázalas en el README principal, en la sección *Qué hace*. Con `alt` que
describa lo que se ve, no «captura de pantalla»: es lo que lee quien navega sin
imágenes o con lector de pantalla.
