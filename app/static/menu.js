/* Pliega la barra de navegación tras un botón cuando no cabe en una fila.
 *
 * Archivo aparte servido desde /static, nunca en línea: la CSP es
 * script-src 'self'. Por eso tampoco vale un hx-on en la plantilla.
 *
 * Mejora progresiva: el botón nace oculto y el menú desplegado. Solo cuando
 * este archivo carga se marca la barra como .plegable, y es esa clase la que
 * activa el menú desplegable en estrecho. Si no cargara, la barra se ve como
 * antes —apilada, pero entera— en vez de esconder la navegación tras un botón
 * muerto.
 *
 * El ancho de corte vive solo en estilo.css. Aquí no hace falta: en ancho el
 * CSS ignora .abierto, así que un menú que quedó abierto al ensanchar la
 * ventana no se ve ni estorba.
 */
(function () {
  "use strict";

  var barra = document.querySelector(".barra");
  var boton = barra && barra.querySelector(".menu-boton");
  var menu = barra && document.getElementById("menu-principal");

  // La página de entrada no tiene barra: no hay nada que plegar.
  if (!boton || !menu) {
    return;
  }

  barra.classList.add("plegable");

  function poner(abierto) {
    barra.classList.toggle("abierto", abierto);
    boton.setAttribute("aria-expanded", abierto ? "true" : "false");
    boton.setAttribute("aria-label", abierto ? "Cerrar menú" : "Abrir menú");
  }

  function abierto() {
    return barra.classList.contains("abierto");
  }

  boton.addEventListener("click", function () {
    poner(!abierto());
  });

  // Escape devuelve el foco al botón: si se quedara en un enlace que acaba de
  // ocultarse, el teclado se perdería en algo invisible.
  document.addEventListener("keydown", function (evt) {
    if (evt.key === "Escape" && abierto()) {
      poner(false);
      boton.focus();
    }
  });

  // Tocar fuera cierra, como en cualquier desplegable. Sin esto, en un
  // teléfono el panel tapa la página hasta volver a dar al botón.
  document.addEventListener("click", function (evt) {
    if (abierto() && !menu.contains(evt.target) && !boton.contains(evt.target)) {
      poner(false);
    }
  });

  // Al volver con el botón de atrás el navegador puede restaurar la página
  // tal cual la dejó: con el menú abierto encima del contenido.
  window.addEventListener("pageshow", function (evt) {
    if (evt.persisted) {
      poner(false);
    }
  });
})();
