/* Sustituye el confirm() del navegador por un diálogo del propio panel.
 *
 * Archivo aparte servido desde /static, nunca en línea: la CSP es
 * script-src 'self', que admite archivos locales y prohíbe los inline y los
 * remotos. Es la misma vía por la que se sirve htmx.min.js.
 *
 * Se engancha al evento htmx:confirm, así que cubre los hx-confirm que ya hay
 * repartidos por las plantillas sin tocar ninguna: revocar, restaurar,
 * eliminar, desconectar, borrar una cuenta y demás.
 *
 * Ojo con la degradación, que aquí importa más de lo normal: si este archivo
 * no llegara a cargar, HTMX vuelve a su window.confirm nativo. La guarda de
 * las acciones destructivas NO depende de que esto funcione; solo su aspecto.
 */
(function () {
  "use strict";

  document.addEventListener("htmx:confirm", function (evt) {
    var pregunta = evt.detail.question;

    // Sin hx-confirm no hay nada que confirmar: HTMX dispara este evento en
    // toda petición, y quedárselo aquí las bloquearía todas.
    if (!pregunta) {
      return;
    }

    var dialogo = document.getElementById("dialogo-confirmar");

    // <dialog> sin showModal es un navegador que no lo soporta. Se deja pasar
    // para que actúe el confirm nativo en vez de quedarse sin confirmación.
    if (!dialogo || typeof dialogo.showModal !== "function") {
      return;
    }

    evt.preventDefault();

    dialogo.querySelector(".dialogo-texto").textContent = pregunta;

    // El botón hereda el tono del que lo disparó: lo destructivo se confirma
    // con un botón que también lo parece.
    var origen = evt.detail.elt;
    var peligro = origen && origen.classList.contains("boton-peligro");
    var aceptar = dialogo.querySelector('button[value="si"]');
    aceptar.className = "boton " + (peligro ? "boton-peligro" : "boton-principal");

    function alCerrar() {
      dialogo.removeEventListener("close", alCerrar);
      // Escape y el botón de cancelar dejan returnValue vacío o en "no".
      if (dialogo.returnValue === "si") {
        evt.detail.issueRequest(true);
      }
    }

    dialogo.addEventListener("close", alCerrar);
    dialogo.returnValue = "";
    dialogo.showModal();
  });

  /* Un solo envío por formulario plano.
   *
   * Los formularios con hx-post ya se protegen con hx-disabled-elt, pero los
   * de HTML corriente —entrar, el código de dos pasos, salir— no tenían nada, y
   * ahí el doble clic no es cosmético:
   *
   *   /login        una contraseña mal tecleada y pulsada dos veces quema dos
   *                 de los cinco intentos antes del bloqueo.
   *   /login/codigo peor: el primero consume el paso del TOTP y el segundo lo
   *                 encuentra gastado, así que cuenta un fallo y responde
   *                 "Código incorrecto" a un código que era correcto.
   *
   * Si este archivo no cargara se vuelve al comportamiento de antes: molesto,
   * nunca inseguro.
   */
  document.addEventListener("submit", function (evt) {
    var formulario = evt.target;

    // Los de HTMX van por su cuenta con hx-disabled-elt
    if (!formulario || formulario.hasAttribute("hx-post")) {
      return;
    }

    var botones = formulario.querySelectorAll(
      'button:not([type="button"]):not([disabled]), input[type="submit"]:not([disabled])'
    );

    /* En el siguiente tick y no ahora: desactivar un botón dentro del propio
     * manejador de submit puede dejar fuera su valor de los datos enviados, y
     * en algún navegador cancela el envío entero. */
    window.setTimeout(function () {
      for (var i = 0; i < botones.length; i++) {
        botones[i].disabled = true;
        botones[i].setAttribute("aria-busy", "true");
      }
    }, 0);
  });

  /* Al volver con el botón de atrás, el navegador puede restaurar la página
   * desde su caché tal como quedó: con el botón muerto. Se reactiva. */
  window.addEventListener("pageshow", function (evt) {
    if (!evt.persisted) {
      return;
    }
    var botones = document.querySelectorAll("button[aria-busy], input[aria-busy]");
    for (var i = 0; i < botones.length; i++) {
      botones[i].disabled = false;
      botones[i].removeAttribute("aria-busy");
    }
  });
})();
