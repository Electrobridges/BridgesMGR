// Tooltip de las gráficas del panel.
//
// Archivo local y no en línea: la CSP es script-src 'self'. Solo enseña el
// texto que el servidor ya puso en data-tip; si no carga, queda el <title>
// nativo de cada columna y la tabla de datos debajo de cada gráfica.
(function () {
  'use strict';
  var tip = null;

  function caja() {
    if (!tip) {
      tip = document.createElement('div');
      tip.className = 'grafica-tip';
      tip.setAttribute('role', 'tooltip');
      document.body.appendChild(tip);
    }
    return tip;
  }

  function mostrar(objetivo, x, y) {
    var t = caja();
    t.textContent = objetivo.getAttribute('data-tip');
    t.classList.add('visible');
    var ancho = t.offsetWidth, alto = t.offsetHeight;
    var izq = Math.min(x + 14, window.innerWidth - ancho - 8);
    var arriba = y - alto - 12 < 0 ? y + 16 : y - alto - 12;
    t.style.left = (izq + window.scrollX) + 'px';
    t.style.top = (arriba + window.scrollY) + 'px';
  }

  function ocultar() { if (tip) tip.classList.remove('visible'); }

  document.addEventListener('mousemove', function (e) {
    var objetivo = e.target.closest ? e.target.closest('[data-tip]') : null;
    if (objetivo) mostrar(objetivo, e.clientX, e.clientY); else ocultar();
  });
  document.addEventListener('scroll', ocultar, true);
})();
