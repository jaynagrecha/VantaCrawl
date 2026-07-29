/* Minimal ng-app stand-in for /xss/angular — evaluates {{expr}} in-page. */
(function () {
  function evalExpr(expr) {
    try {
      if (!/^[\d\s+\-*/().]+$/.test(expr)) return '{{' + expr + '}}';
      // eslint-disable-next-line no-new-func
      return Function('"use strict"; return (' + expr + ');')();
    } catch (e) {
      return '{{' + expr + '}}';
    }
  }
  function boot() {
    var roots = document.querySelectorAll('[ng-app]');
    roots.forEach(function (root) {
      root.innerHTML = root.innerHTML.replace(/\{\{([^}]+)\}\}/g, function (_, expr) {
        return String(evalExpr(String(expr).trim()));
      });
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
