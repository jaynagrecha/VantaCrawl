/* Same-origin DOM-clobber execution proof for /xss/dom-clobber. */
document.body.dataset.domClobberExecuted = "true";
var statusEl = document.getElementById("status");
if (statusEl) {
  statusEl.textContent = "DOM clobber execution confirmed";
}
