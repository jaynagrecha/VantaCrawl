/* Same-origin DOM-clobber execution proof (static alias). */
document.body.dataset.domClobberExecuted = "true";
var statusEl = document.getElementById("status");
if (statusEl) {
  statusEl.textContent = "DOM clobber execution confirmed";
}
