/* Applies the stored theme before first paint, so a saved light theme never
 * flashes dark. Loaded synchronously in <head> — deliberately not deferred,
 * because a deferred script runs after the document has already painted.
 *
 * This lives in its own file rather than inline so the Content-Security-Policy
 * can be a plain `script-src 'self'`. An inline script would need a sha256
 * hash, and that hash breaks the moment a line ending changes between the
 * Windows working copy (CRLF) and the Linux checkout Vercel deploys (LF).
 */
(function () {
  try {
    var stored = localStorage.getItem('winregistry-theme');
    if (stored) {
      document.documentElement.dataset.theme = stored;
    } else if (window.matchMedia('(prefers-color-scheme: light)').matches) {
      document.documentElement.dataset.theme = 'light';
    }
  } catch (e) {
    /* localStorage blocked (private mode / third-party context).
       Fall through to the CSS prefers-color-scheme default. */
  }
})();
