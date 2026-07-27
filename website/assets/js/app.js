/* winregistry.org — progressive enhancement only.
 *
 * The page is fully readable and navigable with JavaScript disabled; everything
 * here adds convenience on top. No external dependencies: the design system
 * recommended GSAP ScrollTrigger for the reveal, but a 70 KB CDN payload on the
 * marketing site for a tool whose pitch is "one file, no dependencies" is the
 * wrong trade. IntersectionObserver reproduces the same spec — 350ms, 12px
 * offset, ease-out, play once.
 */
(function () {
  'use strict';

  var root = document.documentElement;
  root.classList.add('js');

  /* ---- Theme -------------------------------------------------------------
   * The inline script in <head> has already applied the stored theme to avoid
   * a flash; this only wires up the toggle.
   */
  var STORAGE_KEY = 'winregistry-theme';
  var toggle = document.querySelector('.theme-toggle');

  function currentTheme() {
    if (root.dataset.theme) return root.dataset.theme;
    return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }

  if (toggle) {
    var syncLabel = function () {
      var next = currentTheme() === 'light' ? 'dark' : 'light';
      toggle.setAttribute('aria-label', 'Switch to ' + next + ' theme');
    };
    syncLabel();

    toggle.addEventListener('click', function () {
      var next = currentTheme() === 'light' ? 'dark' : 'light';
      root.dataset.theme = next;
      try { localStorage.setItem(STORAGE_KEY, next); } catch (e) { /* private mode */ }
      syncLabel();
    });
  }

  /* ---- Mobile navigation ------------------------------------------------ */
  var navToggle = document.querySelector('.nav-toggle');
  var nav = document.querySelector('.nav');

  if (navToggle && nav) {
    navToggle.addEventListener('click', function () {
      var open = nav.classList.toggle('is-open');
      navToggle.setAttribute('aria-expanded', String(open));
    });
    nav.addEventListener('click', function (e) {
      if (e.target.tagName === 'A') {
        nav.classList.remove('is-open');
        navToggle.setAttribute('aria-expanded', 'false');
      }
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && nav.classList.contains('is-open')) {
        nav.classList.remove('is-open');
        navToggle.setAttribute('aria-expanded', 'false');
        navToggle.focus();
      }
    });
  }

  /* ---- Copy to clipboard -------------------------------------------------
   * Feature-detected: without the async clipboard API the button is removed
   * rather than left as a control that silently does nothing.
   */
  var canCopy = !!(navigator.clipboard && navigator.clipboard.writeText);

  Array.prototype.forEach.call(document.querySelectorAll('.copy-btn'), function (btn) {
    var target = document.getElementById(btn.getAttribute('data-copy-target'));
    if (!canCopy || !target) {
      btn.remove();
      return;
    }
    var label = btn.querySelector('.copy-label');
    btn.addEventListener('click', function () {
      navigator.clipboard.writeText(target.innerText.trim()).then(function () {
        btn.dataset.state = 'done';
        if (label) label.textContent = 'Copied';
        // aria-live on the label announces the change to screen readers.
        setTimeout(function () {
          delete btn.dataset.state;
          if (label) label.textContent = 'Copy';
        }, 2000);
      }).catch(function () {
        if (label) label.textContent = 'Press Ctrl+C';
      });
    });
  });

  /* ---- Scroll reveal ---------------------------------------------------- */
  var reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  var revealables = document.querySelectorAll('.reveal');

  if (!('IntersectionObserver' in window) || reduced.matches) {
    Array.prototype.forEach.call(revealables, function (el) { el.classList.add('is-visible'); });
  } else {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        entry.target.classList.add('is-visible');
        io.unobserve(entry.target); // play once, never re-trigger on scroll-up
      });
    }, { rootMargin: '0px 0px -10% 0px', threshold: 0.05 });

    Array.prototype.forEach.call(revealables, function (el) { io.observe(el); });
  }

  /* ---- Docs table of contents highlight ---------------------------------- */
  var tocLinks = document.querySelectorAll('.toc a[href^="#"]');
  if (tocLinks.length && 'IntersectionObserver' in window) {
    var byId = {};
    var headings = [];

    Array.prototype.forEach.call(tocLinks, function (link) {
      var el = document.getElementById(link.getAttribute('href').slice(1));
      if (!el) return;
      byId[el.id] = link;
      headings.push(el);
    });

    var spy = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        Array.prototype.forEach.call(tocLinks, function (l) { l.classList.remove('is-active'); });
        var link = byId[entry.target.id];
        if (link) link.classList.add('is-active');
      });
    }, { rootMargin: '-88px 0px -70% 0px', threshold: 0 });

    headings.forEach(function (h) { spy.observe(h); });
  }
})();
