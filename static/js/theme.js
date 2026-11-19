/*
 * theme.js — SQLShield theme switcher + motion helpers
 * - persists light/dark in localStorage (falls back to OS preference)
 * - circular reveal transition via View Transitions API
 * - scroll reveal, scroll progress bar, card spotlight, subtle 3D tilt
 * - dispatches a "themechange" event so charts can re-theme
 */
(function () {
  "use strict";
  var KEY = "sqlshield-theme";
  var root = document.documentElement;

  function stored() {
    try { return localStorage.getItem(KEY); } catch (e) { return null; }
  }
  function systemTheme() {
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  function apply(theme) {
    root.setAttribute("data-theme", theme);
    var meta = document.querySelector('meta[name="theme-color"]');
    if (!meta) { meta = document.createElement("meta"); meta.name = "theme-color"; document.head.appendChild(meta); }
    meta.content = theme === "dark" ? "#060913" : "#eef2fb";
    window.dispatchEvent(new CustomEvent("themechange", { detail: { theme: theme } }));
  }
  // Already applied by the inline head snippet; make sure it exists.
  if (!root.getAttribute("data-theme")) root.setAttribute("data-theme", stored() || systemTheme());

  window.SQLShieldTheme = {
    get: function () { return root.getAttribute("data-theme"); },
    chartColors: function () {
      var cs = getComputedStyle(root);
      return {
        mode: root.getAttribute("data-theme"),
        text: cs.getPropertyValue("--chart-text").trim() || "#cbd5e1",
        grid: cs.getPropertyValue("--chart-grid").trim() || "rgba(255,255,255,.08)",
        a1: cs.getPropertyValue("--a1").trim() || "#6366f1",
        ok: cs.getPropertyValue("--ok").trim() || "#34d399"
      };
    }
  };

  function toggle(ev) {
    var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    try { localStorage.setItem(KEY, next); } catch (e) {}
    var x = ev && ev.clientX != null ? ev.clientX : window.innerWidth;
    var y = ev && ev.clientY != null ? ev.clientY : 0;
    root.style.setProperty("--tx", x + "px");
    root.style.setProperty("--ty", y + "px");
    var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (document.startViewTransition && !reduce) {
      document.startViewTransition(function () { apply(next); });
    } else {
      apply(next);
    }
  }

  var SUN = '<svg class="ico-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4.2"/><path d="M12 2v2.2M12 19.8V22M4.9 4.9l1.6 1.6M17.5 17.5l1.6 1.6M2 12h2.2M19.8 12H22M4.9 19.1l1.6-1.6M17.5 6.5l1.6-1.6"/></svg>';
  var MOON = '<svg class="ico-moon" viewBox="0 0 24 24" fill="currentColor"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';

  function mountToggle() {
    if (document.querySelector(".theme-toggle")) return;
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "theme-toggle";
    btn.setAttribute("aria-label", "Toggle light / dark theme");
    btn.title = "Toggle theme";
    btn.innerHTML = SUN + MOON;
    btn.addEventListener("click", toggle);

    var host = document.querySelector(".d-topbar-right");
    if (host) { host.insertBefore(btn, host.firstChild); return; }
    host = document.querySelector(".navbar-inner");
    if (host) {
      var launch = host.querySelector("a.btn");
      host.insertBefore(btn, launch || null);
      return;
    }
    btn.classList.add("floating");
    document.body.appendChild(btn);
  }

  function mountFx() {
    var grid = document.createElement("div");
    grid.className = "fx-grid";
    grid.setAttribute("aria-hidden", "true");
    document.body.appendChild(grid);

    var bar = document.createElement("div");
    bar.className = "scroll-progress";
    bar.setAttribute("aria-hidden", "true");
    document.body.appendChild(bar);

    var ticking = false;
    function onScroll() {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(function () {
        var scroller = document.scrollingElement || document.documentElement;
        var max = scroller.scrollHeight - scroller.clientHeight;
        bar.style.transform = "scaleX(" + (max > 0 ? scroller.scrollTop / max : 0) + ")";
        ticking = false;
      });
    }
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
  }

  function mountReveal() {
    var sel = ".d-card, .d-hero-strip, .stat-card, .attack-card, .terminal, .cta-inner, .section-header, .endpoint, .eval-image-card";
    var els = Array.prototype.slice.call(document.querySelectorAll(sel));
    if (!("IntersectionObserver" in window)) return;
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
      });
    }, { threshold: 0.08, rootMargin: "0px 0px -6% 0px" });
    els.forEach(function (el, i) {
      el.classList.add("reveal");
      el.style.transitionDelay = Math.min((i % 6) * 70, 350) + "ms";
      io.observe(el);
    });
  }

  function mountSpotlightAndTilt() {
    var fine = window.matchMedia && window.matchMedia("(pointer: fine)").matches;
    if (!fine) return;
    document.addEventListener("pointermove", function (e) {
      var card = e.target.closest && e.target.closest(".d-card, .stat-card, .attack-card");
      if (!card) return;
      var r = card.getBoundingClientRect();
      var px = e.clientX - r.left, py = e.clientY - r.top;
      card.style.setProperty("--mx", px + "px");
      card.style.setProperty("--my", py + "px");
      if (card.classList.contains("attack-card") || card.classList.contains("stat-card")) {
        var rx = ((py / r.height) - 0.5) * -6, ry = ((px / r.width) - 0.5) * 6;
        card.style.transform = "translateY(-6px) perspective(800px) rotateX(" + rx + "deg) rotateY(" + ry + "deg)";
      }
    }, { passive: true });
    document.addEventListener("pointerout", function (e) {
      var card = e.target.closest && e.target.closest(".attack-card, .stat-card");
      if (card && !card.contains(e.relatedTarget)) card.style.transform = "";
    });
  }

  // Keyboard shortcut: press "T" (outside inputs) to flip theme.
  document.addEventListener("keydown", function (e) {
    var t = e.target, tag = t && t.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || (t && t.isContentEditable)) return;
    if ((e.key === "t" || e.key === "T") && !e.metaKey && !e.ctrlKey && !e.altKey) toggle();
  });

  // Follow OS changes only if the user never chose manually.
  if (window.matchMedia) {
    var mq = window.matchMedia("(prefers-color-scheme: light)");
    var onChange = function (e) { if (!stored()) apply(e.matches ? "light" : "dark"); };
    if (mq.addEventListener) mq.addEventListener("change", onChange);
  }

  function init() { mountToggle(); mountFx(); mountReveal(); mountSpotlightAndTilt(); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
