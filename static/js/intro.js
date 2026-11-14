/* TRACE X - cinematic intro (landing page only).
   Stage 1: opening screen  ->  Stage 2: MP4 with its own audio  ->  Stage 3: fade into the homepage.
   Loaded from templates/index.html. The CSP only allows scripts from /static, so this lives in its own file. */

(function () {
  "use strict";

  var KEY = "tracex_intro_seen";          // remembered per browser tab (sessionStorage)
  var FADE_MS = 670;                      // length of the final cinematic fade (keep equal to --tx-fade in style.css)
  var html = document.documentElement;

  // Show the intro once per tab session. Add ?intro=1 to the URL to replay it (handy for presentations).
  var forced = /[?&]intro=1(&|$)/.test(window.location.search);
  var seen = false;
  try { seen = window.sessionStorage.getItem(KEY) === "1"; } catch (e) { /* storage blocked: just show it */ }
  if (seen && !forced) { return; }

  // Runs while the page is still parsing, so the black overlay is there on the very first paint (no flash of the homepage).
  html.classList.add("tx-intro-active");

  function init() {
    var intro = document.getElementById("tx-intro");
    var video = document.getElementById("tx-intro-video");
    var enter = document.getElementById("tx-intro-enter");
    var skip = document.getElementById("tx-intro-skip");
    if (!intro || !video || !enter || !skip) { html.classList.remove("tx-intro-active"); return; }

    var started = false, leaving = false, finished = false;

    // Keep the homepage out of reach (tab key / screen readers) until the intro is over.
    var blocked = [];
    Array.prototype.forEach.call(document.body.children, function (el) {
      if (el !== intro && el.tagName !== "SCRIPT" && !el.inert) { el.inert = true; blocked.push(el); }
    });

    // Stop the page behind the overlay from scrolling.
    function stop(e) { e.preventDefault(); }
    intro.addEventListener("wheel", stop, { passive: false });
    intro.addEventListener("touchmove", stop, { passive: false });
    function keys(e) {
      var k = e.key;
      var scrolls = k === "PageUp" || k === "PageDown" || k === "Home" || k === "End" || k === "ArrowUp" || k === "ArrowDown" || k === " ";
      if (scrolls && e.target.tagName !== "BUTTON") { e.preventDefault(); }
    }
    document.addEventListener("keydown", keys);

    // Start loading the video now so it can play the instant the visitor clicks.
    video.src = video.getAttribute("data-src");
    video.load();

    function start() {
      if (started || leaving) { return; }
      started = true;
      intro.classList.add("is-playing");
      var p;
      try { p = video.play(); } catch (e) { leave(false); return; }   // original audio stays on: never muted
      if (p && p.catch) { p.catch(function () { leave(false); }); }    // if a browser refuses, go straight to the site
      window.setTimeout(function () { try { skip.focus({ preventScroll: true }); } catch (e) {} }, 60);
    }

    function fadeAudio() {                                             // only used when SKIP INTRO is pressed
      var v0 = video.volume, t0 = Date.now();
      var timer = window.setInterval(function () {
        var k = 1 - (Date.now() - t0) / FADE_MS;
        if (k <= 0) { window.clearInterval(timer); try { video.pause(); } catch (e) {} }
        else { try { video.volume = Math.max(0, v0 * k); } catch (e) {} }
      }, 30);
    }

    function leave(fromSkip) {
      if (leaving) { return; }
      leaving = true;
      intro.classList.add("is-leaving");                               // black fade + red/silver glow (CSS)
      if (fromSkip) { fadeAudio(); }
      intro.addEventListener("animationend", function (e) {
        if (e.target === intro && e.animationName === "tx-intro-out") { cleanup(); }
      });
      window.setTimeout(cleanup, FADE_MS + 250);                       // safety net
    }

    function cleanup() {
      if (finished) { return; }
      finished = true;
      try { video.pause(); } catch (e) {}
      video.removeAttribute("src");
      blocked.forEach(function (el) { el.inert = false; });
      document.removeEventListener("keydown", keys);
      html.classList.remove("tx-intro-active");                        // overlay is display:none again; homepage was underneath all along
      intro.classList.remove("is-playing", "is-leaving");
      try { window.sessionStorage.setItem(KEY, "1"); } catch (e) {}
    }

    enter.addEventListener("click", start);
    skip.addEventListener("click", function () { leave(true); });
    video.addEventListener("ended", function () { leave(false); });
    video.addEventListener("error", function () { if (started) { leave(false); } });

    try { enter.focus({ preventScroll: true }); } catch (e) {}
  }

  if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", init); } else { init(); }
})();
