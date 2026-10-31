/* TRACE X - small page behaviours shared by every page.
   The server does all real work; this file only improves the interface. */

(function () {
  "use strict";

  var csrfMeta = document.querySelector('meta[name="csrf-token"]');

  // Shared helper for fetch() calls to Flask. Sends the CSRF token header.
  window.TRACEX = {
    postJSON: function (url, data) {
      return fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfMeta ? csrfMeta.content : ""
        },
        credentials: "same-origin",
        body: JSON.stringify(data)
      }).then(function (response) {
        return response.json().catch(function () { return {}; }).then(function (body) {
          if (!response.ok) { throw new Error(body.error || ("Request failed (" + response.status + ")")); }
          return body;
        });
      });
    }
  };

  // Ask before destructive form submissions: <form data-confirm="Are you sure?">
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.getAttribute("data-confirm"))) { event.preventDefault(); }
    });
  });

  // Click a hash to copy it.
  document.querySelectorAll("[data-copy]").forEach(function (el) {
    el.style.cursor = "copy";
    el.addEventListener("click", function () {
      if (!navigator.clipboard) { return; }
      navigator.clipboard.writeText(el.textContent.trim()).then(function () {
        var old = el.getAttribute("title");
        el.setAttribute("title", "Copied");
        setTimeout(function () { el.setAttribute("title", old || ""); }, 1200);
      });
    });
  });

  // <select data-autosubmit> submits its form when changed.
  document.querySelectorAll("select[data-autosubmit]").forEach(function (select) {
    select.addEventListener("change", function () { select.form.submit(); });
  });

  // Show CCTV fields only when a video file is chosen.
  document.querySelectorAll("input[data-video-toggle]").forEach(function (input) {
    var target = document.querySelector(input.getAttribute("data-video-toggle"));
    if (!target) { return; }
    var videoExt = /\.(mp4|webm|ogv|mov|m4v)$/i;
    function update() {
      var file = input.files && input.files[0];
      target.hidden = !(file && videoExt.test(file.name));
    }
    input.addEventListener("change", update);
    update();
  });

  // Relationship form: reveal "new location/device" fields.
  document.querySelectorAll("select[data-new-toggle]").forEach(function (select) {
    var target = document.querySelector(select.getAttribute("data-new-toggle"));
    if (!target) { return; }
    function update() { target.hidden = select.value !== "__new__"; }
    select.addEventListener("change", update);
    update();
  });

  // ---------------------------------------------------------- CCTV viewer
  var video = document.getElementById("cctv-video");
  if (video) {
    var pos = document.getElementById("cctv-pos");
    var clock = document.getElementById("cctv-clock");
    var rate = document.getElementById("cctv-rate");
    var start = clock && clock.dataset.start ? new Date(clock.dataset.start.replace(" ", "T")) : null;

    function pad(n, width) { n = String(n); while (n.length < width) { n = "0" + n; } return n; }
    function formatPosition(seconds) {
      var h = Math.floor(seconds / 3600), m = Math.floor(seconds % 3600 / 60), s = seconds % 60;
      return pad(h, 2) + ":" + pad(m, 2) + ":" + pad(s.toFixed(2), 5);
    }
    function formatClock(date) {
      return date.getFullYear() + "-" + pad(date.getMonth() + 1, 2) + "-" + pad(date.getDate(), 2) + " " +
        pad(date.getHours(), 2) + ":" + pad(date.getMinutes(), 2) + ":" + pad(date.getSeconds(), 2);
    }
    function tick() {
      pos.textContent = formatPosition(video.currentTime || 0);
      if (start && !isNaN(start)) {
        clock.textContent = formatClock(new Date(start.getTime() + video.currentTime * 1000));
      }
    }
    video.addEventListener("timeupdate", tick);
    video.addEventListener("seeked", tick);
    rate.addEventListener("change", function () { video.playbackRate = parseFloat(rate.value); });
    document.querySelectorAll("[data-cctv]").forEach(function (button) {
      button.addEventListener("click", function () {
        if (button.dataset.cctv === "frame") { video.pause(); }
        video.currentTime = Math.max(0, video.currentTime + parseFloat(button.dataset.amount));
      });
    });
  }
})();
