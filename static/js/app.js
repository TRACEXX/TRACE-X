(function () {
  "use strict";

  var csrfMeta = document.querySelector('meta[name="csrf-token"]');

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

  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.getAttribute("data-confirm"))) { event.preventDefault(); }
    });
  });

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

  document.querySelectorAll("select[data-autosubmit]").forEach(function (select) {
    select.addEventListener("change", function () { select.form.submit(); });
  });
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

  // ---------------------------------------------------------- Floating TRACE AI Widget (CSP Compliant)
  document.addEventListener("DOMContentLoaded", function () {
    var toggleBtn = document.getElementById("ai-widget-toggle");
    var closeBtn = document.querySelector(".ai-close-btn");
    var widgetBox = document.getElementById("ai-widget-box");
    var sendBtn = document.getElementById("ai-widget-send");
    var inputField = document.getElementById("ai-widget-query");

    if (toggleBtn && widgetBox) {
      toggleBtn.addEventListener("click", function () {
        widgetBox.classList.toggle("hidden");
      });
    }

    if (closeBtn && widgetBox) {
      closeBtn.addEventListener("click", function () {
        widgetBox.classList.add("hidden");
      });
    }

    if (sendBtn) {
      sendBtn.addEventListener("click", sendWidgetQuery);
    }

    if (inputField) {
      inputField.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          sendWidgetQuery();
        }
      });
    }
  });

  function sendWidgetQuery() {
    var input = document.getElementById("ai-widget-query");
    var messages = document.getElementById("ai-widget-messages");
    if (!input || !messages) { return; }

    var question = input.value.trim();
    if (!question) { return; }

    var userDiv = document.createElement("div");
    userDiv.className = "ai-msg ai-msg-user";
    userDiv.innerHTML = "<b>You:</b> " + question;
    messages.appendChild(userDiv);

    input.value = "";
    messages.scrollTop = messages.scrollHeight;

    var loadingId = "loading-" + Date.now();
    var loadingDiv = document.createElement("div");
    loadingDiv.id = loadingId;
    loadingDiv.className = "ai-msg ai-msg-system";
    loadingDiv.textContent = "Analyzing case records...";
    messages.appendChild(loadingDiv);
    messages.scrollTop = messages.scrollHeight;

    window.TRACEX.postJSON("/ai/ask", { question: question })
      .then(function (data) {
        var loader = document.getElementById(loadingId);
        if (loader) { loader.remove(); }

        var answer = "";
        if (data.ai && data.ai.text) {
                    answer = data.ai.text
            .replace(/\*\*RECORDED FACTS:\*\*/gi, "")
            .replace(/\*\*INTERPRETATION \(AI-generated\):\*\*/gi, "")
            .replace(/\*\*MISSING INFORMATION:\*\*/gi, "")
            .replace(/Not recorded in TRACE X\./gi, "")
            .trim();
        } else if (data.sections && data.sections.length) {
          var cleanSections = data.sections.filter(function (s) {
            return s.kind !== "notice" && s.heading !== "How this was searched";
          });

          answer = cleanSections.map(function (s) {
            return "<b>" + s.heading + "</b><br>" + s.items.join("<br>");
          }).join("<br><br>");
        }

        if (!answer) {
          answer = data.error || "No information found.";
        }

        var botDiv = document.createElement("div");
        botDiv.className = "ai-msg ai-msg-bot";
        botDiv.innerHTML = "<b>TRACE AI:</b><br>" + answer.replace(/\n/g, "<br>");
        messages.appendChild(botDiv);
        messages.scrollTop = messages.scrollHeight;
      })
      .catch(function (err) {
        var loader = document.getElementById(loadingId);
        if (loader) { loader.remove(); }

        var errDiv = document.createElement("div");
        errDiv.className = "ai-msg ai-msg-error";
        errDiv.textContent = err.message || "TRACE AI is currently unavailable.";
        messages.appendChild(errDiv);
        messages.scrollTop = messages.scrollHeight;
      });
  }
})();
