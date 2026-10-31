/* TRACE AI chat panel.
   Sends the question to Flask (/ai/ask) and renders the structured answer.
   All text is inserted with textContent, never innerHTML, so record content
   can never run as code in the page. */

(function () {
  "use strict";

  var form = document.getElementById("chat-form");
  var input = document.getElementById("question");
  var log = document.getElementById("chat-log");
  var button = document.getElementById("ask-btn");

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined) { node.textContent = text; }
    return node;
  }

  function scrollDown() { log.scrollTop = log.scrollHeight; }

  function renderAnswer(data) {
    var box = el("div", "msg bot");
    (data.sections || []).forEach(function (section) {
      var sec = el("div", "sec " + (section.kind || ""));
      sec.appendChild(el("h4", "", section.heading));
      var list = el("ul");
      section.items.forEach(function (item) { list.appendChild(el("li", "", item)); });
      sec.appendChild(list);
      box.appendChild(sec);
    });

    if (data.ai) {
      if (data.ai.status === "ok" && data.ai.text) {
        box.appendChild(el("div", "ai-label", ""));
        box.appendChild(el("div", "ai-text", data.ai.text));
        box.appendChild(el("div", "hint", data.ai.message));
      } else if (data.ai.status === "unavailable") {
        box.appendChild(el("div", "hint", data.ai.message));
      }
    }

    if (data.references && data.references.length) {
      var refs = el("div", "refs");
      data.references.forEach(function (ref) {
        var link = el("a", "btn small", ref.label);
        link.href = ref.url;
        refs.appendChild(link);
      });
      box.appendChild(refs);
    }
    return box;
  }

  function ask(question) {
    log.appendChild(el("div", "msg user", question));
    var waiting = el("div", "msg bot muted", "Retrieving authorised records…");
    log.appendChild(waiting);
    scrollDown();
    button.disabled = true;

    window.TRACEX.postJSON(form.dataset.url, { question: question, "case": form.dataset.case || null })
      .then(function (data) { log.replaceChild(renderAnswer(data), waiting); })
      .catch(function (error) { waiting.textContent = "Error: " + error.message; })
      .then(function () { button.disabled = false; input.focus(); scrollDown(); });
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    var question = input.value.trim();
    if (!question) { return; }
    input.value = "";
    ask(question);
  });

  document.querySelectorAll("[data-example]").forEach(function (example) {
    example.addEventListener("click", function () { ask(example.dataset.example); });
  });
})();
