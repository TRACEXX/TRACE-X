/* Relationship graph drawing.
   The BROWSER only draws. BFS/DFS run in Python (POST /cases/<id>/graph/traverse)
   and this file animates the visit order that Python returns. */

(function () {
  "use strict";

  var data = JSON.parse(document.getElementById("graph-data").textContent);
  var initialStart = JSON.parse(document.getElementById("graph-start").textContent);
  var svg = document.getElementById("graph-svg");
  var NS = "http://www.w3.org/2000/svg";
  var COLORS = { suspect: "#ec6553", evidence: "#f2b33d", witness: "#62b6dc",
                 location: "#3fbf8f", device: "#a48bea", event: "#8d9aa8" };

  var width = svg.clientWidth || 800;
  var height = svg.clientHeight || 560;
  svg.setAttribute("viewBox", "0 0 " + width + " " + height);

  // ---------------------------------------------------------- layout
  // Simple force-directed layout: nodes repel, edges pull. Deterministic start
  // positions (a circle) so the drawing is the same every time.
  var nodes = data.nodes.map(function (n, i) {
    var angle = 2 * Math.PI * i / Math.max(data.nodes.length, 1);
    return { id: n.id, label: n.label, type: n.type,
             x: width / 2 + Math.cos(angle) * width * 0.32, y: height / 2 + Math.sin(angle) * height * 0.36,
             vx: 0, vy: 0 };
  });
  var byId = {};
  nodes.forEach(function (n) { byId[n.id] = n; });
  var edges = data.edges.filter(function (e) { return byId[e.source] && byId[e.target]; });

  for (var iteration = 0; iteration < 320; iteration++) {
    var cooling = 1 - iteration / 320;
    for (var i = 0; i < nodes.length; i++) {
      for (var j = i + 1; j < nodes.length; j++) {
        var a = nodes[i], b = nodes[j];
        var dx = a.x - b.x, dy = a.y - b.y;
        // Horizontal distance counts for less, because labels are wide: nodes spread sideways more.
        var dist2 = Math.max(dx * dx * 0.35 + dy * dy, 400);
        var force = 9000 / dist2;
        var d = Math.sqrt(dist2);
        a.vx += dx / d * force; a.vy += dy / d * force;
        b.vx -= dx / d * force; b.vy -= dy / d * force;
      }
    }
    edges.forEach(function (e) {
      var s = byId[e.source], t = byId[e.target];
      var dx = t.x - s.x, dy = t.y - s.y, d = Math.sqrt(dx * dx + dy * dy) || 1;
      var pull = (d - 140) * 0.02;
      s.vx += dx / d * pull; s.vy += dy / d * pull;
      t.vx -= dx / d * pull; t.vy -= dy / d * pull;
    });
    nodes.forEach(function (n) {
      n.vx += (width / 2 - n.x) * 0.002; n.vy += (height / 2 - n.y) * 0.002;   // gentle centring
      n.x += Math.max(-12, Math.min(12, n.vx)) * cooling;
      n.y += Math.max(-12, Math.min(12, n.vy)) * cooling;
      n.vx *= 0.55; n.vy *= 0.55;
      n.x = Math.max(95, Math.min(width - 95, n.x));
      n.y = Math.max(25, Math.min(height - 40, n.y));
    });
  }

  // ---------------------------------------------------------- drawing
  function make(tag, attrs, parent) {
    var node = document.createElementNS(NS, tag);
    Object.keys(attrs).forEach(function (k) { node.setAttribute(k, attrs[k]); });
    if (parent) { parent.appendChild(node); }
    return node;
  }
  var edgeLayer = make("g", {}, svg);
  var nodeLayer = make("g", {}, svg);

  edges.forEach(function (e) {
    e.line = make("line", { "class": "edge" }, edgeLayer);
    var title = make("title", {}, e.line);
    title.textContent = e.type + ": " + e.description;
  });
  nodes.forEach(function (n) {
    n.group = make("g", { "class": "node" }, nodeLayer);
    n.circle = make("circle", { r: 11, fill: COLORS[n.type] || "#8d9aa8" }, n.group);
    n.orderText = make("text", { "class": "order", "text-anchor": "middle", dy: "3.5" }, n.group);
    // Label centred under the dot keeps neighbouring labels from running into each other.
    n.text = make("text", { y: 25, "text-anchor": "middle" }, n.group);
    n.text.textContent = n.label.length > 24 ? n.label.slice(0, 23) + "…" : n.label;
    var title = make("title", {}, n.group);
    title.textContent = "[" + n.type + "] " + n.label;
  });

  function render() {
    edges.forEach(function (e) {
      var s = byId[e.source], t = byId[e.target];
      e.line.setAttribute("x1", s.x); e.line.setAttribute("y1", s.y);
      e.line.setAttribute("x2", t.x); e.line.setAttribute("y2", t.y);
    });
    nodes.forEach(function (n) { n.group.setAttribute("transform", "translate(" + n.x + "," + n.y + ")"); });
  }
  render();

  // Dragging nodes.
  var dragging = null;
  function svgPoint(event) {
    var rect = svg.getBoundingClientRect();
    return { x: (event.clientX - rect.left) * width / rect.width, y: (event.clientY - rect.top) * height / rect.height };
  }
  nodes.forEach(function (n) {
    n.group.addEventListener("pointerdown", function (event) {
      dragging = { node: n, moved: false };
      n.group.setPointerCapture(event.pointerId);
    });
    n.group.addEventListener("pointermove", function (event) {
      if (!dragging || dragging.node !== n) { return; }
      var p = svgPoint(event);
      n.x = p.x; n.y = p.y; dragging.moved = true;
      render();
    });
    n.group.addEventListener("pointerup", function () {
      if (dragging && !dragging.moved) { startSelect.value = n.id; runTraversal(); }
      dragging = null;
    });
  });

  // ---------------------------------------------------------- controls
  var form = document.getElementById("traverse-form");
  var startSelect = document.getElementById("start");
  var targetSelect = document.getElementById("target");
  var sorted = nodes.slice().sort(function (a, b) {
    return (a.type + a.label).localeCompare(b.type + b.label);
  });
  sorted.forEach(function (n) {
    [startSelect, targetSelect].forEach(function (select) {
      var option = document.createElement("option");
      option.value = n.id;
      option.textContent = "[" + n.type + "] " + n.label;
      select.appendChild(option);
    });
  });
  if (initialStart && byId[initialStart]) { startSelect.value = initialStart; }

  var timers = [];
  function clearHighlights() {
    timers.forEach(clearTimeout); timers = [];
    nodes.forEach(function (n) { n.group.classList.remove("visited", "start"); n.orderText.textContent = ""; });
    edges.forEach(function (e) { e.line.classList.remove("hot"); });
  }

  function li(text, className) {
    var item = document.createElement("li");
    item.textContent = text;
    if (className) { item.className = className; }
    return item;
  }

  function showResult(result) {
    clearHighlights();
    document.getElementById("traverse-result").hidden = false;
    document.getElementById("result-title").textContent =
      result.algorithm.toUpperCase() + " from " + byId[result.start].label;

    var direct = document.getElementById("direct-list");
    direct.innerHTML = "";
    result.direct.forEach(function (d) { direct.appendChild(li(d.label + " - " + d.type + ": " + d.description)); });
    if (!result.direct.length) { direct.appendChild(li("No recorded links.", "muted")); }

    var orderList = document.getElementById("order-list");
    orderList.innerHTML = "";
    result.order.forEach(function (o) {
      orderList.appendChild(li(o.label + (o.level !== null && o.level !== undefined ? "  (level " + o.level + ")" : "")));
    });
    if (result.unreached.length) {
      orderList.appendChild(li("Not reachable: " + result.unreached.length + " node(s)", "muted"));
    }
    document.getElementById("steps").textContent = result.steps.join("\n");

    var pathBox = document.getElementById("path-box");
    pathBox.innerHTML = "";
    if (result.target) {
      var note = document.createElement("div");
      note.className = "notice";
      if (!result.path) {
        note.textContent = "No chain of recorded relationships connects these two nodes.";
      } else {
        note.appendChild(document.createTextNode("Why they are connected (shortest chain, found with BFS):"));
        var list = document.createElement("ol");
        list.className = "order-list";
        result.path.forEach(function (hop) {
          list.appendChild(li(hop.from + " -> " + hop.to + "  [" + hop.type + "]  " + hop.description));
        });
        note.appendChild(list);
      }
      pathBox.appendChild(note);
    }

    // Animate the visit order returned by Python.
    byId[result.start].group.classList.add("start");
    result.order.forEach(function (o, index) {
      timers.push(setTimeout(function () {
        var n = byId[o.id];
        n.group.classList.add("visited");
        n.orderText.textContent = index + 1;
        edges.forEach(function (e) {
          var other = e.source === o.id ? e.target : (e.target === o.id ? e.source : null);
          if (other && byId[other].group.classList.contains("visited")) { e.line.classList.add("hot"); }
        });
      }, index * 260));
    });
  }

  function runTraversal() {
    var algorithm = form.querySelector('input[name="algorithm"]:checked').value;
    window.TRACEX.postJSON(form.dataset.url, {
      start: startSelect.value, algorithm: algorithm, target: targetSelect.value || null
    }).then(showResult).catch(function (error) {
      document.getElementById("traverse-result").hidden = false;
      document.getElementById("result-title").textContent = "Traversal failed: " + error.message;
    });
  }

  form.addEventListener("submit", function (event) { event.preventDefault(); runTraversal(); });
  if (initialStart && byId[initialStart]) { runTraversal(); }
})();
