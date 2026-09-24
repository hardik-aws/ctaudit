(function () {
  "use strict";

  // Filter: each search box narrows the rows of the table it names.
  document.querySelectorAll("input[data-filter]").forEach(function (input) {
    var table = document.getElementById(input.dataset.filter);
    var count = document.querySelector('[data-count="' + input.dataset.filter + '"]');
    if (!table) return;
    var rows = Array.prototype.slice.call(table.tBodies[0].rows);
    var total = rows.length;
    function apply() {
      var terms = input.value.toLowerCase().split(/\s+/).filter(Boolean);
      var shown = 0;
      rows.forEach(function (row) {
        var text = row.dataset.text || (row.dataset.text = row.textContent.toLowerCase());
        var ok = terms.every(function (t) { return text.indexOf(t) !== -1; });
        row.classList.toggle("hidden", !ok);
        if (ok) shown++;
      });
      if (count) count.textContent = terms.length ? shown + " of " + total + " rows" : total + " rows";
    }
    input.addEventListener("input", apply);
    apply();
  });

  // Sort: clicking a header sorts by that column. Cells may carry a raw
  // data-sort value; otherwise their text is used. Numeric when both parse.
  document.querySelectorAll("table.data").forEach(function (table) {
    var heads = table.tHead ? table.tHead.rows[0].cells : [];
    Array.prototype.forEach.call(heads, function (th, col) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "sort";
      while (th.firstChild) btn.appendChild(th.firstChild);
      th.appendChild(btn);
      btn.addEventListener("click", function () {
        var dir = th.getAttribute("aria-sort") === "ascending" ? "descending" : "ascending";
        Array.prototype.forEach.call(heads, function (h) { h.removeAttribute("aria-sort"); });
        th.setAttribute("aria-sort", dir);
        var body = table.tBodies[0];
        var rows = Array.prototype.slice.call(body.rows);
        var key = function (row) {
          var cell = row.cells[col];
          return cell ? (cell.dataset.sort !== undefined ? cell.dataset.sort : cell.textContent.trim()) : "";
        };
        var sign = dir === "ascending" ? 1 : -1;
        rows.sort(function (a, b) {
          var x = key(a), y = key(b);
          var nx = parseFloat(x), ny = parseFloat(y);
          if (x !== "" && y !== "" && !isNaN(nx) && !isNaN(ny) && isFinite(x) && isFinite(y)) return (nx - ny) * sign;
          return x.localeCompare(y, undefined, { numeric: true }) * sign;
        });
        rows.forEach(function (r) { body.appendChild(r); });
      });
    });
  });

  // Column sets: "Key columns" hides cells marked .x.
  document.querySelectorAll(".seg[data-cols]").forEach(function (seg) {
    var wrap = document.getElementById(seg.dataset.cols);
    seg.querySelectorAll("button").forEach(function (btn) {
      btn.addEventListener("click", function () {
        seg.querySelectorAll("button").forEach(function (b) { b.setAttribute("aria-pressed", String(b === btn)); });
        if (wrap) wrap.classList.toggle("compact", btn.dataset.mode === "key");
      });
    });
  });

  // Highlight the nav link for the section in view.
  var links = document.querySelectorAll(".topbar nav a");
  if ("IntersectionObserver" in window && links.length) {
    var byId = {};
    links.forEach(function (a) { byId[a.getAttribute("href").slice(1)] = a; });
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting || !byId[e.target.id]) return;
        links.forEach(function (a) { a.classList.remove("on"); });
        byId[e.target.id].classList.add("on");
      });
    }, { rootMargin: "-30% 0px -60% 0px" });
    Object.keys(byId).forEach(function (id) {
      var el = document.getElementById(id);
      if (el) io.observe(el);
    });
  }
})();
