/* "Last updated <date, time>" line at the top of a page.
   <div class="eyebrow" id="last-updated" data-src="data/status.json" data-field="lastSuccessAt">…</div>
   data-field may be a dotted path (e.g. dataset.updatedAt). Times are shown in US Eastern time. */
(function () {
  "use strict";
  var el = document.getElementById("last-updated");
  if (!el) return;
  var src = el.getAttribute("data-src") || "";
  var field = el.getAttribute("data-field") || "";
  if (!/^(\.\.\/)?[\w\-\/]+\.json$/.test(src) || !/^[\w.]+$/.test(field)) return;
  function fmt(ts) {
    var d = new Date(ts);
    if (isNaN(d)) return null;
    return d.toLocaleString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "numeric",
      minute: "2-digit", timeZone: "America/New_York", timeZoneName: "short" });
  }
  fetch(src + "?t=" + Date.now(), { cache: "no-cache" })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (d) {
      var v = d;
      field.split(".").forEach(function (k) { v = v && typeof v === "object" ? v[k] : undefined; });
      var s = typeof v === "string" ? fmt(v) : null;
      el.textContent = s ? "Last updated " + s : "Last updated: unavailable";
    })
    .catch(function () { el.textContent = "Last updated: unavailable"; });
})();
