/* AEGIS ThreatWatch — Advisory Explorer. Reads data/advisories/days/<day>.json (by release day),
   data/advisories/updates.json (recently updated older advisories) and data/advisories/sources.json. */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var PAGE = 200, shown = PAGE, all = [], view = [], SRC = {}, dayCache = {}, idx = { days: {} };

  function el(tag, attrs, kids) {
    var n = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "text") n.textContent = attrs[k]; else if (k === "cls") n.className = attrs[k]; else n.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function (c) { if (c != null) n.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return n;
  }
  function safe(u) { return typeof u === "string" && /^https:\/\/[^\s"'<>]+$/.test(u) ? u : null; }
  function link(u, t) { var h = safe(u); return h ? el("a", { href: h, rel: "noopener noreferrer", target: "_blank", text: t }) : document.createTextNode(t); }
  function getJSON(u) { return fetch(u, { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); }); }
  function ymd(d) { return d.toISOString().slice(0, 10); }
  function fmt(iso) {
    if (!iso) return "—";
    try { return new Date(iso).toLocaleString("en-US", { timeZone: "America/New_York", dateStyle: "medium", timeStyle: "short" }) + " ET"; }
    catch (e) { return iso; }
  }
  function label(src) { return (SRC[src] && SRC[src].label) || src; }
  function group(src) { return (SRC[src] && SRC[src].group) || "Other"; }

  // ---------------------------------------------------------------- loading
  function days(n) {
    var out = [], now = new Date();
    for (var i = 0; i < n; i++) out.push(ymd(new Date(now.getTime() - i * 864e5)));
    return out.filter(function (d) { return idx.days[d]; });
  }
  function loadDay(d) {
    return dayCache[d] = dayCache[d] || getJSON("data/advisories/days/" + d + ".json").then(function (j) { return j.items || []; }).catch(function () { return []; });
  }
  function load() {
    var n = parseInt($("ax-days").value, 10) || 7, list = days(n);
    $("ax-count").textContent = "Loading " + list.length + " day" + (list.length === 1 ? "" : "s") + " of advisories…";
    var batches = [], i;
    for (i = 0; i < list.length; i += 8) batches.push(list.slice(i, i + 8));
    var acc = [];
    return batches.reduce(function (p, b) {
      return p.then(function () { return Promise.all(b.map(loadDay)).then(function (rs) { rs.forEach(function (r) { acc = acc.concat(r); }); }); });
    }, Promise.resolve()).then(function () {
      return getJSON("data/advisories/updates.json").then(function (u) { return u.items || []; }).catch(function () { return []; });
    }).then(function (upd) {
      var seen = {};
      all = [];
      acc.concat(upd).forEach(function (a) { var k = a.src + "|" + a.id; if (!seen[k]) { seen[k] = 1; all.push(a); } });
      apply();
    });
  }

  // ---------------------------------------------------------------- filtering
  function apply() {
    var n = parseInt($("ax-days").value, 10) || 7, since = ymd(new Date(Date.now() - (n - 1) * 864e5)),
        kind = $("ax-kind").value, grp = $("ax-group").value, sev = $("ax-sev").value, cve = $("ax-cve").value,
        expl = $("ax-expl").checked, toks = $("ax-q").value.trim().toLowerCase().split(/\s+/).filter(Boolean);
    view = all.filter(function (a) {
      var rel = (a.released || a.updated || "").slice(0, 10), upd = (a.updated || "").slice(0, 10);
      var isNew = rel >= since, isUpd = upd >= since && rel < since;
      if (kind === "new" ? !isNew : kind === "updated" ? !isUpd : !(isNew || isUpd)) return false;
      if (grp && group(a.src) !== grp) return false;
      if (sev === "NONE" ? a.sev : sev && a.sev !== sev) return false;
      if (cve === "with" && !(a.cves || []).length) return false;
      if (cve === "without" && (a.cves || []).length) return false;
      if (expl && !a.expl) return false;
      if (toks.length) {
        var hay = [a.id, a.title, a.vendor, label(a.src)].concat(a.products || [], a.cves || []).join(" ").toLowerCase();
        for (var i = 0; i < toks.length; i++) if (hay.indexOf(toks[i]) < 0) return false;
      }
      return true;
    }).sort(function (x, y) { return (y.updated || y.released || "").localeCompare(x.updated || x.released || ""); });
    shown = PAGE;
    render();
  }

  var SEVC = { CRITICAL: "crit", HIGH: "high", MEDIUM: "med", LOW: "low" };
  function render() {
    var tb = $("ax-table").querySelector("tbody"); tb.textContent = "";
    var noCve = view.filter(function (a) { return !(a.cves || []).length; }).length;
    $("ax-count").textContent = view.length.toLocaleString() + " advisor" + (view.length === 1 ? "y" : "ies") + " match · " +
      noCve.toLocaleString() + " without a CVE ID.";
    view.slice(0, shown).forEach(function (a) {
      var cves = a.cves || [], rel = (a.released || "").slice(0, 10), upd = (a.updated || "").slice(0, 10);
      var cveCell = el("td", null, cves.slice(0, 3).map(function (c, i) {
        return el("span", null, [i ? ", " : "", el("a", { href: "validate.html?cve=" + c, text: c })]);
      }).concat(cves.length > 3 ? [" +" + (cves.length - 3) + " more"] : cves.length ? [] : [el("span", { cls: "muted", text: "No CVE" })]));
      cveCell.title = cves.join(", ");
      tb.appendChild(el("tr", null, [
        el("td", null, [rel || "—", upd && upd !== rel ? el("div", { cls: "muted", text: "updated " + upd }) : null]),
        el("td", null, [label(a.src), el("div", { cls: "muted", text: group(a.src) })]),
        el("td", null, [a.url ? link(a.url, a.title || a.id) : (a.title || a.id), el("div", { cls: "muted", text: a.id + (a.lang && a.lang !== "en" ? " · " + a.lang.toUpperCase() : "") })]),
        el("td", null, [a.vendor || "—", (a.products || []).length ? el("div", { cls: "muted", text: a.products.slice(0, 2).join("; ") + (a.products.length > 2 ? "…" : "") }) : null]),
        cveCell,
        el("td", null, [a.sev ? el("span", { cls: "sev " + (SEVC[a.sev] || ""), text: a.sev.charAt(0) + a.sev.slice(1).toLowerCase() + (a.cvss != null ? " " + a.cvss : "") }) : el("span", { cls: "muted", text: "Unscored" }),
          a.expl ? el("div", { cls: "expl", text: "Exploited" }) : null]),
        el("td", null, (a.fix || []).length ? [el("span", { cls: "fixed", text: "✓ " + a.fix.length }), el("div", { cls: "muted", text: (a.fix[0].t || "").slice(0, 70) })] : [el("span", { cls: "muted", text: "See advisory" })])
      ]));
    });
    $("ax-more").hidden = view.length <= shown;
  }

  // ---------------------------------------------------------------- export
  function download(name, type, text) {
    var a = el("a", { href: URL.createObjectURL(new Blob([text], { type: type })), download: name });
    document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }
  function csvCell(v) { v = v == null ? "" : String(v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }
  $("ax-csv").addEventListener("click", function () {
    var cols = ["id", "source", "source_type", "vendor", "title", "url", "released", "updated", "first_collected", "cves", "severity", "cvss", "products", "fixes", "exploited"];
    var rows = [cols.join(",")].concat(view.map(function (a) {
      return [a.id, label(a.src), group(a.src), a.vendor, a.title, a.url, a.released, a.updated, a.seen, (a.cves || []).join("; "), a.sev, a.cvss,
        (a.products || []).join("; "), (a.fix || []).map(function (f) { return (f.t || "") + (f.u ? " " + f.u : ""); }).join("; "), a.expl ? "yes" : ""].map(csvCell).join(",");
    }));
    download("aegis-advisories-" + ymd(new Date()) + ".csv", "text/csv", rows.join("\n"));
  });
  $("ax-json").addEventListener("click", function () {
    download("aegis-advisories-" + ymd(new Date()) + ".json", "application/json",
      JSON.stringify({ exportedAt: new Date().toISOString(), count: view.length, advisories: view.map(function (a) { return Object.assign({ sourceLabel: label(a.src), sourceType: group(a.src) }, a); }) }, null, 1));
  });

  // ---------------------------------------------------------------- source status
  function renderSources(s) {
    var tb = $("ax-src").querySelector("tbody"); tb.textContent = "";
    var list = Object.keys(s.sources || {}).map(function (k) { return Object.assign({ key: k }, s.sources[k]); })
      .sort(function (a, b) { return (a.group + a.label).localeCompare(b.group + b.label); });
    list.forEach(function (x) {
      var st = x.ok === false ? ["Failing", "bad"] : x.daysSinceNewest != null && x.daysSinceNewest > 30 ? ["Quiet", "warn"] :
        !x.backfillComplete ? ["Backfilling", "warn"] : ["OK", "ok"];
      tb.appendChild(el("tr", null, [el("td", { text: x.label }), el("td", { text: x.group }),
        el("td", null, [el("span", { cls: "st " + st[1], text: st[0] }), x.error ? el("div", { cls: "muted", text: x.error }) : x.note ? el("div", { cls: "muted", text: x.note }) : null]),
        el("td", { text: x.lastSuccess ? fmt(x.lastSuccess) : "never" }), el("td", { text: (x.recordsThisRun || 0).toLocaleString() }),
        el("td", { text: (x.stored || 0).toLocaleString() }), el("td", { text: x.daysSinceNewest == null ? "—" : String(x.daysSinceNewest) })]));
    });
    var failing = list.filter(function (x) { return x.ok === false; }).length;
    $("ax-summary").textContent = (s.total || 0).toLocaleString() + " advisories stored from " + list.length + " sources · last collection " +
      fmt(s.generatedAt) + " (+" + (s.added || 0).toLocaleString() + " new, " + (s.changed || 0).toLocaleString() + " updated)" +
      (failing ? " · " + failing + " source" + (failing === 1 ? "" : "s") + " failing" : "") + ". Collected twice a day.";
    var groups = {}; list.forEach(function (x) { groups[x.group] = 1; });
    Object.keys(groups).sort().forEach(function (g) { $("ax-group").appendChild(el("option", { value: g, text: g })); });
  }

  // ---------------------------------------------------------------- boot
  ["ax-kind", "ax-group", "ax-sev", "ax-cve", "ax-expl"].forEach(function (id) { $(id).addEventListener("change", apply); });
  var qt; $("ax-q").addEventListener("input", function () { clearTimeout(qt); qt = setTimeout(apply, 200); });
  $("ax-days").addEventListener("change", load);
  $("ax-more").addEventListener("click", function () { shown += PAGE; render(); });
  $("ax-filters").addEventListener("submit", function (e) { e.preventDefault(); });
  Promise.all([getJSON("data/advisories/sources.json").catch(function () { return { sources: {} }; }),
               getJSON("data/advisories/days/index.json").catch(function () { return { days: {} }; })]).then(function (r) {
    SRC = r[0].sources || {}; idx = r[1];
    renderSources(r[0]);
    if (!Object.keys(idx.days || {}).length) { $("ax-count").textContent = "The first collection hasn’t run yet. Advisories appear after the next twice-daily run."; return; }
    load();
  });
})();
