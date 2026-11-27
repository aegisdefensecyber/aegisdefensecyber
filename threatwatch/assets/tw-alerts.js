/* AEGIS ThreatWatch — Alerts & briefings. Reads data/watch/alerts.json (Layer 1 events) and
   data/briefings/index.json + data/briefings/<file>.json (Layer 2 analyst briefings). All text is
   rendered with textContent; links must be https. */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var ALL = [], RANK = { critical: 0, high: 1, medium: 2, info: 3 };

  function el(tag, attrs, kids) {
    var n = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "text") n.textContent = attrs[k]; else if (k === "cls") n.className = attrs[k]; else n.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function (c) { if (c != null) n.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return n;
  }
  function safe(u) { return typeof u === "string" && (/^https:\/\/[^\s"'<>]+$/.test(u) || /^[a-z]+\.html(\?[\w=.%-]*)?$/.test(u)) ? u : null; }
  function link(u, t) { var h = safe(u); return h ? el("a", { href: h, rel: "noopener noreferrer", target: /^https/.test(h) ? "_blank" : "_self", text: t }) : document.createTextNode(t); }
  function getJSON(u) { return fetch(u, { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); }); }
  function fmt(iso) {
    try { return new Date(iso).toLocaleString("en-US", { timeZone: "America/New_York", dateStyle: "medium", timeStyle: "short" }) + " ET"; }
    catch (e) { return iso || ""; }
  }
  function cveLinks(cves) {
    return (cves || []).slice(0, 8).map(function (c, i) { return el("span", null, [i ? ", " : "", el("a", { href: "validate.html?cve=" + c, text: c })]); })
      .concat((cves || []).length > 8 ? [" +" + (cves.length - 8) + " more"] : []);
  }

  // ------------------------------------------------------------------ Layer 1: events
  function renderEvents() {
    var w = $("al-watch").value, lv = $("al-level").value, days = parseInt($("al-days").value, 10) || 7,
        since = new Date(Date.now() - days * 864e5).toISOString();
    var list = ALL.filter(function (e) {
      return e.ts >= since && (!w || e.watch === w) && (!lv || RANK[e.level] <= RANK[lv]);
    });
    var ol = $("al-events"); ol.textContent = "";
    $("al-count").textContent = list.length + " alert" + (list.length === 1 ? "" : "s") + " in this period.";
    list.forEach(function (e) {
      ol.appendChild(el("li", { cls: "al-ev " + e.level }, [
        el("div", { cls: "al-meta" }, [el("span", { cls: "al-lv " + e.level, text: e.level.toUpperCase() }), " " + e.watchName + " · " + fmt(e.ts)]),
        el("p", { cls: "al-title", text: e.title }),
        el("p", { cls: "muted", text: e.detail }),
        (e.cves || []).length ? el("p", { cls: "al-cves" }, cveLinks(e.cves)) : null,
        (e.links || []).length ? el("p", { cls: "al-links" }, e.links.map(function (l, i) { return el("span", null, [i ? " · " : "", link(l.u, l.t)]); })) : null
      ]));
    });
    if (!list.length) ol.appendChild(el("li", { cls: "muted", text: "No alerts match. Quiet is good news: nothing changed for the watched items in this period." }));
  }

  // ------------------------------------------------------------------ Layer 2: briefings
  var PRI = { EMERGENCY: "critical", HIGH: "high", ELEVATED: "medium", ROUTINE: "info" };
  function table(head, rows) {
    return el("table", { cls: "ax-table br-table" }, [el("thead", null, [el("tr", null, head.map(function (h) { return el("th", { scope: "col", text: h }); }))]),
      el("tbody", null, rows.map(function (r) { return el("tr", null, r.map(function (c) { return el("td", { text: String(c == null ? "" : c) }); })); }))]);
  }
  function showBriefing(meta) {
    var v = $("br-view");
    getJSON("data/briefings/" + meta.file).then(function (b) {
      v.textContent = "";
      v.hidden = false;
      v.appendChild(el("div", { cls: "br-head" }, [
        el("span", { cls: "al-lv " + (PRI[b.priority] || "info"), text: "Priority: " + (b.priority || "ROUTINE") }),
        el("h3", { text: b.title }), el("p", { cls: "muted", text: (b.date || "") + " · " + (b.watchName || b.watch || "") + " · written by the AEGIS briefing analyst from AEGIS data and public reporting" })]));
      if (b.headline) v.appendChild(el("p", { cls: "notice br-headline", text: b.headline }));
      if (b.summary) v.appendChild(el("p", { text: b.summary }));
      var sec = function (n, t) { v.appendChild(el("h4", { text: n + ". " + t })); };
      var n = 1;
      if ((b.changes || []).length) { sec(n++, "What has changed?"); v.appendChild(el("ul", null, b.changes.map(function (c) { return el("li", { text: c }); }))); }
      if ((b.assessment || []).length) { sec(n++, "Vulnerability threat assessment"); v.appendChild(table(["Indicator", "Assessment"], b.assessment)); }
      if ((b.affected || []).length) { sec(n++, "Affected applications"); v.appendChild(table(["Application", "Primary business risk"], b.affected)); }
      if ((b.actions || []).length) { sec(n++, "Prioritized remediation actions"); v.appendChild(table(["Priority", "Action", "Target"], b.actions)); }
      if ((b.monitoring || []).length) { sec(n++, "Advisory change monitoring"); v.appendChild(table(["Monitoring category", "Status"], b.monitoring)); }
      if (b.limitations) v.appendChild(el("p", { cls: "muted", text: "Verification limitations: " + b.limitations }));
      if (b.judgment) { sec(n++, "Threat judgment"); v.appendChild(el("p", { cls: "br-judgment", text: b.judgment })); }
      if ((b.sources || []).length) {
        sec(n++, "Sources");
        v.appendChild(el("ol", null, b.sources.map(function (s) { return el("li", null, [link(s.url, s.title || s.url)]); })));
      }
      v.scrollIntoView({ behavior: "smooth", block: "start" });
    }).catch(function () { v.hidden = false; v.textContent = "This briefing could not be loaded."; });
  }
  function renderBriefings(idx) {
    var box = $("br-list"); box.textContent = "";
    var list = (idx.briefings || []).slice(0, 30);
    if (!list.length) { box.appendChild(el("p", { cls: "muted", text: "No briefings yet. A briefing is written on days when a watched item has a material change (KEV, exploitation, PoC, EPSS jump, new or revised vendor advisory)." })); return; }
    box.appendChild(el("ul", { cls: "br-items" }, list.map(function (m) {
      var b = el("button", { type: "button", cls: "linkish", text: m.title });
      b.addEventListener("click", function () { showBriefing(m); history.replaceState(null, "", "#" + m.file.replace(/\.json$/, "")); });
      return el("li", null, [el("span", { cls: "al-lv " + (PRI[m.priority] || "info"), text: m.priority || "ROUTINE" }), " ", m.date + " · ", b,
        m.headline ? el("div", { cls: "muted", text: m.headline }) : null]);
    })));
    var want = location.hash.slice(1);
    var hit = list.filter(function (m) { return m.file.replace(/\.json$/, "") === want; })[0];
    if (hit) showBriefing(hit);
  }

  // ------------------------------------------------------------------ boot
  ["al-watch", "al-level", "al-days"].forEach(function (id) { $(id).addEventListener("change", renderEvents); });
  $("al-filters").addEventListener("submit", function (e) { e.preventDefault(); });
  getJSON("data/watch/alerts.json").then(function (d) {
    ALL = d.events || [];
    $("al-watches").textContent = "Watching: " + (d.watches || []).map(function (w) {
      return w.name + " (" + (w.cves || 0).toLocaleString() + " CVEs, " + (w.advisories || 0) + " recent advisories)";
    }).join(" · ") + ". Checked with every update, four times a day.";
    (d.watches || []).forEach(function (w) { $("al-watch").appendChild(el("option", { value: w.id, text: w.name })); });
    renderEvents();
  }).catch(function () { $("al-watches").textContent = "Watchlist alerts start after the next update."; });
  getJSON("data/briefings/index.json").then(renderBriefings).catch(function () { renderBriefings({}); });
})();
