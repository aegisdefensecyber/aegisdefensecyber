/* AEGIS ThreatWatch — Alerts & briefings. Reads data/watch/alerts.json (Layer 1 events) and
   data/briefings/index.json + data/briefings/<file>.json (Layer 2 analyst briefings). All text is
   rendered with textContent; links must be https. */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var ALL = [], WATCHES = [], RANK = { critical: 0, high: 1, medium: 2, info: 3 };
  // ---- personal watchlist (this browser only; storage may be unavailable, so every access is guarded)
  var KEY = "aegis-my-watchlist-v1", MY = { areas: [], terms: [] };
  try { var raw = JSON.parse(localStorage.getItem(KEY) || "null"); if (raw && Array.isArray(raw.areas)) MY = { areas: raw.areas.slice(0, 60), terms: (raw.terms || []).slice(0, 40) }; } catch (e) { /* private mode */ }
  function saveMy() { try { localStorage.setItem(KEY, JSON.stringify(MY)); } catch (e) { /* ignore */ } }
  function mine(e) {
    if (MY.areas.indexOf(e.watch) >= 0) return true;
    var hay = (e.title + " " + e.detail + " " + (e.cves || []).join(" ")).toLowerCase();
    return MY.terms.some(function (t) { return hay.indexOf(t.toLowerCase()) >= 0; });
  }

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
    var w = $("al-watch").value, lv = $("al-level").value, days = parseInt($("al-days").value, 10) || 7, onlyMine = $("al-mine").checked,
        since = new Date(Date.now() - days * 864e5).toISOString();
    var list = ALL.filter(function (e) {
      return e.ts >= since && (!w || e.watch === w) && (!lv || RANK[e.level] <= RANK[lv]) && (!onlyMine || mine(e));
    });
    var ol = $("al-events"); ol.textContent = "";
    $("al-count").textContent = list.length + " alert" + (list.length === 1 ? "" : "s") + " in this period.";
    list.forEach(function (e) {
      ol.appendChild(el("li", { cls: "al-ev " + e.level + (mine(e) ? " mine" : "") }, [
        el("div", { cls: "al-meta" }, [el("span", { cls: "al-lv " + e.level, text: e.level.toUpperCase() }), " " + e.watchName + " · " + fmt(e.ts)]),
        el("p", { cls: "al-title", text: e.title }),
        e.plain ? el("p", { cls: "al-plain", text: e.plain }) : null,
        el("p", { cls: "muted", text: e.detail }),
        (e.cves || []).length ? el("p", { cls: "al-cves" }, cveLinks(e.cves)) : null,
        (e.links || []).length ? el("p", { cls: "al-links" }, e.links.map(function (l, i) { return el("span", null, [i ? " · " : "", link(l.u, l.t)]); })) : null
      ]));
    });
    if (!list.length) ol.appendChild(el("li", { cls: "muted", text: "No alerts match. Quiet is good news: nothing changed for the watched items in this period." }));
  }

  // ---- overview of every technology area (data/watch/summary.json)
  var STATUS = { red: ["Act now", "critical"], amber: ["Review today", "high"], watch: ["Routine", "medium"], green: ["No significant change", "info"] };
  function renderOverview(sum) {
    var g = $("ov-grid"); g.textContent = "";
    var order = { red: 0, amber: 1, watch: 2, green: 3 };
    (sum.summary || []).slice().sort(function (a, b) { return (order[a.status] - order[b.status]) || a.name.localeCompare(b.name); }).forEach(function (x) {
      var st = STATUS[x.status] || STATUS.green, isMine = MY.areas.indexOf(x.id) >= 0;
      var card = el("div", { cls: "ov-card " + st[1] + (isMine ? " mine" : "") }, [
        el("div", { cls: "ov-top" }, [el("span", { cls: "al-lv " + st[1], text: st[0] }), isMine ? el("span", { cls: "ov-mine", text: "★ My watchlist" }) : null]),
        el("p", { cls: "ov-name", text: x.name }),
        el("p", { cls: "muted", text: x.headline || ((x.cves || 0).toLocaleString() + " known CVEs tracked; nothing significant in the last 24 hours.") }),
        el("p", { cls: "ov-links" }, [el("a", { href: "data/watch/feeds/" + x.id + ".xml", text: "RSS" }), " · ",
          (function () { var b = el("button", { type: "button", cls: "linkish", text: "Show alerts" });
            b.addEventListener("click", function () { $("al-watch").value = x.id; $("al-days").value = "7"; renderEvents(); $("ev-title").scrollIntoView({ behavior: "smooth" }); }); return b; })()])
      ]);
      g.appendChild(card);
    });
  }
  function renderMy() {
    var box = $("my-areas"); box.textContent = "";
    var bySec = {};
    WATCHES.forEach(function (w) { (bySec[w.section || "Other"] = bySec[w.section || "Other"] || []).push(w); });
    Object.keys(bySec).forEach(function (sec) {
      box.appendChild(el("fieldset", null, [el("legend", { text: sec })].concat(bySec[sec].map(function (w) {
        var cb = el("input", { type: "checkbox", value: w.id });
        cb.checked = MY.areas.indexOf(w.id) >= 0;
        cb.addEventListener("change", function () {
          MY.areas = MY.areas.filter(function (a) { return a !== w.id; });
          if (cb.checked) MY.areas.push(w.id);
          saveMy(); $("my-count").textContent = MY.areas.length; renderEvents(); if (window.__twSum) renderOverview(window.__twSum);
        });
        return el("label", null, [cb, " " + w.name + (w.tier === "daily" ? " · daily focus" : ""), " ", el("a", { href: "data/watch/feeds/" + w.id + ".xml", text: "RSS", "aria-label": "RSS feed for " + w.name })]);
      }))));
    });
    $("my-count").textContent = MY.areas.length;
    var ul = $("my-terms"); ul.textContent = "";
    MY.terms.forEach(function (t) {
      var x = el("button", { type: "button", cls: "linkish", text: "remove", "aria-label": "Remove " + t });
      x.addEventListener("click", function () { MY.terms = MY.terms.filter(function (y) { return y !== t; }); saveMy(); renderMy(); renderEvents(); });
      ul.appendChild(el("li", null, [el("b", { text: t }), " ", x]));
    });
  }
  $("my-add").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var t = $("my-term").value.trim().replace(/\s+/g, " ").slice(0, 60);
    if (t.length < 2 || MY.terms.indexOf(t) >= 0 || MY.terms.length >= 40) return;
    MY.terms.push(t); saveMy(); $("my-term").value = ""; renderMy(); renderEvents();
  });

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
        el("h3", { text: b.title }), el("p", { cls: "muted", text: (b.date || "") + " · " + (b.watchName || b.watch || "") +
          (b.updatedAt ? " · updated " + b.updatedAt.slice(0, 10) : "") }),
        el("p", { cls: "br-review", text: reviewLine(b) })]));
      (b.corrections || []).forEach(function (c) {
        if (c && typeof c.text === "string") v.appendChild(el("p", { cls: "notice correction" }, [
          el("strong", { text: "Correction" + (c.date ? " (" + c.date + ")" : "") + ": " }), c.text]));
      });
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
  // Who drafted the briefing and whether a person reviewed it, always shown (AI drafting is disclosed).
  function reviewLine(b) {
    var who = b.draftedBy || "Drafted automatically";
    var r = b.review || {};
    if (r.status === "reviewed") return who + ". Reviewed by " + r.by + (r.at ? " on " + r.at.slice(0, 10) : "") + ".";
    if (r.status === "pending") return who + ". Not yet reviewed by a person.";
    return who + ". " + (r.note || "Not reviewed by a person.");
  }
  function renderBriefings(idx) {
    var box = $("br-list"); box.textContent = "";
    var list = (idx.briefings || []).slice(0, 30);
    if (!list.length) { box.appendChild(el("p", { cls: "muted", text: "No briefings yet. A briefing is written on days when a watched item has a material change (KEV, exploitation, PoC, EPSS jump, new or revised vendor advisory)." })); return; }
    box.appendChild(el("ul", { cls: "br-items" }, list.map(function (m) {
      var b = el("button", { type: "button", cls: "linkish", text: m.title });
      b.addEventListener("click", function () { showBriefing(m); history.replaceState(null, "", "#" + m.file.replace(/\.json$/, "")); });
      return el("li", null, [el("span", { cls: "al-lv " + (PRI[m.priority] || "info"), text: m.priority || "ROUTINE" }), " ", m.date + " · ", b,
        m.corrected ? el("span", { cls: "al-lv info", text: " Corrected" }) : null,
        m.review === "reviewed" ? null : el("span", { cls: "muted", text: " · AI-drafted, not human-reviewed" }),
        m.headline ? el("div", { cls: "muted", text: m.headline }) : null]);
    })));
    var want = location.hash.slice(1);
    var hit = list.filter(function (m) { return m.file.replace(/\.json$/, "") === want; })[0];
    if (hit) showBriefing(hit);
  }

  // ------------------------------------------------------------------ boot
  ["al-watch", "al-level", "al-days", "al-mine"].forEach(function (id) { $(id).addEventListener("change", renderEvents); });
  $("al-filters").addEventListener("submit", function (e) { e.preventDefault(); });
  getJSON("data/watch/alerts.json").then(function (d) {
    ALL = d.events || [];
    var tot = (d.watches || []).length;
    $("al-watches").textContent = "Watching " + tot + " technology areas from the AEGIS consolidated vendor watchlist. Checked with every update, four times a day; significant changes are alerted as they are found.";
    WATCHES = d.watches || [];
    WATCHES.forEach(function (w) { $("al-watch").appendChild(el("option", { value: w.id, text: w.name })); });
    var hw = /watch=([a-z0-9-]+)/.exec(location.hash);
    if (hw) $("al-watch").value = hw[1];
    renderMy();
    renderEvents();
  }).catch(function () { $("al-watches").textContent = "Watchlist alerts start after the next update."; });
  getJSON("data/watch/summary.json").then(function (sm) { window.__twSum = sm; renderOverview(sm); }).catch(function () { $("ov-grid").textContent = "Area status appears after the next update."; });
  getJSON("data/briefings/index.json").then(renderBriefings).catch(function () { renderBriefings({}); });
})();
