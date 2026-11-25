/* Aegis ThreatWatch — relationship explorer (no dependencies, no innerHTML with data). */
(function () {
  "use strict";
  var SVGNS = "http://www.w3.org/2000/svg";
  // Six side-by-side columns, left to right, spanning the full page width.
  var ROWS = { technique: 0, actor: 1, campaign: 2, cve: 3, ioc: 4, industry: 5, geography: 5 };
  var ROW_LABEL = ["ATT&CK technique", "Threat actors", "Campaign", "CVE", "Indicator of compromise", "Industry / category"];
  var CONF = { low: 1, moderate: 2, high: 3 };
  var REL = { attributed: "conducts (attributed)", exploits: "exploits", observed_targeting: "targets",
              possible_exposure: "possible exposure", uses: "uses technique", indicator: "indicator" };
  var NH = 30, SY = 40, HEAD = 46, GAP = 10, PAD = 10;
  var COLOR = ["#9b87d9", "#d97b7b", "#d9a94e", "#5f97d9", "#4bb8a9", "#6fbf7f"];
  var EL = { nodes: {}, edges: [] }, hover = null;

  var G, byId = {}, selected = null;
  var $ = function (id) { return document.getElementById(id); };

  function el(tag, attrs, kids) {
    var n = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      if (k === "text") n.textContent = attrs[k]; else if (k === "cls") n.className = attrs[k]; else n.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function (c) { if (c != null) n.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return n;
  }
  function sv(tag, attrs) { var n = document.createElementNS(SVGNS, tag); Object.keys(attrs || {}).forEach(function (k) { n.setAttribute(k, attrs[k]); }); return n; }
  function safeHref(u) { return typeof u === "string" && /^https:\/\/[^\s"'<>]+$/.test(u) ? u : null; }
  function link(u, t) { var h = safeHref(u); return h ? el("a", { href: h, rel: "noopener noreferrer", text: t }) : document.createTextNode(t); }
  function trunc(s, n) { return s.length > n ? s.slice(0, n - 1) + "…" : s; }

  // ------------------------------------------------------------ filtering
  function filteredEdges() {
    var minC = CONF[$("f-conf").value] || 1, ev = $("f-ev").value, since = $("f-since").value,
        exp = $("f-exposure").checked;
    return G.edges.filter(function (e) {
      if ((CONF[e.confidence] || 0) < minC) return false;
      if (ev && (e.evidence || {}).type !== ev) return false;
      if (since && ((e.evidence || {}).lastObserved || "") < since) return false;
      if (!exp && e.relation === "possible_exposure") return false;
      return true;
    });
  }

  function neighbourhood(seeds, edges) {
    var adj = {};
    edges.forEach(function (e) { (adj[e.source] = adj[e.source] || []).push(e.target); (adj[e.target] = adj[e.target] || []).push(e.source); });
    var seen = {}, q = seeds.map(function (s) { return [s, true]; });
    while (q.length) {
      var cur = q.shift(), id = cur[0], isSeed = cur[1];
      if (seen[id]) continue;
      seen[id] = true;
      var t = byId[id].type;
      (adj[id] || []).forEach(function (o) {
        var ot = byId[o].type;
        if (isSeed || t === "campaign") q.push([o, false]);
        else if (t === "actor" && ot === "technique") q.push([o, false]);
        // non-seed leaves (CVE, industry, geography, technique) do not expand: avoids
        // leaking unrelated campaigns through a shared CVE or sector.
      });
    }
    return seen;
  }

  function compute() {
    var edges = filteredEdges();
    var sets = [];
    var q = $("f-q").value.trim().toLowerCase();
    if (q) {
      var seeds = G.nodes.filter(function (n) {
        return (n.label || "").toLowerCase().indexOf(q) >= 0 || (n.aliases || []).some(function (a) { return a.toLowerCase().indexOf(q) >= 0; });
      }).map(function (n) { return n.id; });
      sets.push(neighbourhood(seeds, edges));
    }
    ["f-ind", "f-geo"].forEach(function (f) { if ($(f).value) sets.push(neighbourhood([$(f).value], edges)); });
    if (sets.length) edges = edges.filter(function (e) { return sets.every(function (s) { return s[e.source] && s[e.target]; }); });
    var nodes = {};
    edges.forEach(function (e) { nodes[e.source] = nodes[e.target] = true; });
    return { edges: edges, nodes: nodes };
  }

  // ------------------------------------------------------------ rendering
  function render() {
    var view = compute(), svg = $("graph");
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    var rows = [[], [], [], [], [], []];
    G.nodes.forEach(function (n) { if (view.nodes[n.id] && ROWS[n.type] != null) rows[ROWS[n.type]].push(n); });
    // order each band to keep links short: campaigns alphabetically, then every other band by the
    // average position of the nodes it links to (barycentre), which reduces crossing lines.
    var adj = {};
    view.edges.forEach(function (e) { (adj[e.source] = adj[e.source] || []).push(e.target); (adj[e.target] = adj[e.target] || []).push(e.source); });
    var rank = {};
    function place(ri, byLabel) {
      var list = rows[ri];
      list.forEach(function (n) {
        var ks = (adj[n.id] || []).filter(function (o) { return rank[o] != null; }).map(function (o) { return rank[o]; });
        n._b = byLabel || !ks.length ? null : ks.reduce(function (a, b) { return a + b; }, 0) / ks.length;
      });
      list.sort(function (a, b) {
        if (a._b != null && b._b != null && a._b !== b._b) return a._b - b._b;
        if ((a._b == null) !== (b._b == null)) return a._b == null ? 1 : -1;
        return a.label.localeCompare(b.label);
      });
      list.forEach(function (n, i) { rank[n.id] = (i + 0.5) / list.length; });
    }
    place(2, true); place(1); place(3); place(0); place(4); place(5);
    var maxLen = Math.max.apply(null, rows.map(function (r) { return r.length; }).concat([1]));
    var wrap = svg.parentNode, W = Math.max(wrap.clientWidth - 20, 900);
    var CW = (W - GAP * (rows.length - 1)) / rows.length, NW = CW - 2 * PAD;
    var H = HEAD + maxLen * SY + 16;
    var pos = {};
    rows.forEach(function (list, ci) {
      var step = (maxLen * SY) / Math.max(list.length, 1);   // every column spans the full height
      var x = ci * (CW + GAP) + PAD;
      list.forEach(function (n, i) { pos[n.id] = { x: x, y: HEAD + (i + 0.5) * step - NH / 2 + 6 }; });
    });
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    svg.setAttribute("width", W);
    svg.setAttribute("height", H);
    ROW_LABEL.forEach(function (l, i) {
      var x = i * (CW + GAP);
      svg.appendChild(sv("rect", { x: x, y: 0, width: CW, height: H, rx: 4, "class": "col-bg" }));
      var t = sv("text", { x: x + CW / 2, y: 20, "text-anchor": "middle", "class": "col-h" });
      t.textContent = l.toUpperCase(); svg.appendChild(t);
      svg.appendChild(sv("rect", { x: x + CW / 2 - 28, y: 30, width: 56, height: 2, rx: 1, fill: COLOR[i] }));
    });
    var maxChars = Math.max(8, Math.floor((NW - 22) / 6.8));

    if (!view.edges.length) {
      var t = sv("text", { x: 8, y: HEAD + 30, fill: "#B1C3D3", "font-size": "14" });
      t.textContent = "No verified relationships match these filters.";
      svg.appendChild(t);
    }
    EL = { nodes: {}, edges: [] };
    var eg = sv("g", {});
    view.edges.forEach(function (e) {
      var a = pos[e.source], b = pos[e.target];
      if (!a || !b) return;
      var l = a.x <= b.x ? a : b, r = a.x <= b.x ? b : a;
      var x1 = l.x + NW, y1 = l.y + NH / 2, x2 = r.x, y2 = r.y + NH / 2, mx = (x1 + x2) / 2;
      var long = Math.abs(ROWS[byId[e.source].type] - ROWS[byId[e.target].type]) > 1;
      var cls = "edge" + (e.relation === "possible_exposure" ? " exposure" : "") + (long ? " long" : "");
      var p = sv("path", { d: "M" + x1 + "," + y1 + " C" + mx + "," + y1 + " " + mx + "," + y2 + " " + x2 + "," + y2,
                           "class": cls, "stroke-width": e.confidence === "high" ? 2 : 1 });
      var tt = sv("title", {}); tt.textContent = byId[e.source].label + " — " + REL[e.relation] + " — " + byId[e.target].label + " (" + e.confidence + " confidence)";
      p.appendChild(tt);
      EL.edges.push({ e: e, el: p });
      eg.appendChild(p);
    });
    svg.appendChild(eg);
    rows.forEach(function (list) {
      list.forEach(function (n) {
        var p = pos[n.id];
        var cls = "node" + (selected === n.id ? " sel" : "");
        var g = sv("g", { "class": cls, transform: "translate(" + p.x + "," + p.y + ")", tabindex: "0", role: "button",
                          "aria-pressed": selected === n.id ? "true" : "false",
                          "aria-label": n.type + ": " + n.label + ". Press Enter for details." });
        g.appendChild(sv("rect", { width: NW, height: NH, rx: 4 }));
        g.appendChild(sv("rect", { width: 3, height: NH, rx: 1.5, fill: COLOR[ROWS[n.type]], "class": "stripe" }));
        var lab = sv("text", { x: 12, y: 19 }); lab.textContent = trunc(n.type === "ioc" ? n.label : n.label, maxChars); g.appendChild(lab);
        var tt = sv("title", {}); tt.textContent = n.label; g.appendChild(tt);
        g.addEventListener("click", function () { select(n.id); });
        g.addEventListener("mouseenter", function () { hover = n.id; highlight(); });
        g.addEventListener("mouseleave", function () { hover = null; highlight(); });
        g.addEventListener("focus", function () { hover = n.id; highlight(); });
        g.addEventListener("blur", function () { hover = null; highlight(); });
        EL.nodes[n.id] = g;
        g.addEventListener("keydown", function (ev) { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); select(n.id, true); } });
        svg.appendChild(g);
      });
    });
    EL.view = view.edges;
    highlight();
    renderTable(view.edges);
    if (selected && !view.nodes[selected]) { selected = null; clearDetails(); }
    else if (selected) renderDetails(selected, view.edges);
  }

  // the whole chain through a node: walk left through lower columns and right through higher ones
  function chain(id, edges) {
    var out = { nodes: {}, edges: {} }, adj = {};
    edges.forEach(function (e) { (adj[e.source] = adj[e.source] || []).push(e); (adj[e.target] = adj[e.target] || []).push(e); });
    function walk(nid, dir) {
      out.nodes[nid] = true;
      (adj[nid] || []).forEach(function (e) {
        var o = e.source === nid ? e.target : e.source, d = ROWS[byId[o].type] - ROWS[byId[nid].type];
        if (d === 0 || (dir && Math.sign(d) !== dir)) return;
        out.edges[e.id] = true;
        if (!out.nodes[o]) walk(o, dir || Math.sign(d));
      });
    }
    walk(id, 0);
    return out;
  }
  function highlight() {
    var focusId = hover || selected, c = focusId && EL.view ? chain(focusId, EL.view) : null;
    $("graph").classList.toggle("focus", !!c);
    EL.edges.forEach(function (x) { x.el.classList.toggle("hi", !!(c && c.edges[x.e.id])); });
    Object.keys(EL.nodes).forEach(function (k) { EL.nodes[k].classList.toggle("hi", !!(c && c.nodes[k])); });
  }

  function connectedTo(id, edges) {
    var out = { nodes: {}, edges: {} }; out.nodes[id] = true;
    edges.forEach(function (e) { if (e.source === id || e.target === id) { out.edges[e.id] = true; out.nodes[e.source] = out.nodes[e.target] = true; } });
    return out;
  }

  function select(id, keepFocus) {
    selected = selected === id ? null : id;
    render();
    if (!selected) clearDetails();
    if (keepFocus) {
      var nodes = $("graph").querySelectorAll(".node");
      for (var i = 0; i < nodes.length; i++) if (nodes[i].getAttribute("aria-label").indexOf(byId[id].label + ".") >= 0) { nodes[i].focus(); break; }
    }
  }

  function clearDetails() {
    var d = $("details"); d.textContent = "";
    d.appendChild(el("h2", { id: "details-title", text: "Details" }));
    d.appendChild(el("p", { cls: "muted", text: "Select a node to see connected records, evidence, observation dates and why each relationship exists." }));
  }

  function renderDetails(id, edges) {
    var n = byId[id], d = $("details"); d.textContent = "";
    d.appendChild(el("h2", { id: "details-title", text: n.label }));
    d.appendChild(el("p", { cls: "muted", text: n.type === "ioc" ? "Indicator of compromise" : n.type.charAt(0).toUpperCase() + n.type.slice(1) }));
    var facts = [];
    if (n.type === "actor") {
      facts.push("Aliases: " + ((n.aliases || []).join(", ") || "None recorded"));
      facts.push("Classification: " + (n.classification || "Unknown"));
      facts.push("Motivation: " + (n.motivation || "Unknown"));
      facts.push("Suspected origin: " + (n.origin || "Not assessed"));
    } else if (n.type === "cve") {
      facts.push("Product: " + (n.product || "Unknown"));
      facts.push("Exploitation: " + (n.exploitation || "Unknown") + (n.kev ? " · in CISA KEV" : " · not in KEV"));
      facts.push("EPSS: " + (n.epss != null ? n.epss : "Unknown") + " · CVSS: " + (n.cvss != null ? n.cvss : "Unknown"));
    } else if (n.type === "campaign") {
      facts.push("Timeframe: " + (n.timeframe || "Unknown"));
    } else if (n.type === "ioc") {
      facts.push("Type: " + ({ ipv4: "IPv4 address", ipv6: "IPv6 address", domain: "Domain", url: "URL", sha256: "SHA-256 file hash", md5: "MD5 file hash" }[n.iocType] || n.iocType));
      facts.push("Value (defanged, do not visit): " + n.label);
      facts.push("Source: " + n.source + (n.ref ? " · " + n.ref : ""));
      facts.push("First seen: " + (n.firstSeen || "Unknown") + (n.malware ? " · malware: " + n.malware : ""));
    } else if (n.type === "industry") {
      facts.push("Category taken from MITRE ATT&CK's descriptions of the linked campaigns and actors.");
    } else if (n.type === "geography") {
      facts.push("Scope: " + (n.scope || "victim geography") + " — not actor origin.");
    }
    if (facts.length) d.appendChild(el("ul", null, facts.map(function (f) { return el("li", { text: f }); })));
    if (n.profile) d.appendChild(el("p", null, [link(n.profile, "Profile reference")]));
    if (n.url) d.appendChild(el("p", null, [link(n.url, "MITRE ATT&CK entry")]));

    var mine = edges.filter(function (e) { return e.source === id || e.target === id; });
    d.appendChild(el("h3", { text: "Connected records (" + mine.length + ")" }));
    d.appendChild(el("ul", null, mine.map(function (e) {
      var other = byId[e.source === id ? e.target : e.source], ev = e.evidence || {};
      return el("li", null, [
        el("strong", { text: (e.source === id ? REL[e.relation] + " → " : "← " + REL[e.relation] + " ") + other.label }),
        el("br"), e.why || "", el("br"),
        el("span", { cls: "muted", text: e.confidence + " confidence · " + (ev.type || "evidence type unknown") +
          " · report " + (ev.reportDate || "?") + " · observed " + (ev.firstObserved || "?") + " – " + (ev.lastObserved || "?") }),
        el("br"), link(ev.url, "Source"), ev.provenance ? el("span", { cls: "muted", text: " · " + ev.provenance }) : null
      ]);
    })));

    if (n.type === "actor") {
      var derived = [];
      edges.forEach(function (e) {
        if (e.source !== id || byId[e.target].type !== "campaign") return;
        edges.forEach(function (f) {
          if (f.source === e.target && (byId[f.target].type === "industry" || byId[f.target].type === "cve")) {
            derived.push(byId[f.target].label + " — via " + byId[e.target].label + " (" + REL[f.relation] + ", " +
              (CONF[f.confidence] < CONF[e.confidence] ? f.confidence : e.confidence) + " confidence)");
          }
        });
      });
      if (derived.length) {
        d.appendChild(el("h3", { text: "Derived links (through campaign evidence)" }));
        d.appendChild(el("ul", null, derived.map(function (t) { return el("li", { text: t }); })));
      }
    }
    d.appendChild(el("button", { type: "button", cls: "btn secondary", id: "clear-sel", text: "Clear selection" }));
    $("clear-sel").addEventListener("click", function () { selected = null; render(); clearDetails(); });
  }

  function renderTable(edges) {
    var tb = $("rel-table").querySelector("tbody"); tb.textContent = "";
    $("list-count").textContent = edges.length + " relationship" + (edges.length === 1 ? "" : "s") + " shown.";
    if (!edges.length) { tb.appendChild(el("tr", null, [el("td", { colspan: "6", text: "No verified relationships match these filters." })])); return; }
    edges.forEach(function (e) {
      var ev = e.evidence || {};
      tb.appendChild(el("tr", null, [
        el("td", { text: byId[e.source].label }), el("td", { text: REL[e.relation] }), el("td", { text: byId[e.target].label }),
        el("td", { text: e.confidence }), el("td", { text: (ev.firstObserved || "?") + " – " + (ev.lastObserved || "?") }),
        el("td", null, [link(ev.url, ev.type || "source")])
      ]));
    });
  }

  // ------------------------------------------------------------ boot
  function fill(selId, items) {
    items.forEach(function (it) { $(selId).appendChild(el("option", { value: it[0], text: it[1] })); });
    // Hide filters the current dataset has no values for (e.g. industry/geography in the ATT&CK-derived map).
    var lab = $(selId).closest("label");
    if (lab) lab.hidden = !items.length;
  }

  fetch("data/relationships.json", { cache: "no-cache" }).then(function (r) { return r.json(); }).then(function (g) {
    G = g;
    G.nodes.forEach(function (n) { byId[n.id] = n; });
    G.edges = G.edges.filter(function (e) { return byId[e.source] && byId[e.target]; });
    var banner = $("dataset-banner");
    if (!G.dataset || G.dataset.status !== "verified") {
      banner.appendChild(el("p", { cls: "notice demo" }, [el("strong", { text: "Demonstration data. " }),
        (G.dataset && G.dataset.label) || "These relationships are illustrative and are not live, verified threat attribution."]));
    } else {
      banner.appendChild(el("p", { cls: "notice info", text: "Verified, source-linked dataset · updated " + G.dataset.updatedAt }));
    }
    fill("f-ind", G.nodes.filter(function (n) { return n.type === "industry"; }).map(function (n) { return [n.id, n.label]; }));
    fill("f-geo", G.nodes.filter(function (n) { return n.type === "geography"; }).map(function (n) { return [n.id, n.label]; }));
    var types = {}; G.edges.forEach(function (e) { if (e.evidence && e.evidence.type) types[e.evidence.type] = true; });
    fill("f-ev", Object.keys(types).sort().map(function (t) { return [t, t]; }));
    ["f-q", "f-ind", "f-geo", "f-conf", "f-ev", "f-since", "f-exposure"].forEach(function (id) {
      $(id).addEventListener(id === "f-q" ? "input" : "change", render);
    });
    $("filters").addEventListener("submit", function (e) { e.preventDefault(); });
    $("f-reset").addEventListener("click", function () { $("filters").reset(); selected = null; clearDetails(); render(); });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape" && selected) { selected = null; clearDetails(); render(); } });
    render();
    var rt; window.addEventListener("resize", function () { clearTimeout(rt); rt = setTimeout(render, 150); });
  }).catch(function () {
    $("dataset-banner").appendChild(el("p", { cls: "notice", text: "Relationship data could not be loaded." }));
  });
})();
