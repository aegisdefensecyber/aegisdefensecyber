/* AEGIS ThreatWatch — live lookup of any CVE in the official CVE List (CVEProject/cvelistV5).
   Used when a CVE is not in the site's own catalog. Returns a small normalised record. */
(function () {
  "use strict";
  var BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/";
  var ID_RE = /^CVE-(\d{4})-(\d{4,7})$/;
  var cache = {};

  function safe(u) { return typeof u === "string" && /^https:\/\/[^\s"'<>]+$/.test(u) ? u : null; }
  function en(list) {
    var d = (list || []).filter(function (x) { return (x.lang || "").indexOf("en") === 0; })[0] || (list || [])[0];
    return d ? String(d.value || d.description || "") : "";
  }
  function bestCvss(containers) {
    var order = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"], best = null;
    containers.forEach(function (c) {
      (c.metrics || []).forEach(function (m) {
        order.forEach(function (k, i) {
          var v = m[k];
          if (v && typeof v.baseScore === "number" && (!best || i < best.rank)) {
            best = { rank: i, score: v.baseScore, severity: v.baseSeverity || null, version: v.version || k,
                     vector: v.vectorString || null, by: (c.providerMetadata || {}).shortName || "CNA" };
          }
        });
      });
    });
    return best;
  }

  function normalise(doc, id) {
    var meta = doc.cveMetadata || {}, cont = doc.containers || {}, cna = cont.cna || {}, adp = cont.adp || [];
    var all = [cna].concat(adp);
    var cwes = [];
    all.forEach(function (c) {
      (c.problemTypes || []).forEach(function (p) {
        (p.descriptions || []).forEach(function (d) {
          if (d.cweId && cwes.indexOf(d.cweId) < 0) cwes.push(d.cweId);
        });
      });
    });
    var aff = (cna.affected || []).filter(function (a) { return a.vendor && a.vendor !== "n/a"; });
    var kev = null, ssvc = null;
    adp.forEach(function (c) {
      (c.metrics || []).forEach(function (m) {
        var o = m.other || {};
        if (o.type === "kev" && o.content) kev = { dateAdded: o.content.dateAdded || null };
        if (o.type === "ssvc" && o.content) {
          ssvc = {};
          (o.content.options || []).forEach(function (opt) { Object.keys(opt).forEach(function (k) { ssvc[k] = opt[k]; }); });
        }
      });
    });
    var refs = [];
    (cna.references || []).forEach(function (r) {
      var u = safe(r.url);
      if (u && refs.length < 12) refs.push({ url: u, name: r.name && r.name.length < 90 ? r.name : u.replace(/^https:\/\//, "").slice(0, 80) });
    });
    return {
      cve: id, source: "CVE List", state: meta.state || "PUBLISHED",
      title: cna.title || "", description: en(cna.descriptions) || en((cna.rejectedReasons || [])),
      vendor: aff.length ? aff[0].vendor : "", product: aff.length ? aff[0].product : "",
      affected: aff.slice(0, 8).map(function (a) { return (a.vendor + " " + (a.product || "")).trim(); }),
      published: (meta.datePublished || "").slice(0, 10), updated: (meta.dateUpdated || "").slice(0, 10),
      assigner: meta.assignerShortName || "", cvss: bestCvss(all), cwes: cwes, kev: kev, ssvc: ssvc,
      references: refs, recordUrl: "https://www.cve.org/CVERecord?id=" + id
    };
  }

  function lookup(raw) {
    var id = String(raw || "").trim().toUpperCase(), m = ID_RE.exec(id);
    if (!m) return Promise.reject(new Error("Not a CVE ID"));
    if (cache[id]) return cache[id];
    var bucket = Math.floor(parseInt(m[2], 10) / 1000) + "xxx";
    var url = BASE + m[1] + "/" + bucket + "/" + id + ".json";
    cache[id] = fetch(url, { cache: "no-cache" }).then(function (r) {
      if (r.status === 404) return null;
      if (!r.ok) throw new Error("CVE List returned HTTP " + r.status);
      return r.json().then(function (d) { return normalise(d, id); });
    });
    cache[id].catch(function () { delete cache[id]; });
    return cache[id];
  }

  window.TWCveList = { lookup: lookup, ID_RE: ID_RE };
})();
