/* AEGIS ThreatWatch — vulnerability assessment generator (browser only; nothing is sent anywhere).
 * Builds a decision-ready assessment for one CVE from the AEGIS record: executive summary, business
 * impact, threat picture, fix-or-defer decision with reasons, proof-of-concept and exploitation status,
 * ATT&CK TTPs, indicators of compromise, hunting and detection guidance, vendor guidance and references.
 * Also builds vendor-guided validation checks (package / version queries from vendor advisories).
 * Every statement is derived from cited data; where data is missing the report says so.
 */
(function () {
  "use strict";

  // ------------------------------------------------------------------ helpers
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }
  function safe(u) { return typeof u === "string" && /^https:\/\/[^\s"'<>]+$/.test(u) ? u : null; }
  function host(u) { try { return new URL(u).hostname.replace(/^www\./, ""); } catch (e) { return null; } }
  function uniq(a) { return a.filter(function (x, i) { return x && a.indexOf(x) === i; }); }
  function pctTop(p) { return p == null ? null : Math.max(1, Math.round((1 - p) * 100)); }
  function vec(v) {
    var o = {}; String(v || "").split("/").forEach(function (kv) { var p = kv.split(":"); if (p.length === 2) o[p[0]] = p[1]; }); return o;
  }

  // ------------------------------------------------------------------ vendor-guided validation
  var ECO = [
    [/^(ubuntu|debian)\b/i, "Debian/Ubuntu", function (p) { return "dpkg-query -W -f='${Package} ${Version}\\n' " + p; }],
    [/^(red ?hat|rhel|rocky|alma|centos|fedora|oracle linux|amazon linux|azure ?linux|suse|opensuse|sles|mariner)/i, "RPM-based Linux", function (p) { return "rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE}\\n' " + p; }],
    [/^alpine/i, "Alpine Linux", function (p) { return "apk info -v " + p; }],
    [/^pypi/i, "Python (pip)", function (p) { return "pip show " + p + "  # or: pip list | grep -i " + p; }],
    [/^npm/i, "Node.js (npm)", function (p) { return "npm ls " + p + " --all"; }],
    [/^maven/i, "Java (Maven)", function (p) { return "mvn dependency:tree -Dincludes=" + p.replace(/:.*/, "") + "  # Gradle: gradle dependencies | grep " + p.split(":").pop(); }],
    [/^go\b/i, "Go modules", function (p) { return "go list -m all | grep " + p; }],
    [/^crates/i, "Rust (cargo)", function (p) { return "cargo tree -i " + p; }],
    [/^nuget/i, ".NET (NuGet)", function (p) { return "dotnet list package --include-transitive | findstr /i " + p; }],
    [/^rubygems/i, "Ruby (gem)", function (p) { return "gem list " + p; }],
    [/^packagist/i, "PHP (Composer)", function (p) { return "composer show " + p; }]
  ];
  function packageChecks(r) {
    var out = [];
    (r.vendorAdvisories || []).forEach(function (a) {
      (a.products || []).forEach(function (prod) {
        var m = /^([^:]+):\s*([A-Za-z0-9_.+@\/:-]{1,80})/.exec(prod);
        if (!m) return;
        for (var i = 0; i < ECO.length; i++) {
          if (ECO[i][0].test(m[1])) {
            var pkg = m[2].replace(/\s.*$/, "");
            var fix = (a.fixes || []).map(function (f) { return f.text; }).filter(function (t) { return t && t.indexOf(pkg) >= 0; })[0];
            out.push({ platform: ECO[i][1], package: pkg, command: ECO[i][2](pkg), fixed: fix || null, source: (a.vendor || a.source) + (a.id ? " " + a.id : ""), url: safe(a.url) });
            break;
          }
        }
      });
    });
    var seen = {};
    return out.filter(function (x) { var k = x.platform + x.package; if (seen[k]) return false; seen[k] = 1; return true; }).slice(0, 12);
  }
  function vendorGuidance(r) {
    var advs = (r.vendorAdvisories || []).map(function (a) {
      return { vendor: a.vendor || a.publisher || a.source, id: a.id, title: a.title, url: safe(a.url), released: (a.released || "").slice(0, 10),
               products: (a.products || []).slice(0, 6), fixes: (a.fixes || []).filter(function (f) { return f.text || f.url; }).slice(0, 4),
               exploited: a.exploited === true };
    });
    var refs = (r.vendorRefs || []).concat(r.fixRefs || []).map(function (x) { return safe(x.url); }).filter(Boolean);
    var hosts = uniq(refs.concat(advs.map(function (a) { return a.url; }).filter(Boolean)).map(host)).filter(function (h) {
      return h && !/(nvd\.nist\.gov|cve\.org|mitre\.org|github\.com|twitter\.com|x\.com)$/.test(h);
    }).slice(0, 4);
    return {
      advisories: advs,
      vendorLinks: uniq(refs).slice(0, 8),
      searches: hosts.map(function (h) { return { host: h, url: "https://www.google.com/search?q=" + encodeURIComponent("site:" + h + " " + r.cve) }; }),
      packages: packageChecks(r),
      affected: (r.affected || []).slice(0, 12).map(function (a) { return [a.vendor, a.product, a.versions || "see advisory"].join(" · "); })
    };
  }

  // ------------------------------------------------------------------ hunting templates per ATT&CK technique
  var HUNT = {
    T1190: { what: "Exploitation of an internet-facing application", logs: "Web server, reverse proxy, WAF and load-balancer logs; EDR process telemetry on the server",
      look: ["Requests to the vulnerable endpoint or parameter, especially from scanning infrastructure or with unusual payloads (encoded strings, JNDI/LDAP, path traversal, template syntax).",
             "The web or application server process spawning a shell or script interpreter.", "New files written to web roots (possible web shell) and outbound connections from the server shortly after suspicious requests."],
      splunk: "index=edr (parent_process_name IN (\"java*\",\"w3wp.exe\",\"httpd\",\"nginx\",\"tomcat*\",\"php*\") process_name IN (\"cmd.exe\",\"powershell.exe\",\"pwsh.exe\",\"sh\",\"bash\",\"dash\")) | stats count by host parent_process_name process_name process",
      kql: "DeviceProcessEvents | where InitiatingProcessFileName has_any (\"java\",\"w3wp.exe\",\"httpd\",\"nginx\",\"tomcat\",\"php\") and FileName in~ (\"cmd.exe\",\"powershell.exe\",\"pwsh.exe\",\"sh\",\"bash\") | summarize count() by DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine" },
    T1133: { what: "Abuse of external remote services (VPN, gateway, remote access)", logs: "VPN/gateway authentication and session logs, identity provider sign-ins",
      look: ["Successful logins from new countries, hosting providers or impossible-travel locations.", "Sessions without MFA, or admin sessions on the appliance outside change windows.", "Configuration changes, new local accounts or unexpected processes on the appliance."],
      splunk: "index=vpn action=success | iplocation src_ip | stats dc(Country) as countries values(Country) by user | where countries>1",
      kql: "SigninLogs | where ResultType == 0 | summarize Countries=dcount(LocationDetails.countryOrRegion), make_set(IPAddress) by UserPrincipalName | where Countries > 1" },
    T1203: { what: "Client application exploitation (documents, browsers, mail clients)", logs: "EDR process telemetry, email gateway logs",
      look: ["Office, PDF readers, browsers or mail clients spawning command shells, script hosts or LOLBins.", "Recently received attachments or links that match the vulnerable file type."],
      splunk: "index=edr parent_process_name IN (\"winword.exe\",\"excel.exe\",\"powerpnt.exe\",\"outlook.exe\",\"acrord32.exe\",\"chrome.exe\",\"msedge.exe\",\"firefox.exe\") process_name IN (\"cmd.exe\",\"powershell.exe\",\"wscript.exe\",\"mshta.exe\",\"rundll32.exe\",\"regsvr32.exe\") | stats count by host user parent_process_name process",
      kql: "DeviceProcessEvents | where InitiatingProcessFileName in~ (\"winword.exe\",\"excel.exe\",\"powerpnt.exe\",\"outlook.exe\",\"acrord32.exe\",\"chrome.exe\",\"msedge.exe\") and FileName in~ (\"cmd.exe\",\"powershell.exe\",\"wscript.exe\",\"mshta.exe\",\"rundll32.exe\")" },
    T1068: { what: "Privilege escalation through a vulnerable component", logs: "EDR process and driver-load telemetry, OS security logs",
      look: ["Processes started as SYSTEM/root from a normal user's session.", "Loading of vulnerable or unsigned drivers / kernel modules.", "New administrator or sudo-capable accounts."],
      splunk: "index=edr (user!=\"SYSTEM\" AND process_user=\"SYSTEM\") OR (event_type=driver_load signature_status!=valid) | stats count by host user process",
      kql: "DeviceEvents | where ActionType == \"DriverLoad\" | join kind=leftanti (DeviceFileCertificateInfo | where IsTrusted == 1) on SHA1" },
    T1059: { what: "Command and scripting interpreter execution after exploitation", logs: "EDR command-line telemetry, PowerShell/Script Block logging",
      look: ["Encoded or obfuscated command lines.", "Interpreters downloading content from the internet."],
      splunk: "index=edr process_name IN (\"powershell.exe\",\"pwsh.exe\",\"bash\",\"sh\",\"python*\") (process=\"*-enc*\" OR process=\"*FromBase64String*\" OR process=\"*curl*http*\" OR process=\"*wget*http*\")",
      kql: "DeviceProcessEvents | where FileName in~ (\"powershell.exe\",\"pwsh.exe\") and ProcessCommandLine has_any (\"-enc\",\"FromBase64String\",\"DownloadString\")" },
    T1505: { what: "Web shell or server software component implanted", logs: "File integrity monitoring on web roots, web logs",
      look: ["New or modified script files (.jsp, .aspx, .php) in web directories.", "Requests to rarely used scripts that return small responses to a single client."],
      splunk: "index=edr event_type=file_create file_path IN (\"*\\\\inetpub\\\\*\",\"*/var/www/*\",\"*/webapps/*\") file_name IN (\"*.jsp\",\"*.aspx\",\"*.php\")",
      kql: "DeviceFileEvents | where FolderPath has_any (\"inetpub\",\"/var/www\",\"webapps\") and FileName endswith_cs \".jsp\" or FileName endswith \".aspx\" or FileName endswith \".php\"" },
    T1486: { what: "Data encrypted for impact (ransomware)", logs: "EDR file telemetry, backup and storage alerts",
      look: ["Mass file renames or new extensions on servers and shares.", "Deletion of shadow copies or backups (vssadmin, wbadmin, bcdedit)."],
      splunk: "index=edr process_name IN (\"vssadmin.exe\",\"wbadmin.exe\",\"bcdedit.exe\") (process=\"*delete*\" OR process=\"*resize*\")",
      kql: "DeviceProcessEvents | where FileName in~ (\"vssadmin.exe\",\"wbadmin.exe\",\"bcdedit.exe\") and ProcessCommandLine has_any (\"delete\",\"resize\",\"recoveryenabled no\")" }
  };
  HUNT.T1210 = { what: "Exploitation of remote services inside the network (lateral movement)", logs: "Internal firewall/NDR, Windows security logs",
    look: ["New internal connections to the vulnerable service from workstations.", "Authentication from servers that rarely initiate connections."],
    splunk: "index=netflow dest_port IN (139,445,3389,22,5985) | stats dc(dest_ip) as targets by src_ip | where targets>20",
    kql: "DeviceNetworkEvents | where RemotePort in (139,445,3389,22,5985) | summarize Targets=dcount(RemoteIP) by DeviceName | where Targets > 20" };

  // ------------------------------------------------------------------ the assessment
  function decision(r, e) {
    var cv = r.cvss || {}, v = vec(cv.vector), kev = !!(r.kev && r.kev.dateAdded), itw = !!(r.exploitation && r.exploitation.inTheWild),
        poc = (r.pocs && r.pocs.count) || 0, net = cv.attackVector === "NETWORK" || v.AV === "N", noAuth = cv.privileges === "NONE" || v.PR === "N",
        noUI = cv.userInteraction === "NONE" || v.UI === "N", score = cv.score || 0, top = e && e.percentile >= 0.9;
    var level, window, label, why = [];
    if (kev || itw || r.zeroDay) {
      level = "emergency"; label = "Remediate immediately"; window = kev && r.kev.dueDate ? "now; the CISA federal deadline was " + r.kev.dueDate : "within 24–72 hours";
    } else if ((poc && net && noAuth) || top) {
      level = "urgent"; label = "Remediate urgently"; window = "within 7 days";
    } else if (score >= 9) {
      level = "high"; label = "Remediate in the next priority patch cycle"; window = "within 15 days";
    } else if (score >= 7) {
      level = "elevated"; label = "Remediate in the regular patch cycle"; window = "within 30 days";
    } else {
      level = "standard"; label = "Remediate on the standard schedule, or formally accept the risk"; window = "within 90 days";
    }
    if (kev) why.push("CISA lists it as a Known Exploited Vulnerability (added " + r.kev.dateAdded + ").");
    if (itw && !kev) why.push("In-the-wild exploitation is reported by " + (r.exploitation.sources || []).map(function (s) { return s.source; }).join(", ") + ".");
    if (r.kev && r.kev.ransomware === "known") why.push("CISA notes known use in ransomware campaigns.");
    if (poc) why.push(poc + " public exploit / proof-of-concept reference(s) exist, which lowers the skill needed to attack.");
    if (top) why.push("EPSS rates it in the top " + pctTop(e.percentile) + "% most likely to be exploited in the next 30 days.");
    if (net && noAuth) why.push("It can be attacked over the network without credentials" + (noUI ? " or user interaction." : "."));
    if (score >= 9) why.push("CVSS " + score + " (critical).");
    if ((r.intel && r.intel.groups || []).length) why.push("Threat groups documented by MITRE ATT&CK have used it: " + r.intel.groups.map(function (g) { return g.name; }).slice(0, 5).join(", ") + ".");
    var defer = ["The affected product or version is not deployed anywhere (confirm with an authenticated inventory, not a network scan alone).",
                 "The vulnerable feature or configuration is disabled and the vendor confirms that removes exposure.",
                 "The system is not reachable by the attack vector (" + (net ? "network" : (cv.attackVector || "local").toLowerCase()) + ") and compensating controls (segmentation, WAF/IPS rule, MFA) are verified.",
                 "The system is being decommissioned before the remediation window ends."];
    if (level === "emergency") defer = ["Deferral is not recommended while exploitation is confirmed. Only an approved interim mitigation from the vendor (or isolating the asset) is acceptable until the fix is applied."].concat(defer.slice(0, 1));
    return { level: level, label: label, window: window, why: why, defer: defer };
  }

  function impactLines(r) {
    var cv = r.cvss || {}, v = vec(cv.vector), out = [];
    var map = { H: "high", L: "low", N: "no" };
    if (v.C) out.push("Confidentiality: " + map[v.C] + " impact" + (v.C === "H" ? ": an attacker could read sensitive data handled by the system." : "."));
    if (v.I) out.push("Integrity: " + map[v.I] + " impact" + (v.I === "H" ? ": an attacker could change data, configuration or code." : "."));
    if (v.A) out.push("Availability: " + map[v.A] + " impact" + (v.A === "H" ? ": an attacker could take the service down." : "."));
    if (v.S === "C") out.push("Scope changed: a successful attack can affect systems beyond the vulnerable component.");
    var how = [];
    if (cv.attackVector) how.push(cv.attackVector.toLowerCase() + " attack vector");
    if (cv.privileges) how.push(cv.privileges === "NONE" ? "no login needed" : cv.privileges.toLowerCase() + " privileges needed");
    if (cv.userInteraction) how.push(cv.userInteraction === "NONE" ? "no user action needed" : "a user must take an action");
    if (how.length) out.push("How it is attacked: " + how.join(", ") + ".");
    return out;
  }

  function build(r, ctx) {
    ctx = ctx || {};
    var e = ctx.epss || null, cv = r.cvss || {}, d = decision(r, e), vg = vendorGuidance(r);
    var prod = [r.vendor, (r.product || "").replace(/\s*\(\+\d+ other products?\)$/, "")].filter(Boolean).join(" ");
    var kev = r.kev && r.kev.dateAdded, itw = r.exploitation && r.exploitation.inTheWild, pocs = r.pocs || {};
    var sections = [];

    // 1. Executive summary
    var exec = (r.cve + " is a " + (cv.severity ? cv.severity.toLowerCase() + "-severity " : "") + "vulnerability in " + (prod || "the affected product") + ". ") +
      (kev ? "It is being actively exploited (CISA KEV since " + kev + "). " : itw ? "Exploitation in the wild has been reported. " : "No confirmed exploitation is recorded in AEGIS sources. ") +
      (pocs.count ? "Public exploit code exists. " : "No public exploit code is recorded. ") +
      "Recommendation: " + d.label.toLowerCase() + ", " + d.window + ".";
    sections.push({ h: "Executive summary", p: [exec, r.description ? "What it is: " + String(r.description).slice(0, 700) : null].filter(Boolean),
      table: { cols: ["Question", "Answer"], rows: [
        ["Are attackers using it?", kev ? "Yes: CISA KEV (" + kev + ")" : itw ? "Reported: " + (r.exploitation.sources || []).map(function (s) { return s.source; }).join(", ") : "Not confirmed in tracked sources"],
        ["Is attack code public?", pocs.count ? "Yes: " + pocs.count + " reference(s)" : "None recorded"],
        ["How likely is exploitation soon?", e ? "EPSS " + (e.score * 100).toFixed(1) + "% (top " + pctTop(e.percentile) + "% of CVEs)" : "EPSS not available"],
        ["Severity", cv.score != null ? "CVSS " + cv.score + " " + (cv.severity || "") : "Not scored yet"],
        ["Fix available?", (r.fixRefs || []).length || (vg.advisories.some(function (a) { return a.fixes.length; })) ? "Yes: see Remediation" : "No fix reference recorded yet: use mitigations"],
        ["Decision", d.label + " — " + d.window]] } });

    // 2. Business impact
    sections.push({ h: "Business impact", p: [
      "If exploited on a system your organization relies on, the realistic outcomes are:"].concat(impactLines(r)).concat([
      (r.kev && r.kev.ransomware === "known") ? "This vulnerability has been used in ransomware attacks, which typically means encrypted systems, data theft and extortion." : null,
      "Business impact depends on where the product runs: internet-facing gateways, identity systems, remote-management and backup platforms carry the highest risk because compromise gives attackers a foothold or control over many other systems."]).filter(Boolean) });

    // 3. Threat
    var tp = [];
    tp.push(kev ? "CISA confirmed active exploitation on " + kev + (r.kev.dueDate ? "; US federal agencies must remediate by " + r.kev.dueDate + "." : ".") : "Not listed in CISA KEV.");
    (r.exploitation && r.exploitation.sources || []).forEach(function (s) { if (s.source !== "CISA KEV") tp.push("Exploitation report: " + s.source + (s.date ? " (" + s.date + ")" : "") + "."); });
    if (r.zeroDay) tp.push("Exploited as a zero-day (before a fix was available).");
    if (e) tp.push("EPSS (FIRST) estimates a " + (e.score * 100).toFixed(1) + "% probability of exploitation activity in the next 30 days, higher than " + Math.round(e.percentile * 100) + "% of all CVEs.");
    var groups = (r.intel && r.intel.groups || []).map(function (g) { return g.name + " (" + g.id + ")"; });
    var camps = (r.intel && r.intel.campaigns || []).map(function (c) { return c.name; });
    (ctx.attackers || []).forEach(function (a) { if (groups.join(" ").indexOf(a.name) < 0) groups.push(a.name + (a.via ? " (via " + a.via + ")" : "")); });
    tp.push(groups.length ? "Threat actors linked by MITRE ATT&CK: " + uniq(groups).slice(0, 8).join(", ") + "." : "No threat actor is publicly linked to this CVE in MITRE ATT&CK.");
    if (camps.length) tp.push("Campaigns: " + camps.slice(0, 6).join(", ") + ".");
    sections.push({ h: "Threat assessment", bullets: tp });

    // 4. Decision
    sections.push({ h: "Should you fix it? Decision and rationale", p: ["**" + d.label + "** — target " + d.window + "."],
      bullets: d.why.length ? d.why : ["No exploitation, public exploit code or critical severity is recorded; remediate on the standard schedule."],
      sub: { h: "When deferring or accepting the risk can be justified", bullets: d.defer } });

    // 5. Proof of concept & exploitation evidence
    var pocRows = [];
    (pocs.metasploit || []).slice(0, 5).forEach(function (m) { pocRows.push(["Metasploit", m.name + (m.check ? " (has a non-destructive check)" : ""), safe(m.url) || ""]); });
    (pocs.exploitdb || []).slice(0, 5).forEach(function (x) { pocRows.push(["Exploit-DB", x.title + (x.verified ? " (verified)" : ""), safe(x.url) || ""]); });
    (pocs.github || []).slice(0, 6).forEach(function (g) { pocRows.push(["GitHub", g.repo + (g.stars ? " · ★" + g.stars : ""), safe(g.url) || ""]); });
    (pocs.vulncheckXdb || []).slice(0, 3).forEach(function (x) { pocRows.push(["VulnCheck XDB", x.name || x.id || "exploit", safe(x.url) || ""]); });
    sections.push({ h: "Proof of concept and exploit availability", p: [pocs.count ? pocs.count + " public reference(s). Public PoC repositories are unvetted and can contain malware: only use them in an isolated lab, never on production." : "No public proof-of-concept or exploit is recorded in Metasploit, Exploit-DB, GitHub or VulnCheck XDB. This can change quickly after disclosure."],
      table: pocRows.length ? { cols: ["Source", "Item", "Link"], rows: pocRows } : null });

    // 6. TTPs
    var techs = (r.attack && r.attack.techniques || []);
    sections.push({ h: "Tactics, techniques and procedures (MITRE ATT&CK)",
      p: [techs.length ? "Techniques mapped to this CVE (CTID / MITRE ATT&CK):" : "No ATT&CK technique mapping is published for this CVE. For an internet-facing product the initial-access technique is typically T1190 (Exploit Public-Facing Application)."],
      table: techs.length ? { cols: ["Technique", "Role", "Source"], rows: techs.map(function (t) { return [t.id + " " + t.name, (t.mappingType || "").replace(/_/g, " "), t.via || ""]; }) } : null });

    // 7. IOCs
    var iocs = ctx.iocs || [];
    sections.push({ h: "Indicators of compromise", p: [iocs.length ?
      "Indicators associated with the threat actors / campaigns that exploited this CVE (from CISA advisories and abuse.ch ThreatFox). They are actor-level indicators, not proof of exploitation of this CVE; values are defanged." :
      "No public indicators tied to this CVE or its known exploiters are in AEGIS sources. Use the behavioural hunting guidance below; check the vendor advisory and CISA alerts for any indicators they publish."],
      table: iocs.length ? { cols: ["Type", "Indicator (defanged)", "Source"], rows: iocs.slice(0, 25).map(function (i) { return [i.type, i.value, i.source]; }) } : null });

    // 8. Hunt & detect
    var ids = uniq(techs.map(function (t) { return t.id.split(".")[0]; }));
    if (!ids.length && (cv.attackVector === "NETWORK")) ids = ["T1190"];
    if (r.kev && r.kev.ransomware === "known" && ids.indexOf("T1486") < 0) ids.push("T1486");
    var hunts = ids.filter(function (t) { return HUNT[t]; }).map(function (t) { return { id: t, h: HUNT[t] }; });
    var dets = (r.detections || []).map(function (x) { return [x.method === "nuclei" ? "Nuclei" : x.method === "nmap" ? "Nmap NSE" : x.method, x.name || x.id, safe(x.url) || ""]; });
    sections.push({ h: "How to hunt and detect", p: ["Positive results mean ‘suspected’ until confirmed by an analyst. Adapt index and table names to your SIEM/EDR."],
      table: dets.length ? { cols: ["Detection check", "Name", "Link"], rows: dets.slice(0, 8) } : null,
      hunts: hunts,
      bullets: ["Search your SIEM, EDR and web logs for " + r.cve + " and for the vendor's published indicators.",
        "Sigma community rules: https://github.com/SigmaHQ/sigma (search for " + r.cve + ")."] });

    // 9. Remediation & vendor guidance
    var rem = [];
    var vend = String(r.vendor || "").toLowerCase().split(/\s+/)[0], own = [], other = [];
    vg.advisories.forEach(function (a) {
      var mineV = vend && String(a.vendor || "").toLowerCase().indexOf(vend) >= 0;
      a.fixes.forEach(function (f) { (mineV ? own : other).push((a.vendor || "Vendor") + ": " + (f.text || "fix") + (f.url ? " — " + f.url : "")); });
    });
    rem = own.slice(0, 6).concat(other.slice(0, 4).map(function (t) { return "Related product advisory — " + t; }));
    (r.fixRefs || []).slice(0, 5).forEach(function (f) { if (safe(f.url)) rem.push("Fix / mitigation reference: " + f.url); });
    if (r.kev && r.kev.requiredAction) rem.push("CISA required action: " + r.kev.requiredAction);
    sections.push({ h: "Remediation and vendor guidance", bullets: rem.length ? rem.slice(0, 14) : ["No vendor fix reference is recorded yet. Apply vendor mitigations, restrict network access to the affected service and monitor closely."],
      sub: vg.packages.length ? { h: "Check installed versions (from vendor advisories)", code: vg.packages.map(function (x) { return "# " + x.platform + (x.fixed ? " — " + x.fixed : "") + "\n" + x.command; }).join("\n\n") } : null });

    // 10. Other information
    var other = [];
    if (r.published) other.push("Published " + String(r.published).slice(0, 10) + (r.lastModified ? "; last modified " + String(r.lastModified).slice(0, 10) : "") + ".");
    if ((r.cwes || []).length) other.push("Weakness: " + r.cwes.join(", ") + ".");
    if (r.affectedTruncated || (r.affected || []).length) other.push((r.affected || []).length + (r.affectedTruncated ? "+" : "") + " affected product/version entries in NVD (see the CVE page).");
    if (r.vendorPublishedOnly) other.push("Vendor-published CVE with no NVD record yet: details come from the vendor advisory.");
    other.push("Prepared automatically by AEGIS ThreatWatch on " + new Date().toISOString().slice(0, 10) + " from public sources. Validate against your own inventory and the vendor advisory before acting.");
    sections.push({ h: "Other relevant information", bullets: other });

    var refs = uniq([].concat(vg.advisories.map(function (a) { return a.url; }), vg.vendorLinks, kev ? ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"] : [],
      ["https://nvd.nist.gov/vuln/detail/" + r.cve, "https://www.cve.org/CVERecord?id=" + r.cve, "https://www.first.org/epss/"]).filter(Boolean)).slice(0, 20);
    return { title: "Vulnerability assessment — " + r.cve + (prod ? " (" + prod + ")" : ""), decision: d, sections: sections, references: refs, vendor: vg };
  }

  // ------------------------------------------------------------------ renderers
  function inline(s) { return esc(s).replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>"); }
  function toHTML(m) {
    var h = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>" + esc(m.title) + "</title><style>" +
      "body{font:15px/1.55 Helvetica,Arial,sans-serif;color:#1f2933;max-width:900px;margin:30px auto;padding:0 20px}h1{font-size:24px;color:#1d3a5f}" +
      "h2{font-size:18px;color:#1d3a5f;border-bottom:2px solid #d9e2ec;padding-bottom:4px;margin-top:28px}h3{font-size:15px}table{border-collapse:collapse;width:100%;margin:8px 0}" +
      "th,td{border:1px solid #d9e2ec;padding:6px 8px;text-align:left;vertical-align:top;font-size:13px}th{background:#1f4e79;color:#fff}pre{background:#f4f6f8;padding:10px;white-space:pre-wrap;font-size:12px}" +
      ".dec{border-left:5px solid #b42318;background:#fef3f2;padding:10px 14px}.muted{color:#52606d;font-size:12px}</style></head><body>";
    h += "<h1>" + esc(m.title) + "</h1><p class=\"dec\"><strong>Decision: " + esc(m.decision.label) + "</strong> — " + esc(m.decision.window) + "</p>";
    m.sections.forEach(function (s, i) {
      h += "<h2>" + (i + 1) + ". " + esc(s.h) + "</h2>";
      (s.p || []).forEach(function (p) { h += "<p>" + inline(p) + "</p>"; });
      if (s.bullets) h += "<ul>" + s.bullets.map(function (b) { return "<li>" + inline(b) + "</li>"; }).join("") + "</ul>";
      if (s.table) h += "<table><tr>" + s.table.cols.map(function (c) { return "<th>" + esc(c) + "</th>"; }).join("") + "</tr>" +
        s.table.rows.map(function (r) { return "<tr>" + r.map(function (c) { return "<td>" + (safe(c) ? "<a href=\"" + esc(c) + "\">" + esc(c) + "</a>" : esc(c)) + "</td>"; }).join("") + "</tr>"; }).join("") + "</table>";
      (s.hunts || []).forEach(function (x) {
        h += "<h3>" + esc(x.id + " — " + x.h.what) + "</h3><p><strong>Log sources:</strong> " + esc(x.h.logs) + "</p><ul>" + x.h.look.map(function (l) { return "<li>" + esc(l) + "</li>"; }).join("") +
          "</ul><p><strong>Splunk</strong></p><pre>" + esc(x.h.splunk) + "</pre><p><strong>Microsoft Defender / Sentinel (KQL)</strong></p><pre>" + esc(x.h.kql) + "</pre>";
      });
      if (s.sub) { h += "<h3>" + esc(s.sub.h) + "</h3>"; if (s.sub.bullets) h += "<ul>" + s.sub.bullets.map(function (b) { return "<li>" + inline(b) + "</li>"; }).join("") + "</ul>"; if (s.sub.code) h += "<pre>" + esc(s.sub.code) + "</pre>"; }
    });
    h += "<h2>References</h2><ol>" + m.references.map(function (u) { return "<li><a href=\"" + esc(u) + "\">" + esc(u) + "</a></li>"; }).join("") + "</ol>";
    h += "<p class=\"muted\">AEGIS ThreatWatch · aegisdefensecyber.com/threatwatch · Generated from public data; not a guarantee that a system is or is not vulnerable.</p></body></html>";
    return h;
  }
  function toDOM(m, el) {
    function rich(s) { return String(s).split("**").map(function (part, i) { return i % 2 ? el("strong", { text: part }) : document.createTextNode(part); }); }
    function cell(c) { return el("td", null, [safe(c) ? el("a", { href: c, rel: "noopener noreferrer", target: "_blank", text: c.replace(/^https:\/\//, "").slice(0, 70) }) : document.createTextNode(c)]); }
    var root = el("div", { cls: "assess" }, [el("p", { cls: "assess-dec " + m.decision.level }, [el("strong", { text: "Decision: " + m.decision.label }), " — " + m.decision.window])]);
    m.sections.forEach(function (s, i) {
      var sec = el("section", { cls: "assess-sec" }, [el("h4", { text: (i + 1) + ". " + s.h })]);
      (s.p || []).forEach(function (p) { sec.appendChild(el("p", null, rich(p))); });
      if (s.bullets) sec.appendChild(el("ul", null, s.bullets.map(function (b) { return el("li", null, rich(b)); })));
      if (s.table) sec.appendChild(el("div", { cls: "assess-tbl" }, [el("table", null, [el("thead", null, [el("tr", null, s.table.cols.map(function (c) { return el("th", { text: c }); }))]),
        el("tbody", null, s.table.rows.map(function (r) { return el("tr", null, r.map(cell)); }))])]));
      (s.hunts || []).forEach(function (x) {
        sec.appendChild(el("h5", { text: x.id + " — " + x.h.what }));
        sec.appendChild(el("p", null, [el("strong", { text: "Log sources: " }), x.h.logs]));
        sec.appendChild(el("ul", null, x.h.look.map(function (l) { return el("li", { text: l }); })));
        sec.appendChild(el("p", { cls: "muted", text: "Splunk" })); sec.appendChild(el("pre", { text: x.h.splunk }));
        sec.appendChild(el("p", { cls: "muted", text: "Microsoft Defender / Sentinel (KQL)" })); sec.appendChild(el("pre", { text: x.h.kql }));
      });
      if (s.sub) {
        sec.appendChild(el("h5", { text: s.sub.h }));
        if (s.sub.bullets) sec.appendChild(el("ul", null, s.sub.bullets.map(function (b) { return el("li", null, rich(b)); })));
        if (s.sub.code) sec.appendChild(el("pre", { text: s.sub.code }));
      }
      root.appendChild(sec);
    });
    return root;
  }

  window.TWAssess = { build: build, toHTML: toHTML, toDOM: toDOM, vendorGuidance: vendorGuidance, decision: decision };
})();
