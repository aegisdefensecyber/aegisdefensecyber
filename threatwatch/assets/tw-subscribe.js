/* ThreatWatch email signup: email address only, posted to the provider in subscription-config.json.
   No address is stored by this site. The provider (Zoho Campaigns) sends a confirmation email
   (double opt-in) before anyone is subscribed. For Zoho, signupUrl is the form's weboptin.zc action,
   emailField is CONTACT_EMAIL and hiddenFields holds the hidden inputs from the Zoho form code. */
(function () {
  "use strict";
  var form = document.getElementById("subscribe-form");
  if (!form) return;
  var input = document.getElementById("sub-email");
  var msg = document.getElementById("sub-msg");
  var btn = form.querySelector("button[type=submit]");
  var EMAIL_RE = /^[^\s@<>"']{1,64}@[^\s@<>"']+\.[^\s@<>"']{2,}$/;
  var cfg = null;

  function say(text, kind) {
    msg.textContent = text;
    msg.className = "sub-msg" + (kind ? " " + kind : "");
  }
  var SAFE_NAME = /^[A-Za-z0-9_]{1,40}$/, SAFE_VAL = /^[A-Za-z0-9_.:\-]{0,200}$/;
  function applyFields(c) {
    if (c && SAFE_NAME.test(c.emailField || "")) input.name = c.emailField;
    var hf = (c && c.hiddenFields) || {};
    Object.keys(hf).forEach(function (k) {
      if (!SAFE_NAME.test(k) || typeof hf[k] !== "string" || !SAFE_VAL.test(hf[k]) || form.elements[k]) return;
      var h = document.createElement("input");
      h.type = "hidden"; h.name = k; h.value = hf[k];
      form.appendChild(h);
    });
  }
  function endpoint(c) {
    var u = c && c.enabled && typeof c.signupUrl === "string" ? c.signupUrl : "";
    return /^https:\/\/[^\s"'<>]+$/.test(u) ? u : null;
  }

  // Pages outside /threatwatch/ point at the shared config with data-config="../threatwatch/subscription-config.json".
  var cfgUrl = form.getAttribute("data-config") || "subscription-config.json";
  if (!/^(\.\.\/)?[\w\-\/]*subscription-config\.json$/.test(cfgUrl)) cfgUrl = "subscription-config.json";
  fetch(cfgUrl, { cache: "no-cache" })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (c) {
      cfg = c; var u = endpoint(c); if (u) { form.action = u; applyFields(c); }
      // The "brief + alerts" choice stays hidden until the Zoho opt-in field is configured, so it never silently does nothing.
      var ao = (c && c.alertsOptIn) || {}, fs = form.querySelector(".sub-choice");
      if (fs && u && ao.field && SAFE_NAME.test(ao.field)) fs.hidden = false;
    })
    .catch(function () { cfg = null; });

  form.querySelectorAll('input[name="tw_choice"]').forEach(function (r) { r.setAttribute("form", "tw-none"); });
  form.addEventListener("submit", function (ev) {
    var email = (input.value || "").trim();
    input.value = email;
    if (!email || !EMAIL_RE.test(email) || !input.checkValidity()) {
      ev.preventDefault();
      input.setAttribute("aria-invalid", "true");
      say("Please enter a valid email address.", "err");
      input.focus();
      return;
    }
    input.removeAttribute("aria-invalid");
    var url = endpoint(cfg);
    if (!url) {
      ev.preventDefault();
      say("Email signup opens soon. Thank you for your interest. Please check back shortly.", "info");
      return;
    }
    form.action = url;
    var wantsAlerts = !!form.querySelector('input[name="tw_choice"][value="alerts"]:checked');
    var ao = (cfg && cfg.alertsOptIn) || {}, oldFlag = form.querySelector("input[data-alerts]");
    if (oldFlag) oldFlag.remove();
    if (wantsAlerts && SAFE_NAME.test(ao.field || "") && SAFE_VAL.test(ao.value || "Yes")) {
      var f = document.createElement("input");
      f.type = "hidden"; f.name = ao.field; f.value = ao.value || "Yes"; f.setAttribute("data-alerts", "1");
      form.appendChild(f);
    }
    // The provider's confirmation page opens in a new tab (target=_blank); this page stays put.
    say("Almost done: check your inbox and click the confirmation link to start receiving the brief" +
        (wantsAlerts ? (ao.field ? " and alerts." : ". Alert emails are launching shortly; until then, follow alerts on the Alerts page or by RSS.") : "."), "ok");
    btn.disabled = true;
    setTimeout(function () { form.reset(); btn.disabled = false; }, 1500);
  });
  input.addEventListener("input", function () {
    if (input.getAttribute("aria-invalid")) { input.removeAttribute("aria-invalid"); say(""); }
  });
})();
