/* Granted Agent — signed-in application.
 *
 * Plain ES2020, no framework, because the whole surface is a handful of views
 * and a build step would add more moving parts than the app has.
 *
 * Two things in here are security-relevant and easy to get wrong:
 *
 * 1. State-changing requests carry the CSRF token from the readable cookie in
 *    an X-CSRF-Token header. The server enforces this for cookie sessions. Do
 *    not "simplify" this by dropping the header; it is not decoration.
 *
 * 2. Every tenant-scoped call includes the nonprofit id in the *path*. The
 *    server derives authorisation from the caller's membership, so a wrong id
 *    yields a 404, not someone else's data. The client never decides access.
 *
 * All user-supplied text is inserted via textContent or createElement. No
 * innerHTML with interpolated data anywhere in this file - grant titles come
 * from third-party feeds and are not trusted.
 */
"use strict";

const API = "";

function readCookie(name) {
  const parts = document.cookie ? document.cookie.split("; ") : [];
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq > -1 && part.slice(0, eq) === name) {
      return decodeURIComponent(part.slice(eq + 1));
    }
  }
  return "";
}

async function api(path, options) {
  const opts = Object.assign({ credentials: "same-origin" }, options || {});
  const headers = Object.assign({}, opts.headers || {});
  const method = (opts.method || "GET").toUpperCase();

  if (opts.body && typeof opts.body !== "string") {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.body);
  }
  if (["POST", "PUT", "PATCH", "DELETE"].indexOf(method) > -1) {
    const token = readCookie("ga_csrf");
    if (token) headers["X-CSRF-Token"] = token;
  }
  opts.headers = headers;

  const response = await fetch(API + path, opts);
  const text = await response.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch (e) { data = { detail: text }; }
  }
  if (!response.ok) {
    const err = new Error((data && (data.detail || data.message)) || "Request failed");
    err.status = response.status;
    err.data = data;
    throw err;
  }
  return data;
}

/* --- small DOM helpers ---------------------------------------------------- */

function h(tag, attrs, children) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const key of Object.keys(attrs)) {
      const value = attrs[key];
      if (value === null || value === undefined || value === false) continue;
      if (key === "class") el.className = value;
      else if (key === "text") el.textContent = value;
      else if (key === "onClick") el.addEventListener("click", value);
      else if (key === "onSubmit") el.addEventListener("submit", value);
      else if (key === "onInput") el.addEventListener("input", value);
      else if (key === "onChange") el.addEventListener("change", value);
      else if (key === "value") el.value = value;
      else el.setAttribute(key, value === true ? "" : value);
    }
  }
  if (children) {
    for (const child of [].concat(children)) {
      if (child === null || child === undefined || child === false) continue;
      el.appendChild(typeof child === "string" || typeof child === "number"
        ? document.createTextNode(String(child))
        : child);
    }
  }
  return el;
}

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

const state = {
  user: null,
  nonprofits: [],
  activeId: null,
  view: "overview",
  flash: null,
};

function flash(kind, text) { state.flash = { kind: kind, text: text }; }

function activeNonprofit() {
  return state.nonprofits.find((n) => n.id === state.activeId) || null;
}

function isAdmin() {
  const np = activeNonprofit();
  return !!np && ["admin", "owner"].indexOf(np.role) > -1;
}

/* --- error surface -------------------------------------------------------- */

function showError(err) {
  let text = err && err.message ? err.message : "Something went wrong.";
  if (err && err.status === 404) text = "Not found, or you do not have access to it.";
  if (err && err.status === 401) text = "Your session expired. Sign in again.";
  if (err && err.status === 402) text = text || "You have reached your plan limit.";
  flash("error", text);
  render();
}

/* --- auth views ----------------------------------------------------------- */

function authView() {
  const container = h("div", { class: "auth-shell" });
  const mode = state.authMode || "login";

  container.appendChild(h("div", { class: "center", style: "margin-bottom:1.5rem" }, [
    h("div", { class: "brand", style: "font-size:1.3rem", text: "GrantedAgent" }),
    h("p", { class: "muted small", text: "Grant intelligence for the entire US." }),
  ]));

  const card = h("div", { class: "card" });
  if (state.flash) card.appendChild(alertEl(state.flash));

  const err = h("div", { class: "alert error", style: "display:none" });
  card.appendChild(err);

  function fail(message) {
    err.textContent = message;
    err.style.display = "block";
  }

  if (mode === "login") {
    const email = h("input", { type: "email", name: "email", autocomplete: "email", required: true });
    const password = h("input", { type: "password", name: "password", autocomplete: "current-password", required: true });
    const submit = h("button", { type: "submit", style: "width:100%;margin-top:1rem", text: "Sign in" });

    card.appendChild(h("h1", { text: "Sign in" }));
    card.appendChild(h("form", { onSubmit: async (e) => {
      e.preventDefault();
      submit.disabled = true;
      err.style.display = "none";
      try {
        const data = await api("/api/auth/login", {
          method: "POST",
          body: { email: email.value.trim(), password: password.value },
        });
        state.user = data.user;
        state.nonprofits = data.nonprofits || [];
        state.activeId = state.nonprofits.length ? state.nonprofits[0].id : null;
        state.flash = null;
        render();
      } catch (ex) {
        fail(ex.message);
      } finally {
        submit.disabled = false;
      }
    } }, [
      h("div", { class: "field" }, [h("label", { text: "Email" }), email]),
      h("div", { class: "field" }, [h("label", { text: "Password" }), password]),
      submit,
    ]));

    card.appendChild(h("div", { class: "hr" }));
    card.appendChild(h("div", { class: "row", style: "justify-content:space-between" }, [
      h("button", { class: "ghost small", text: "Create an account", onClick: () => { state.authMode = "signup"; state.flash = null; render(); } }),
      h("button", { class: "ghost small", text: "Forgot password?", onClick: () => { state.authMode = "forgot"; state.flash = null; render(); } }),
    ]));
  } else if (mode === "signup") {
    const email = h("input", { type: "email", autocomplete: "email", required: true });
    const password = h("input", { type: "password", autocomplete: "new-password", required: true });
    const fullName = h("input", { type: "text", autocomplete: "name" });
    const org = h("input", { type: "text", required: true });
    const st = h("input", { type: "text", maxlength: "2", placeholder: "WI" });
    const submit = h("button", { type: "submit", style: "width:100%;margin-top:1rem", text: "Create account" });

    card.appendChild(h("h1", { text: "Create your account" }));
    card.appendChild(h("p", { class: "muted small", text: "Your first organization is created with you as its owner." }));
    card.appendChild(h("form", { onSubmit: async (e) => {
      e.preventDefault();
      submit.disabled = true;
      err.style.display = "none";
      try {
        const data = await api("/api/auth/signup", {
          method: "POST",
          body: {
            email: email.value.trim(),
            password: password.value,
            full_name: fullName.value.trim() || null,
            nonprofit_name: org.value.trim(),
            state: (st.value || "").trim().toUpperCase(),
          },
        });
        state.user = data.user;
        state.nonprofits = data.nonprofits || [];
        state.activeId = state.nonprofits.length ? state.nonprofits[0].id : null;
        state.flash = { kind: "ok", text: "Account created. Check your email to confirm your address." };
        render();
      } catch (ex) {
        fail(ex.message);
      } finally {
        submit.disabled = false;
      }
    } }, [
      h("div", { class: "field" }, [h("label", { text: "Work email" }), email]),
      h("div", { class: "field" }, [h("label", { text: "Password" }), password,
        h("div", { class: "small muted", text: "At least 12 characters, mixing letters with numbers or symbols." })]),
      h("div", { class: "field" }, [h("label", { text: "Your name" }), fullName]),
      h("div", { class: "field" }, [h("label", { text: "Organization name" }), org]),
      h("div", { class: "field" }, [h("label", { text: "State (2 letters)" }), st]),
      submit,
    ]));

    card.appendChild(h("div", { class: "hr" }));
    card.appendChild(h("button", { class: "ghost small", text: "Back to sign in", onClick: () => { state.authMode = "login"; state.flash = null; render(); } }));
  } else if (mode === "forgot") {
    const email = h("input", { type: "email", required: true });
    const submit = h("button", { type: "submit", style: "width:100%;margin-top:1rem", text: "Send reset link" });
    card.appendChild(h("h1", { text: "Reset your password" }));
    card.appendChild(h("p", { class: "muted small", text: "If an account exists for that address, we will email a reset link." }));
    card.appendChild(h("form", { onSubmit: async (e) => {
      e.preventDefault();
      submit.disabled = true;
      err.style.display = "none";
      try {
        await api("/api/auth/forgot-password", { method: "POST", body: { email: email.value.trim() } });
        flash("ok", "If an account exists for that address, a reset link is on its way.");
        state.authMode = "login";
        render();
      } catch (ex) {
        fail(ex.message);
      } finally {
        submit.disabled = false;
      }
    } }, [h("div", { class: "field" }, [h("label", { text: "Email" }), email]), submit]));
    card.appendChild(h("div", { class: "hr" }));
    card.appendChild(h("button", { class: "ghost small", text: "Back to sign in", onClick: () => { state.authMode = "login"; render(); } }));
  }

  container.appendChild(card);
  return container;
}

function promptReset() {
  const container = h("div", { class: "auth-shell" });
  const token = h("input", { type: "text", placeholder: "token from your email", required: true });
  const password = h("input", { type: "password", required: true });
  const err = h("div", { class: "alert error", style: "display:none" });
  const submit = h("button", { type: "submit", style: "width:100%;margin-top:1rem", text: "Set new password" });

  container.appendChild(h("div", { class: "card" }, [
    h("h1", { text: "Set a new password" }),
    err,
    h("form", { onSubmit: async (e) => {
      e.preventDefault();
      submit.disabled = true;
      try {
        await api("/api/auth/reset-password", {
          method: "POST",
          body: { token: token.value.trim(), password: password.value },
        });
        flash("ok", "Password updated. Sign in with your new password.");
        state.route = "/app";
        window.history.replaceState({}, "", "/app");
        state.authMode = "login";
        render();
      } catch (ex) {
        err.textContent = ex.message; err.style.display = "block";
      } finally { submit.disabled = false; }
    } }, [
      h("div", { class: "field" }, [h("label", { text: "Reset token" }), token]),
      h("div", { class: "field" }, [h("label", { text: "New password" }), password]),
      submit,
    ]),
  ]));
  return container;
}

function promptVerify() {
  const container = h("div", { class: "auth-shell" });
  const params = new URLSearchParams(window.location.search);
  const token = params.get("token") || "";
  const body = h("div", { class: "card" }, [h("h1", { text: "Confirming your email…" })]);

  api("/api/auth/verify-email", { method: "POST", body: { token: token } })
    .then(() => {
      clear(body);
      body.appendChild(h("h1", { text: "Email confirmed" }));
      body.appendChild(h("p", { class: "muted", text: "Your address is verified." }));
      const go = h("button", { text: "Continue to the app", style: "margin-top:1rem", onClick: () => {
        window.history.replaceState({}, "", "/app");
        state.route = "/app";
        render();
      } });
      body.appendChild(go);
    })
    .catch((err) => {
      clear(body);
      body.appendChild(h("h1", { text: "Link problem" }));
      body.appendChild(h("div", { class: "alert error", text: err.message }));
      body.appendChild(h("button", { class: "secondary", text: "Go to sign in", onClick: () => {
        window.history.replaceState({}, "", "/app");
        state.route = "/app";
        state.authMode = "login";
        render();
      } }));
    });

  container.appendChild(body);
  return container;
}

/* --- dashboard views ------------------------------------------------------ */

function alertEl(f) {
  return h("div", { class: "alert " + f.kind, text: f.text });
}

function shellView() {
  const wrap = h("div");
  const np = activeNonprofit();

  const actions = h("div", { class: "topbar-actions" });
  if (state.nonprofits.length > 1) {
    const select = h("select", { onChange: (e) => {
      state.activeId = parseInt(e.target.value, 10);
      render();
    } });
    for (const org of state.nonprofits) {
      select.appendChild(h("option", { value: org.id, text: org.name + " (" + org.role + ")", selected: org.id === state.activeId }));
    }
    actions.appendChild(select);
  } else if (np) {
    actions.appendChild(h("span", { class: "badge", text: np.name + " · " + np.role }));
  }
  if (state.user && !state.user.email_verified) {
    actions.appendChild(h("span", { class: "badge amber", text: "email unconfirmed" }));
  }
  actions.appendChild(h("button", { class: "ghost small", text: "Sign out", onClick: async () => {
    try { await api("/api/auth/logout", { method: "POST" }); } catch (e) { /* already gone */ }
    state.user = null; state.nonprofits = []; state.activeId = null; state.flash = null;
    render();
  } }));

  wrap.appendChild(h("div", { class: "topbar" }, [
    h("div", { class: "brand", text: "GrantedAgent" }),
    actions,
  ]));

  const shell = h("div", { class: "shell" });
  wrap.appendChild(shell);

  if (state.flash) { shell.appendChild(alertEl(state.flash)); state.flash = null; }

  if (!np) {
    shell.appendChild(h("div", { class: "card" }, [
      h("h2", { text: "No organization yet" }),
      h("p", { class: "muted", text: "Your account is not linked to a nonprofit." }),
    ]));
    return wrap;
  }

  const tabs = h("div", { class: "tabs" });
  const views = [
    ["overview", "Overview"],
    ["inbox", "Inbox"],
    ["soul", "Soul"],
    ["drafts", "Drafts"],
    ["activity", "Activity"],
    ["billing", "Billing"],
    ["team", "Team"],
  ];
  for (const pair of views) {
    tabs.appendChild(h("button", {
      text: pair[1],
      "aria-current": state.view === pair[0] ? "true" : "false",
      onClick: () => { state.view = pair[0]; state.flash = null; render(); },
    }));
  }
  shell.appendChild(tabs);

  const body = h("div");
  shell.appendChild(body);

  const loaders = {
    overview: renderOverview,
    inbox: renderInbox,
    soul: renderSoul,
    drafts: renderDrafts,
    activity: renderActivity,
    billing: renderBilling,
    team: renderTeam,
  };
  (loaders[state.view] || renderOverview)(body, np);
  return wrap;
}

function renderOverview(node, np) {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", { text: "Catalogue" }));
  card.appendChild(h("p", { class: "muted small", text: "Shared grant catalogue and your review progress." }));
  const stats = h("div", { class: "grid cols-3", style: "margin-top:1rem" });
  card.appendChild(stats);
  node.appendChild(card);

  api("/api/nonprofits/" + np.id + "/stats").then((data) => {
    clear(stats);
    stats.appendChild(statBlock("Grants tracked", data.grants_total));
    stats.appendChild(statBlock("Upcoming deadlines", data.upcoming_deadlines));
    const counts = data.matches_by_status || {};
    stats.appendChild(statBlock("Needs review", counts.NEEDS_REVIEW || 0));

    const sources = h("div", { class: "card" });
    sources.appendChild(h("h3", { text: "By source" }));
    const table = h("table");
    const thead = h("thead", {}, h("tr", {}, [h("th", { text: "Source" }), h("th", { text: "Grants" })]));
    const tbody = h("tbody");
    for (const key of Object.keys(data.by_source || {}).sort()) {
      tbody.appendChild(h("tr", {}, [h("td", { text: key }), h("td", { text: String(data.by_source[key]) })]));
    }
    table.appendChild(thead); table.appendChild(tbody);
    sources.appendChild(table);
    node.appendChild(sources);
  }).catch(showError);
}

function statBlock(label, value) {
  return h("div", {}, [
    h("div", { class: "stat", text: String(value) }),
    h("div", { class: "muted small", text: label }),
  ]);
}

function renderInbox(node, np) {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", { text: "Inbox" }));
  card.appendChild(h("p", { class: "muted small", text: "Ranked matches for your organization. You approve or reject; nothing is submitted automatically." }));
  node.appendChild(card);

  const list = h("div", { style: "margin-top:1rem" });
  card.appendChild(list);

  api("/api/nonprofits/" + np.id + "/matches?limit=50").then((data) => {
    if (!data.items || !data.items.length) {
      list.appendChild(h("p", { class: "muted", text: "No matches yet. The hunter scores new grants on each run." }));
      return;
    }
    for (const match of data.items) {
      list.appendChild(matchRow(match, np, list));
    }
  }).catch(showError);
}

function matchRow(match, np, list) {
  const grant = match.grant || {};
  const row = h("div", { class: "card" });
  const score = Math.round(match.score * 10) / 10;

  row.appendChild(h("div", { class: "spread" }, [
    h("div", {}, [
      h("h3", { text: grant.title || "(untitled)" }),
      h("div", { class: "muted small", text: (grant.agency || "Unknown agency") +
        (grant.deadline ? " · due " + grant.deadline : "") }),
    ]),
    h("span", { class: "badge green", text: score + " match" }),
  ]));

  if (grant.description) {
    row.appendChild(h("p", { class: "small muted", text: grant.description.slice(0, 240) }));
  }

  const actions = h("div", { class: "row", style: "margin-top:.6rem" });
  if (grant.url) {
    actions.appendChild(h("a", { href: grant.url, target: "_blank", rel: "noopener noreferrer", class: "small", text: "Open source page" }));
  }
  actions.appendChild(h("button", { class: "small", text: "Approve", onClick: async () => {
    try {
      await api("/api/nonprofits/" + np.id + "/matches/" + match.id + "/approve", { method: "POST" });
      flash("ok", "Approved. Generate drafts from the Drafts tab.");
      render();
    } catch (e) { showError(e); }
  } }));
  actions.appendChild(h("button", { class: "small secondary", text: "Reject", onClick: async () => {
    try {
      await api("/api/nonprofits/" + np.id + "/matches/" + match.id + "/reject", { method: "POST" });
      flash("ok", "Rejected.");
      render();
    } catch (e) { showError(e); }
  } }));
  row.appendChild(actions);
  return row;
}

function renderSoul(node, np) {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", { text: "Inner Court" }));
  card.appendChild(h("p", { class: "muted small", text: "Your organization's private profile: mission, populations, focus areas, past grants and boilerplate. Stored encrypted; secrets are never returned by the API." }));
  node.appendChild(card);

  const form = h("div", { class: "card" });
  const area = h("textarea", { spellcheck: "false", placeholder: "nonprofit:\n  name: ...\n  state: WI\n..." });
  const status = h("div");
  const err = h("div", { class: "alert error", style: "display:none" });
  form.appendChild(err);
  form.appendChild(h("div", { class: "field" }, [h("label", { text: "soul.md content" }), area]));
  form.appendChild(h("div", { class: "row", style: "margin-top:.75rem" }, [
    h("button", { text: "Validate", onClick: async () => {
      err.style.display = "none";
      try {
        const result = await api("/api/soul/validate", { method: "POST", body: { content: area.value } });
        clear(status);
        if (!result.valid) {
          status.appendChild(h("div", { class: "alert error", text: (result.errors || []).join("; ") }));
        } else {
          status.appendChild(h("div", { class: "alert ok", text: "Valid." }));
          for (const w of result.warnings || []) status.appendChild(h("div", { class: "alert warn", text: w }));
        }
      } catch (e) { err.textContent = e.message; err.style.display = "block"; }
    } }),
    h("button", { text: "Save soul", disabled: !isAdmin() && np.role === "viewer", onClick: async () => {
      err.style.display = "none";
      try {
        await api("/api/nonprofits/" + np.id + "/soul", { method: "PUT", body: { content: area.value } });
        flash("ok", "Soul saved.");
        render();
      } catch (e) { err.textContent = e.message; err.style.display = "block"; }
    } }),
  ]));
  form.appendChild(status);
  if (np.role === "viewer") {
    form.appendChild(h("p", { class: "small muted", text: "Your role is viewer, so you can read the soul but not change it." }));
  }
  node.appendChild(form);

  api("/api/nonprofits/" + np.id + "/soul").then((soul) => {
    clear(status);
    const summary = h("div");
    summary.appendChild(h("h3", { text: soul.nonprofit.name || "(unnamed)" }));
    summary.appendChild(h("div", { class: "small muted", text: "State: " + (soul.location.state || "—") }));
    summary.appendChild(h("div", { class: "small muted", text: "Secrets configured: " + ((soul.secrets_configured || []).join(", ") || "none") }));
    node.insertBefore(summary, form);
  }).catch((err) => {
    if (err.status !== 404) return;
    const empty = h("div", { class: "card" }, [
      h("h3", { text: "No soul configured yet" }),
      h("p", { class: "muted small", text: "Paste a soul.md document below and save it to begin matching." }),
    ]);
    node.insertBefore(empty, form);
  });
}

function renderDrafts(node, np) {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", { text: "Drafts" }));
  card.appendChild(h("p", { class: "muted small", text: "Templated letters of intent, need statements and budget narratives. Every draft starts at needs-review." }));
  node.appendChild(card);

  const list = h("div", { style: "margin-top:1rem" });
  card.appendChild(list);

  api("/api/nonprofits/" + np.id + "/drafts?limit=50").then((drafts) => {
    if (!drafts.length) {
      list.appendChild(h("p", { class: "muted", text: "No drafts yet. Approve a match, then generate from the Inbox." }));
      return;
    }
    for (const draft of drafts) {
      const row = h("div", { class: "card" });
      row.appendChild(h("div", { class: "spread" }, [
        h("h3", { text: draft.title || draft.kind }),
        h("span", { class: "badge", text: draft.status }),
      ]));
      row.appendChild(h("pre", { class: "small", style: "white-space:pre-wrap;max-height:260px;overflow:auto", text: draft.body }));
      if (draft.missing_inputs && draft.missing_inputs.length) {
        row.appendChild(h("div", { class: "alert warn", text: "Missing inputs: " + draft.missing_inputs.join(", ") }));
      }
      list.appendChild(row);
    }
  }).catch(showError);
}

function renderActivity(node, np) {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", { text: "Activity" }));
  card.appendChild(h("p", { class: "muted small", text: "Usage against your plan, and the audit trail for this organization." }));
  node.appendChild(card);

  const usage = h("div", { class: "grid cols-3", style: "margin-top:1rem" });
  card.appendChild(usage);
  api("/api/nonprofits/" + np.id + "/usage").then((data) => {
    clear(usage);
    usage.appendChild(statBlock("Hunts today (" + data.plan_key + ")", data.hunts_today.used + " / " + data.hunts_today.limit));
    usage.appendChild(statBlock("Drafts this month", data.drafts_this_month.used + " / " + data.drafts_this_month.limit));
    usage.appendChild(statBlock("Plan", data.plan_key));
  }).catch(showError);

  const auditCard = h("div", { class: "card" });
  auditCard.appendChild(h("h3", { text: "Audit trail" }));
  const auditList = h("div");
  auditCard.appendChild(auditList);
  node.appendChild(auditCard);

  if (!isAdmin()) {
    auditList.appendChild(h("p", { class: "muted small", text: "Only admins can read the audit trail." }));
    return;
  }
  api("/api/nonprofits/" + np.id + "/audit?limit=100").then((events) => {
    if (!events.length) { auditList.appendChild(h("p", { class: "muted small", text: "No audit events yet." })); return; }
    const table = h("table");
    table.appendChild(h("thead", {}, h("tr", {}, [
      h("th", { text: "When" }), h("th", { text: "Action" }), h("th", { text: "Actor" }), h("th", { text: "Outcome" }),
    ])));
    const tbody = h("tbody");
    for (const ev of events) {
      tbody.appendChild(h("tr", {}, [
        h("td", { class: "small", text: (ev.created_at || "").replace("T", " ").slice(0, 19) }),
        h("td", { class: "small mono", text: ev.action }),
        h("td", { class: "small", text: ev.actor_email || "—" }),
        h("td", {}, h("span", { class: "badge " + (ev.outcome === "success" ? "green" : "red"), text: ev.outcome })),
      ]));
    }
    table.appendChild(tbody);
    auditList.appendChild(table);
  }).catch(showError);
}

function renderBilling(node, np) {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", { text: "Billing" }));
  const body = h("div");
  card.appendChild(body);
  node.appendChild(card);

  api("/api/billing/" + np.id + "/subscription").then((data) => {
    body.appendChild(h("div", { class: "grid cols-2" }, [
      h("div", {}, [
        h("div", { class: "stat", text: data.plan.name }),
        h("div", { class: "muted small", text: data.plan.price_usd_year ? "$" + data.plan.price_usd_year + " / year" : "Free" }),
      ]),
      h("div", {}, [
        h("div", { class: "small muted", text: "Status: " + data.status }),
        data.current_period_end ? h("div", { class: "small muted", text: "Renews: " + data.current_period_end.slice(0, 10) }) : null,
      ]),
    ]));

    if (!data.billing_configured) {
      body.appendChild(h("div", { class: "alert warn", text: "Billing is not configured on this deployment, so upgrades are unavailable." }));
    }

    const plans = h("div", { class: "grid cols-2", style: "margin-top:1rem" });
    for (const key of ["turnkey", "growth", "enterprise"]) {
      const box = h("div", { class: "card" });
      box.appendChild(h("h3", { text: key }));
      const btn = h("button", {
        text: np.role === "owner" ? "Upgrade" : "Owner only",
        disabled: np.role !== "owner" || !data.billing_configured,
        onClick: async () => {
          try {
            const res = await api("/api/billing/" + np.id + "/checkout", { method: "POST", body: { plan_key: key } });
            window.location.href = res.url;
          } catch (e) { showError(e); }
        },
      });
      box.appendChild(btn);
      plans.appendChild(box);
    }
    body.appendChild(plans);

    if (np.role === "owner") {
      body.appendChild(h("button", {
        class: "secondary", style: "margin-top:1rem", text: "Manage payment method",
        disabled: !data.billing_configured,
        onClick: async () => {
          try {
            const res = await api("/api/billing/" + np.id + "/portal", { method: "POST", body: {} });
            window.location.href = res.url;
          } catch (e) { showError(e); }
        },
      }));
    }
  }).catch(showError);
}

function renderTeam(node, np) {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", { text: "Team" }));
  card.appendChild(h("p", { class: "muted small", text: "People with access to this organization. Roles: viewer, member, admin, owner." }));
  node.appendChild(card);

  const list = h("div", { style: "margin-top:1rem" });
  card.appendChild(list);

  api("/api/nonprofits/" + np.id + "/members").then((members) => {
    const table = h("table");
    table.appendChild(h("thead", {}, h("tr", {}, [
      h("th", { text: "Member" }), h("th", { text: "Role" }), h("th", { text: "" }),
    ])));
    const tbody = h("tbody");
    for (const member of members) {
      const actions = h("td");
      if (isAdmin() && member.user_id !== state.user.id) {
        const select = h("select", { onChange: async (e) => {
          try {
            await api("/api/nonprofits/" + np.id + "/members/" + member.user_id, {
              method: "PATCH", body: { role: e.target.value },
            });
            flash("ok", "Role updated.");
            render();
          } catch (ex) { showError(ex); }
        } });
        for (const role of ["viewer", "member", "admin", "owner"]) {
          select.appendChild(h("option", { value: role, text: role, selected: role === member.role }));
        }
        actions.appendChild(select);
        actions.appendChild(h("button", { class: "small danger", text: "Remove", onClick: async () => {
          try {
            await api("/api/nonprofits/" + np.id + "/members/" + member.user_id, { method: "DELETE" });
            flash("ok", "Member removed.");
            render();
          } catch (ex) { showError(ex); }
        } }));
      }
      tbody.appendChild(h("tr", {}, [
        h("td", {}, [h("div", { text: member.full_name || member.email }), h("div", { class: "small muted", text: member.email })]),
        h("td", {}, h("span", { class: "badge", text: member.role })),
        actions,
      ]));
    }
    table.appendChild(tbody);
    list.appendChild(table);
  }).catch(showError);

  if (isAdmin()) {
    const email = h("input", { type: "email", required: true });
    const role = h("select");
    for (const r of ["viewer", "member", "admin"]) role.appendChild(h("option", { value: r, text: r }));
    const err = h("div", { class: "alert error", style: "display:none" });
    const inviteCard = h("div", { class: "card" }, [
      h("h3", { text: "Invite someone" }),
      err,
      h("div", { class: "field" }, [h("label", { text: "Email" }), email]),
      h("div", { class: "field" }, [h("label", { text: "Role" }), role]),
      h("button", { text: "Send invite", style: "margin-top:.75rem", onClick: async () => {
        err.style.display = "none";
        try {
          await api("/api/nonprofits/" + np.id + "/members", { method: "POST", body: { email: email.value.trim(), role: role.value } });
          flash("ok", "Invitation sent.");
          render();
        } catch (e) { err.textContent = e.message; err.style.display = "block"; }
      } }),
    ]);
    node.appendChild(inviteCard);
  }
}

/* --- router / bootstrap --------------------------------------------------- */

function render() {
  const root = document.getElementById("root");
  clear(root);

  const path = window.location.pathname;
  if (path === "/reset-password") { root.appendChild(promptReset()); return; }
  if (path === "/verify-email") { root.appendChild(promptVerify()); return; }

  if (!state.user) { root.appendChild(authView()); return; }
  root.appendChild(shellView());
}

async function boot() {
  try {
    const data = await api("/api/auth/me");
    state.user = data.user;
    state.nonprofits = data.nonprofits || [];
    state.activeId = state.nonprofits.length ? state.nonprofits[0].id : null;
  } catch (e) {
    // 401 is the expected anonymous case, not an error worth surfacing.
  }
  render();
}

window.addEventListener("popstate", render);
document.addEventListener("DOMContentLoaded", boot);

if (document.readyState !== "loading") boot();