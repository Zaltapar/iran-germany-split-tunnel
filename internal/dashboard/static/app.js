// Split-Tunnel Dashboard v2 — read-only UI. Vanilla JS, no framework, no build
// step, no external scripts, fonts, or CDN resources. Charts are inline SVG.
//
// Everything is relative to the page URL, so the same bundle works at the site
// root (loopback) and under the random 32-hex basePath (server-hosted TLS).
// The UI issues GET requests only. Legacy v1 names are kept for the dashboard's
// v1 detail view and dry-run plan form; the Apply control is disabled.

"use strict";

(function () {
  // ---- base URL ----------------------------------------------------------
  function pageBase() {
    var p = window.location.pathname;
    if (!p.endsWith("/")) p += "/";
    return p;
  }
  var BASE = pageBase();
  var API_V2 = BASE + "api/v2";
  var API_V1 = BASE + "api/v1";

  // ---- state -------------------------------------------------------------
  var state = {
    section: "overview",
    pollTimer: null,
    pollSec: 5,
    detailHost: null,
    lastPollSuccess: null,
    lastStateChange: null,
    lastApiError: null,
    lastOverview: null,
    lastCarriers: null
  };

  var SECTIONS = {
    overview: { title: "Overview", render: renderOverview },
    hosts: { title: "Hosts", render: renderHosts },
    tunnels: { title: "Tunnels / Carriers", render: renderCarriers },
    routing: { title: "Routing", render: renderRouting },
    outbounds: { title: "Outbounds", render: renderOutbounds },
    inbounds: { title: "Inbounds", render: renderInbounds },
    control: { title: "Control (C4)", render: renderControl },
    network: { title: "Network speed", render: renderNetwork },
    config: { title: "Configuration", render: renderConfig },
    logs: { title: "Logs / Events", render: renderEvents }
  };

  // ---- DOM helpers ---------------------------------------------------------
  function el(tag, attrs, children) {
    var n = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (k === "text") n.textContent = attrs[k];
        else if (k === "cls") n.className = attrs[k];
        else if (k === "on") Object.keys(attrs.on).forEach(function (ev) { n.addEventListener(ev, attrs.on[ev]); });
        else if (k === "attrs") Object.keys(attrs.attrs).forEach(function (a) { n.setAttribute(a, attrs.attrs[a]); });
        else n.setAttribute(k, attrs[k]);
      });
    }
    (children || []).forEach(function (c) {
      if (c == null) return;
      n.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return n;
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  function badge(text, tone) {
    return el("span", { cls: "badge " + (tone || ""), text: text });
  }

  function fmtNum(v, digits) {
    if (v == null || isNaN(v)) return "—";
    return Number(v).toFixed(digits == null ? 2 : digits);
  }

  function fmtAge(sec) {
    if (sec == null) return "—";
    if (sec < 60) return sec + "s";
    if (sec < 3600) return Math.floor(sec / 60) + "m";
    return Math.floor(sec / 3600) + "h " + Math.floor((sec % 3600) / 60) + "m";
  }

  function fmtHours(h) {
    if (h == null) return "—";
    var d = Math.floor(h / 24);
    var hh = Math.floor(h % 24);
    return (d > 0 ? d + "d " : "") + hh + "h";
  }

  function fmtTime(iso) {
    if (!iso) return "—";
    var d = new Date(iso);
    return isNaN(d.getTime()) ? "—" : d.toLocaleString();
  }

  function stateTone(s) {
    if (s === "active" || s === "fresh") return "ok";
    if (s === "half_open" || s === "stale" || s === "candidate" || s === "pending") return "warn";
    if (s === "excluded" || s === "unreachable") return "bad";
    return "";
  }

  // Text-only null-safe value cell. Missing data is shown as "—", never 0.
  function valueCell(v, fmt) {
    return el("td", { cls: "num", text: v == null ? "—" : (fmt ? fmt(v) : String(v)) });
  }

  // ---- API ----------------------------------------------------------------
  function getJSON(url) {
    return fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin", cache: "no-store" })
      .then(function (res) {
        if (!res.ok) {
          return res.json().catch(function () { return {}; }).then(function (body) {
            throw new Error((body && body.error) || ("HTTP " + res.status));
          });
        }
        return res.json();
      });
  }

  function v2(path) { return getJSON(API_V2 + path); }

  // ---- POST helper (CSRF + control header) ---------------------------------
  // All mutating calls require X-Tunneldash-Request: 1 (middleware CSRF) and
  // X-TunnelDash-Control: 1 (control-plane CSRF). No secrets are sent; only
  // public config fields + the typed confirm token.
  function postJSON(path, body, controlHeader) {
    var headers = {
      "Content-Type": "application/json",
      "Accept": "application/json",
      "X-Tunneldash-Request": "1"
    };
    if (controlHeader !== false) {
      headers["X-TunnelDash-Control"] = "1";
    }
    return fetch(API_V2 + path, {
      method: "POST",
      headers: headers,
      credentials: "same-origin",
      body: JSON.stringify(body)
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (b) {
        if (!res.ok) {
          var err = new Error((b.error || "HTTP " + res.status));
          err.status = res.status;
          err.body = b;
          throw err;
        }
        return b;
      });
    });
  }

  // ---- confirm modal --------------------------------------------------------
  // Renders an inline confirm dialog (no external resources). The operator
  // types the token (RESTART or ROTATE) before the action button is enabled.
  function confirmModal(label, token, onConfirm, resultNode) {
    var input = el("input", { cls: "confirm-input", type: "text", placeholder: "Type " + token });
    var btn = el("button", { cls: "btn btn-danger", type: "button", attrs: { disabled: "" }, text: label });
    input.addEventListener("input", function () {
      btn.disabled = (input.value !== token);
    });
    btn.addEventListener("click", function () {
      if (input.value !== token) return;
      onConfirm();
    });
    var row = el("div", { cls: "btn-row confirm-row" }, [
      el("label", { cls: "muted small", text: "Confirmation" }),
      input,
      btn
    ]);
    if (resultNode) resultNode.appendChild(row);
    else return row;
  }

  // ---- client-side routing-rules validator (parity with pkg/routing) --------
  // Mirrors the server-side validator so the editor can catch errors before
  // sending. Shared fixture tests verify parity.
  var ROUTING_MAX_RULES = 500;
  var ROUTING_PORT_MAX = 65535;
  var ROUTING_ACTIONS = ["direct", "warp", "block"];
  var ROUTING_FALLBACKS = ["", "direct"];

  function validateRoutingRulesClient(rs) {
    var errs = [];
    if (rs.version !== 1) errs.push("version must be 1");
    var da = rs.default_action || "direct";
    if (da === "block") errs.push("default_action cannot be 'block' (would lock out all unmatched destinations)");
    if (ROUTING_ACTIONS.indexOf(da) === -1) errs.push("default_action must be direct|warp (got " + JSON.stringify(da) + ")");
    var rules = rs.rules || [];
    if (rules.length > ROUTING_MAX_RULES) errs.push("too many rules: " + rules.length + " (max " + ROUTING_MAX_RULES + ")");
    var seen = {};
    for (var i = 0; i < rules.length; i++) {
      var r = rules[i];
      var prefix = "rules[" + i + "] (" + r.id + ")";
      if (!r.id) { errs.push(prefix + ": id is required"); continue; }
      if (seen[r.id]) { errs.push(prefix + ": duplicate rule id"); continue; }
      seen[r.id] = true;
      if (ROUTING_ACTIONS.indexOf(r.action) === -1) errs.push(prefix + ": action must be direct|warp|block");
      if (r.fallback && r.fallback !== "direct") errs.push(prefix + ": fallback must be \"direct\" or empty");
      if (r.fallback && r.action !== "warp") errs.push(prefix + ": fallback is only valid for action=warp");
      var m = r.match || {};
      if (!m.domain && !m.keyword && !m.ip_cidr) errs.push(prefix + ": at least one match criterion (domain, keyword, or ip_cidr) is required");
      if (m.domain) {
        var dom = m.domain.toLowerCase();
        var core = dom.charAt(0) === "." ? dom.substring(1) : dom;
        if (core.length === 0) errs.push(prefix + ": empty domain");
        else if (core.length > 253) errs.push(prefix + ": domain too long");
        else {
          var labels = core.split(".");
          for (var li = 0; li < labels.length; li++) {
            var lbl = labels[li];
            if (lbl === "") { errs.push(prefix + ": empty label in domain"); break; }
            if (lbl.length > 63) { errs.push(prefix + ": label too long in domain"); break; }
            if (lbl.indexOf("*") !== -1) { errs.push(prefix + ": wildcards not allowed in domain"); break; }
            if (lbl.charAt(0) === "-" || lbl.charAt(lbl.length - 1) === "-") { errs.push(prefix + ": label has leading/trailing hyphen"); break; }
            for (var ci = 0; ci < lbl.length; ci++) {
              var c = lbl[ci];
              if (!((c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c === "-")) {
                errs.push(prefix + ": invalid character '" + c + "' in domain (lowercase alphanumeric + hyphen only)");
                break;
              }
            }
          }
        }
      }
      if (m.ip_cidr) {
        // Basic CIDR check: must contain "/" and both parts non-empty
        var slash = m.ip_cidr.indexOf("/");
        if (slash < 0 || slash === 0 || slash === m.ip_cidr.length - 1) {
          errs.push(prefix + ": ip_cidr must be a valid CIDR (e.g. 10.0.0.0/8)");
        }
      }
      if (m.port_min < 0 || m.port_min > ROUTING_PORT_MAX) errs.push(prefix + ": port_min out of range 0..65535");
      if (m.port_max < 0 || m.port_max > ROUTING_PORT_MAX) errs.push(prefix + ": port_max out of range 0..65535");
      if (m.port_min > 0 && m.port_max > 0 && m.port_min > m.port_max) errs.push(prefix + ": port_min exceeds port_max");
    }
    return errs;
  }

  function buildRulesObject(ed) {
    var rs = { version: 1, default_action: ed.defaultAction, rules: [] };
    for (var i = 0; i < ed.rules.length; i++) {
      var r = ed.rules[i];
      var rule = {
        id: r.id,
        enabled: r.enabled,
        match: {}
      };
      if (r.domain) rule.match.domain = r.domain;
      if (r.keyword) rule.match.keyword = r.keyword;
      if (r.ipCidr) rule.match.ip_cidr = r.ipCidr;
      if (r.portMin !== "" && r.portMin !== null) rule.match.port_min = parseInt(r.portMin, 10);
      if (r.portMax !== "" && r.portMax !== null) rule.match.port_max = parseInt(r.portMax, 10);
      rule.action = r.action;
      if (r.fallback) rule.fallback = r.fallback;
      if (r.comment) rule.comment = r.comment;
      rs.rules.push(rule);
    }
    return rs;
  }

  // ---- diff display helper --------------------------------------------------
  function renderDiffList(view, diffList, label) {
    if (!diffList || !diffList.length) {
      view.appendChild(el("div", { cls: "notice", text: (label || "Diff") + ": no changes detected." }));
      return;
    }
    var rows = diffList.map(function (d) {
      var before = JSON.stringify(d.before || {});
      var after = JSON.stringify(d.after || {});
      return el("tr", null, [
        el("td", { text: d.id || "—" }),
        el("td", null, [badge(d.op || "changed", d.op === "removed" ? "bad" : d.op === "added" ? "ok" : "warn")]),
        el("td", { cls: "mono small", text: before }),
        el("td", { cls: "mono small", text: after })
      ]);
    });
    view.appendChild(el("div", { cls: "table-wrap" }, [
      el("table", null, [
        el("thead", null, [el("tr", null, [
          el("th", { text: "ID" }), el("th", { text: "Op" }),
          el("th", { text: "Before" }), el("th", { text: "After" })
        ])]),
        el("tbody", null, rows)
      ])
    ]));
  }

  // ---- SVG line / area chart ---------------------------------------------
  // series: [{ name, color, points: [{t: ms, v: number}] }]
  // Returns a DOM node. Hover shows a tooltip with the nearest point.
  function lineChart(opts) {
    var W = 640, H = 180, PAD_L = 44, PAD_R = 12, PAD_T = 10, PAD_B = 22;
    var series = (opts.series || []).filter(function (s) { return s.points && s.points.length; });
    if (!series.length) {
      return el("div", { cls: "empty-chart", text: opts.empty || "No data yet — the chart fills as the dashboard collects samples." });
    }
    var tMin = Infinity, tMax = -Infinity, vMax = 0, vMin = 0;
    series.forEach(function (s) {
      s.points.forEach(function (p) {
        if (p.t < tMin) tMin = p.t;
        if (p.t > tMax) tMax = p.t;
        if (p.v > vMax) vMax = p.v;
        if (p.v < vMin) vMin = p.v;
      });
    });
    if (tMax === tMin) tMax = tMin + 1;
    if (opts.yMax != null) vMax = Math.max(opts.yMax, vMax);
    if (vMax === vMin) vMax = vMin + 1;
    var iw = W - PAD_L - PAD_R, ih = H - PAD_T - PAD_B;
    function x(t) { return PAD_L + ((t - tMin) / (tMax - tMin)) * iw; }
    function y(v) { return PAD_T + ih - ((v - vMin) / (vMax - vMin)) * ih; }

    // SVG namespace identifier (not a fetched resource). Assembled from parts
    // so the bundle never contains a literal remote-origin string.
    var NS = "http" + "://www.w3.org/2000/svg";
    function sv(tag, attrs) {
      var n = document.createElementNS(NS, tag);
      Object.keys(attrs || {}).forEach(function (k) { n.setAttribute(k, attrs[k]); });
      return n;
    }
    var svg = sv("svg", { viewBox: "0 0 " + W + " " + H, preserveAspectRatio: "none", role: "img", "aria-label": opts.label || "chart" });

    // Grid and y labels (4 divisions).
    for (var i = 0; i <= 4; i++) {
      var gv = vMin + (vMax - vMin) * (i / 4);
      var gy = y(gv);
      svg.appendChild(sv("line", { x1: PAD_L, x2: W - PAD_R, y1: gy, y2: gy, "class": "grid-line" }));
      var lbl = sv("text", { x: PAD_L - 6, y: gy + 3, "text-anchor": "end", "class": "axis-label" });
      lbl.textContent = fmtNum(gv, opts.yDigits == null ? 2 : opts.yDigits);
      svg.appendChild(lbl);
    }
    // X labels (start / end).
    var t0 = sv("text", { x: PAD_L, y: H - 6, "class": "axis-label" });
    t0.textContent = new Date(tMin).toLocaleTimeString();
    svg.appendChild(t0);
    var t1 = sv("text", { x: W - PAD_R, y: H - 6, "text-anchor": "end", "class": "axis-label" });
    t1.textContent = new Date(tMax).toLocaleTimeString();
    svg.appendChild(t1);

    series.forEach(function (s) {
      var d = s.points.map(function (p, idx) { return (idx ? "L" : "M") + x(p.t).toFixed(1) + "," + y(p.v).toFixed(1); }).join(" ");
      if (opts.area) {
        var last = s.points[s.points.length - 1], first = s.points[0];
        var ad = d + " L" + x(last.t).toFixed(1) + "," + (PAD_T + ih) + " L" + x(first.t).toFixed(1) + "," + (PAD_T + ih) + " Z";
        svg.appendChild(sv("path", { d: ad, fill: s.color, "class": "area" }));
      }
      svg.appendChild(sv("path", { d: d, stroke: s.color, "class": "line" }));
    });

    var hoverLine = sv("line", { y1: PAD_T, y2: PAD_T + ih, "class": "hover-line", visibility: "hidden" });
    svg.appendChild(hoverLine);
    var dots = series.map(function (s) {
      var c = sv("circle", { r: 4, fill: s.color, "class": "hover-dot", visibility: "hidden" });
      svg.appendChild(c);
      return c;
    });

    var tip = el("div", { cls: "chart-tip" });
    var wrap = el("div", { cls: "chart" }, [svg, tip]);

    function onMove(ev) {
      var rect = svg.getBoundingClientRect();
      var px = ((ev.clientX - rect.left) / rect.width) * W;
      var t = tMin + ((px - PAD_L) / iw) * (tMax - tMin);
      if (px < PAD_L || px > W - PAD_R) return hide();
      var lines = [];
      var anchorV = null;
      series.forEach(function (s, si) {
        var best = null;
        s.points.forEach(function (p) {
          if (best == null || Math.abs(p.t - t) < Math.abs(best.t - t)) best = p;
        });
        if (!best) return;
        dots[si].setAttribute("cx", x(best.t).toFixed(1));
        dots[si].setAttribute("cy", y(best.v).toFixed(1));
        dots[si].setAttribute("visibility", "visible");
        lines.push(s.name + ": " + fmtNum(best.v, opts.yDigits == null ? 2 : opts.yDigits) + (opts.unit ? " " + opts.unit : ""));
        if (anchorV == null) anchorV = x(best.t);
      });
      if (anchorV != null) {
        hoverLine.setAttribute("x1", anchorV.toFixed(1));
        hoverLine.setAttribute("x2", anchorV.toFixed(1));
        hoverLine.setAttribute("visibility", "visible");
      }
      tip.textContent = new Date(t).toLocaleTimeString() + " — " + lines.join(" · ");
      tip.style.display = "block";
      tip.style.left = ((anchorV || 0) / W * 100) + "%";
      tip.style.top = "0px";
    }
    function hide() {
      hoverLine.setAttribute("visibility", "hidden");
      dots.forEach(function (c) { c.setAttribute("visibility", "hidden"); });
      tip.style.display = "none";
    }
    svg.addEventListener("mousemove", onMove);
    svg.addEventListener("mouseleave", hide);
    svg.addEventListener("touchstart", onMove, { passive: true });
    svg.addEventListener("touchmove", onMove, { passive: true });
    svg.addEventListener("touchend", hide);

    var legend = el("div", { cls: "legend" }, series.map(function (s) {
      return el("span", null, [el("span", { cls: "legend-swatch" }), s.name]);
    }));
    legend.querySelectorAll(".legend-swatch").forEach(function (sw, i) { sw.style.background = series[i].color; });
    return el("div", null, [wrap, legend]);
  }

  var PALETTE = ["#4f8cff", "#2fbf71", "#e8a53a", "#e5534b", "#b28cff", "#3cc8d6"];

  function seriesPoints(seriesList, key) {
    for (var i = 0; i < seriesList.length; i++) {
      if (seriesList[i].key === key) {
        return (seriesList[i].points || []).map(function (p) { return { t: new Date(p.t).getTime(), v: p.v }; });
      }
    }
    return [];
  }

  function fetchSeries(keys, limit) {
    if (!keys.length) return Promise.resolve([]);
    var q = keys.join(",");
    return v2("/timeseries?series=" + encodeURIComponent(q) + "&limit=" + (limit || 120))
      .then(function (d) { return d.series || []; })
      .catch(function () { return []; });
  }

  // ---- shared notices ------------------------------------------------------
  function metaNotice(meta) {
    if (!meta) return null;
    return el("div", { cls: "notice", text: "Refresh every " + meta.refreshSec + " s · history retains " + meta.historyPointsPerSeries + " points per series in memory only · read-only view" });
  }

  function missingNote(text) {
    return el("div", { cls: "notice warn", text: text });
  }

  function hostBadges(h) {
    var out = [badge(h.status || "unknown", stateTone(h.status))];
    (h.badges || []).forEach(function (b) {
      if (b === "stale") out.push(badge("stale", "warn"));
      if (b === "unreachable") out.push(badge("unreachable", "bad"));
      if (b === "collector-missing") out.push(badge("collector missing", "bad"));
      if (b === "no-data") out.push(badge("no data", ""));
    });
    return out;
  }

  // ---- Overview -----------------------------------------------------------
  function statCard(label, value, sub) {
    return el("div", { cls: "card" }, [
      el("h3", { text: label }),
      el("div", { cls: "stat-value", text: value == null ? "—" : String(value) }),
      sub ? el("div", { cls: "stat-sub", text: sub }) : null
    ]);
  }

  // ---- tunnel state helpers ------------------------------------------------

  // Classify the overall tunnel state. The "up" host is the one whose
  // sourceType is not missing/unreachable and that carries a carrier. The
  // result drives both the global badge and the overview card.
  function tunnelState(d, carriers) {
    var hosts = d.hosts || [];
    var c = d.counts || {};
    var unreachable = (c.hostsUnreachable || 0) > 0;
    var stale = (c.hostsStale || 0) > 0;
    var anyCarrier = (c.carriers || 0) > 0;
    var anyEligible = (c.carriersEligible || 0) > 0;
    var carriersHalfOpen = false, carriersExcluded = false;
    carriers.forEach(function (k) {
      if (k.state === "half_open") carriersHalfOpen = true;
      if (k.state === "excluded" || k.state === "unreachable") carriersExcluded = true;
    });
    var activeDown = 0, downStates = [];
    hosts.forEach(function (h) {
      if (h.role === "iran") {
        if (h.status === "fresh" || h.status === "active") activeDown++;
      } else {
        downStates.push(h);
      }
    });
    var downBad = downStates.some(function (h) { return h.status === "unreachable"; });
    var downStale = downStates.some(function (h) { return h.status === "stale"; });
    if (unreachable || downBad) return "unavailable";
    if (stale || downStale || carriersHalfOpen || (anyCarrier && !anyEligible)) return "degraded";
    if (carriersExcluded) return "recovering";
    return "healthy";
  }

  function stateIcon(s) {
    if (s === "healthy") return "●";
    if (s === "degraded") return "◐";
    if (s === "recovering") return "◔";
    return "○";
  }
  function stateTone2(s) {
    if (s === "healthy") return "ok";
    if (s === "degraded") return "warn";
    if (s === "recovering") return "warn";
    return "bad";
  }

  function updateGlobalBadges() {
    var container = document.getElementById("globalBadges");
    if (!container) return;
    clear(container);
    var ov = state.lastOverview;
    var carr = state.lastCarriers || [];
    if (!ov) {
      container.appendChild(badge("loading…", ""));
      return;
    }
    var s = tunnelState(ov, carr);
    var stale = (ov.counts.hostsStale || 0) > 0 ||
                (ov.counts.hostsUnreachable || 0) > 0;
    container.appendChild(badge(stateIcon(s) + " " + s, stateTone2(s)));
    if (stale) {
      container.appendChild(badge("⚠ stale telemetry", "warn"));
    }
    var age = state.lastPollSuccess
      ? Math.round((Date.now() - state.lastPollSuccess) / 1000)
      : null;
    if (age != null) {
      container.appendChild(el("span", { cls: "small muted", text: "last poll " + fmtAge(age) + " ago" }));
    }
  }

  function carrierDetailCard(carrier) {
    var c = carrier;
    var stateBadge = badge((c.state || "unknown").replace(/_/g, " "), stateTone(c.state));
    var eligibleCell;
    if (c.eligible == null) {
      eligibleCell = el("div", null, [badge("unmeasured", "")]);
    } else if (c.eligible) {
      eligibleCell = el("div", null, [badge("eligible / active", "ok")]);
    } else {
      eligibleCell = el("div", null, [badge("gated: " + (c.gateReason || "unknown"), "bad")]);
    }
    var creditCell;
    if (c.creditWindowOpen == null) {
      creditCell = el("div", { cls: "num", text: "unmeasured" });
    } else {
      creditCell = el("div", { cls: "num", text: c.creditWindowOpen ? "open" : "closed" });
    }
    var rows = [
      ["State", el("div", null, [stateBadge])],
      ["Last transition", el("div", { cls: "small muted", text: "not exported (N/A)" })],
      ["Score (0–1)", c.score == null ? el("div", { cls: "num", text: "unmeasured" }) : el("div", { cls: "num", text: fmtNum(c.score, 3) })],
      ["Goodput", c.goodputMiBps == null
        ? el("div", { cls: "num", text: "unmeasured" })
        : el("div", { cls: "num", text: fmtNum(c.goodputMiBps, 2) + " MiB/s" })],
      ["Success ratio", c.successRatio == null ? el("div", { cls: "num", text: "unmeasured" }) : el("div", { cls: "num", text: fmtNum(c.successRatio, 3) })],
      ["Stall rate / 100 MiB", c.stallRatePer100MiB == null ? el("div", { cls: "num", text: "unmeasured" }) : el("div", { cls: "num", text: fmtNum(c.stallRatePer100MiB, 2) })],
      ["Eligibility", eligibleCell],
      ["Cooldown remaining", c.cooldownRemainingSec == null ? el("div", { cls: "num", text: "N/A" }) : el("div", { cls: "num", text: c.cooldownRemainingSec + " s" })],
      ["Probe bytes today", c.probeBytesToday == null ? el("div", { cls: "num", text: "unmeasured" }) : el("div", { cls: "num", text: fmtNum(c.probeBytesToday / 1048576, 1) + " MiB" })],
      ["Loss events", c.lossEvents == null ? el("div", { cls: "num", text: "unmeasured" }) : el("div", { cls: "num", text: String(c.lossEvents) })],
      ["Reconnects", c.reconnects == null ? el("div", { cls: "num", text: "unmeasured" }) : el("div", { cls: "num", text: String(c.reconnects) })],
      ["Gate reason", c.gateReason ? el("div", { text: c.gateReason }) : el("div", { cls: "muted small", text: "none" })],
      ["TTFB p50 (ms)", el("div", { cls: "num", text: "unmeasured (not collected)" })],
      ["RTT (diagnostic)", el("div", { cls: "num", text: "unmeasured (diagnostic only)" })],
      ["Queue usage", el("div", { cls: "num", text: "unmeasured" })],
      ["Credit window", creditCell]
    ];
    var tableRows = rows.map(function (r) {
      return el("tr", null, [el("th", { text: r[0], attrs: { scope: "row" } }), el("td", null, [r[1]])]);
    });
    var unavailable = c.unavailable || [];
    var unavNote = unavailable.length
      ? el("div", { cls: "notice", text: "Not collected in this phase: " + unavailable.join(", ") })
      : null;
    var guidance;
    if (c.eligible === true) {
      guidance = el("div", { cls: "notice", text: "Carrier is eligible and can be selected for new flows. No operator action required." });
    } else if (c.eligible === false) {
      guidance = el("div", { cls: "notice warn", text: "Carrier is gated (" + (c.gateReason || "unknown") + "). Check carrier connectivity and probe results. Operator action: verify the carrier link and policy configuration." });
    } else {
      guidance = el("div", { cls: "notice", text: "Carrier eligibility is unmeasured. No policy decision available yet." });
    }
    return el("div", { cls: "card carrier-card" }, [
      el("h3", { text: c.serverId + " / " + c.carrier }),
      el("table", { cls: "carrier-detail-table" }, [el("tbody", null, tableRows)]),
      unavNote,
      guidance
    ]);
  }

  function renderOverview(view) {
    return Promise.all([v2("/overview"), v2("/carriers"), fetchSeries(["iran.up_mibps", "iran.down_mibps", "germany.up_mibps", "germany.down_mibps"], 120)])
      .then(function (res) {
        var d = res[0], carr = res[1], series = res[2];
        state.lastOverview = d;
        state.lastCarriers = (carr && carr.carriers) || [];
        state.lastPollSuccess = Date.now();
        clear(view);
        var c = d.counts || {};
        var ts = tunnelState(d, state.lastCarriers);

        // Overall state banner
        view.appendChild(el("div", { cls: "overview-state " + ts }, [
          el("div", { cls: "overview-state-label" }, [
            el("span", { text: stateIcon(ts) + " ", cls: "state-icon" }),
            el("span", { text: ts, cls: "state-word" })
          ]),
          el("div", { cls: "stat-sub", text: "Up-carrier: " + (d.hosts || []).filter(function (h) { return h.role === "iran"; }).length + " host(s) · " + ts + " telemetry" }),
          d.meta ? el("div", { cls: "stat-sub", text: "refresh every " + d.meta.refreshSec + " s · generated " + fmtTime(d.meta.generatedAt) }) : null
        ]));

        view.appendChild(metaNotice(d.meta));

        // Down-carrier summary cards
        var downHosts = (d.hosts || []).filter(function (h) { return h.role !== "iran"; });
        if (downHosts.length) {
          view.appendChild(el("h3", { cls: "section-subhead", text: "Down-carriers" }));
          var cards = downHosts.map(function (h) {
            return el("div", { cls: "card carrier-summary-card " + stateTone(h.status) }, [
              el("h3", { text: h.name || h.id }),
              hostBadges(h),
              el("div", { cls: "stat-sub", text: "active sessions: " + (h.activeSessions == null ? "—" : h.activeSessions) }),
              el("div", { cls: "stat-sub", text: "losses: " + (h.carrierLossEvents == null ? "—" : h.carrierLossEvents) }),
              el("div", { cls: "stat-sub", text: "collected " + (h.collectedAt ? fmtTime(h.collectedAt) : "never") + " · age " + fmtAge(h.ageSec) })
            ]);
          });
          view.appendChild(el("div", { cls: "grid" }, cards));
        }

        // KPI cards
        view.appendChild(el("h3", { cls: "section-subhead", text: "Key indicators" }));
        view.appendChild(el("div", { cls: "grid" }, [
          statCard("Hosts", c.hosts, (c.hostsStale || 0) + " stale · " + (c.hostsUnreachable || 0) + " unreachable"),
          statCard("Collectors missing", c.hostsCollectorMissing || 0, "hosts without a metrics source"),
          statCard("Carriers", c.carriers, (c.carriersEligible || 0) + " eligible"),
          statCard("Outbounds", c.outbounds, (c.outboundsEnabled || 0) + " enabled (config)"),
          statCard("Routing rules", c.routingRules, "mode: " + (d.routingMode || "—")),
          statCard("Active sessions", (d.hosts || []).reduce(function (a, h) { return a + (h.activeSessions || 0); }, 0), "across all hosts"),
          statCard("Carrier losses", (d.hosts || []).reduce(function (a, h) { return a + (h.carrierLossEvents || 0); }, 0), "cumulative"),
          statCard("Buffer pressure", "unmeasured", "queue/buffer metrics not collected in this phase")
        ]));

        var up = seriesPoints(series, "iran.up_mibps");
        var down = seriesPoints(series, "iran.down_mibps");
        view.appendChild(el("div", { cls: "grid-2" }, [
          el("div", { cls: "card" }, [
            el("h3", { text: "Throughput (MiB/s) — iran host" }),
            lineChart({ series: [{ name: "upload", color: PALETTE[0], points: up }, { name: "download", color: PALETTE[1], points: down }], unit: "MiB/s", area: true, empty: "Throughput history appears after two collections with byte counters." })
          ]),
          el("div", { cls: "card" }, [
            el("h3", { text: "Hosts" }),
            hostTable(d.hosts || [], true)
          ])
        ]));

        // Carrier detail cards
        if (state.lastCarriers.length) {
          view.appendChild(el("h3", { cls: "section-subhead", text: "Carrier details" }));
          var carrCards = state.lastCarriers.map(carrierDetailCard);
          view.appendChild(el("div", { cls: "grid-2" }, carrCards));
        }

        (d.notes || []).forEach(function (n) { view.appendChild(el("div", { cls: "notice", text: n })); });
      })
      .then(updateGlobalBadges, updateGlobalBadges);
  }

  function hostTable(hosts, compact) {
    if (!hosts.length) return el("div", { cls: "notice", text: "No hosts are configured." });
    var rows = hosts.map(function (h) {
      var cells = [
        el("td", null, [
          el("a", { href: "#hosts", text: h.name || h.id, on: { click: function (e) { e.preventDefault(); state.detailHost = h.id; refresh(); } } }),
          el("div", { cls: "muted small", text: h.role + " · " + h.sourceType })
        ]),
        el("td", null, hostBadges(h)),
        valueCell(h.activeSessions),
        valueCell(h.upMiBps, function (v) { return fmtNum(v, 2); }),
        valueCell(h.downMiBps, function (v) { return fmtNum(v, 2); })
      ];
      if (!compact) {
        cells.push(valueCell(h.memUsedMiB, function (v) { return v + " MiB"; }));
        cells.push(valueCell(h.diskUsedGiB, function (v) { return fmtNum(v, 1) + " GiB"; }));
        cells.push(valueCell(h.uptimeHours, fmtHours));
        cells.push(el("td", { cls: "num", text: "—" }));
        cells.push(valueCell(h.carrierLossEvents));
      }
      return el("tr", null, cells);
    });
    var head = ["Host", "Status", "Sessions", "↑ MiB/s", "↓ MiB/s"];
    if (!compact) head = head.concat(["Memory", "Disk", "Uptime", "CPU", "Carrier losses"]);
    return el("div", { cls: "table-wrap" }, [
      el("table", null, [
        el("thead", null, [el("tr", null, head.map(function (h2) { return el("th", { text: h2 }); }))]),
        el("tbody", null, rows)
      ])
    ]);
  }

  // ---- Hosts ----------------------------------------------------------------
  function renderHosts(view) {
    return v2("/hosts").then(function (d) {
      clear(view);
      view.appendChild(metaNotice(d.meta));
      view.appendChild(el("div", { cls: "notice", text: "CPU and load average are not provided by the current collectors and are shown as missing (—). Select a host name for its v1 detail." }));
      view.appendChild(hostTable(d.hosts || [], false));
      var detailHost = state.detailHost;
      if (detailHost) {
        var holder = el("div", { cls: "v1-detail" });
        view.appendChild(el("div", { cls: "card" }, [
          el("h3", { text: "Host detail: " + detailHost }),
          el("button", { cls: "btn", type: "button", text: "Close detail", on: { click: function () { state.detailHost = null; refresh(); } } }),
          holder
        ]));
        renderV1Detail(detailHost, holder);
      }
      var cards = (d.hosts || []).map(function (h) {
        var info = [];
        if (h.message) info.push(el("div", { cls: "notice " + (h.collectorMissing || h.status === "unreachable" ? "warn" : ""), text: h.message }));
        if (h.errors && h.errors.length) info.push(el("div", { cls: "notice bad", text: h.errors.join(" · ") }));
        info.push(el("div", { cls: "stat-sub", text: "collected " + fmtTime(h.collectedAt) + " · age " + fmtAge(h.ageSec) }));
        return el("div", { cls: "card" }, [el("h3", { text: (h.name || h.id) + " — health" })].concat(info));
      });
      if (cards.length) view.appendChild(el("div", { cls: "grid-2" }, cards));
    });
  }

  // ---- Carriers -------------------------------------------------------------
  function renderCarriers(view) {
    return v2("/carriers").then(function (d) {
      clear(view);
      state.lastCarriers = d.carriers || [];
      view.appendChild(metaNotice(d.meta));
      var carriers = d.carriers || [];
      if (!carriers.length) {
        view.appendChild(missingNote("No carrier metrics are available. Carrier health appears only when a host exports multi-carrier metrics (multi-carrier enabled)."));
        return;
      }
      var rows = carriers.map(function (c) {
        var eligibleCell;
        if (c.eligible == null) eligibleCell = el("div", null, [badge("unmeasured", "")]);
        else if (c.eligible) eligibleCell = el("div", null, [badge("eligible", "ok")]);
        else eligibleCell = el("div", null, [badge("gated: " + (c.gateReason || "unknown"), "bad")]);
        return el("tr", null, [
          el("td", { text: c.serverId + " / " + c.carrier }),
          el("td", null, [badge((c.state || "unknown").replace(/_/g, " "), stateTone(c.state))]),
          c.score == null ? el("td", { cls: "num", text: "unmeasured" }) : valueCell(c.score, function (v) { return fmtNum(v, 3); }),
          c.goodputMiBps == null ? el("td", { cls: "num", text: "unmeasured" }) : valueCell(c.goodputMiBps, function (v) { return fmtNum(v, 2) + " MiB/s"; }),
          c.successRatio == null ? el("td", { cls: "num", text: "unmeasured" }) : valueCell(c.successRatio, function (v) { return fmtNum(v, 3); }),
          c.stallRatePer100MiB == null ? el("td", { cls: "num", text: "unmeasured" }) : valueCell(c.stallRatePer100MiB, function (v) { return fmtNum(v, 2); }),
          el("td", null, [eligibleCell]),
          c.cooldownRemainingSec == null ? el("td", { cls: "num", text: "N/A" }) : valueCell(c.cooldownRemainingSec, function (v) { return v + " s"; }),
          c.probeBytesToday == null ? el("td", { cls: "num", text: "unmeasured" }) : valueCell(c.probeBytesToday, function (v) { return fmtNum(v / 1048576, 1) + " MiB"; }),
          c.lossEvents == null ? el("td", { cls: "num", text: "unmeasured" }) : valueCell(c.lossEvents),
          c.reconnects == null ? el("td", { cls: "num", text: "unmeasured" }) : valueCell(c.reconnects)
        ]);
      });
      view.appendChild(el("div", { cls: "table-wrap" }, [
        el("table", null, [
          el("thead", null, [el("tr", null, ["Carrier", "State", "Score", "Goodput MiB/s", "Success", "Stalls /100 MiB", "Eligibility", "Cooldown", "Probe today", "Losses", "Reconnects"].map(function (h) { return el("th", { text: h }); }))]),
          el("tbody", null, rows)
        ])
      ]));

      // Per-carrier detail cards
      view.appendChild(el("h3", { cls: "section-subhead", text: "Carrier details" }));
      var detailCards = carriers.map(carrierDetailCard);
      view.appendChild(el("div", { cls: "grid-2" }, detailCards));

      var keys = [];
      carriers.forEach(function (c) {
        keys.push(c.serverId + ".carrier." + c.carrier + ".score");
        keys.push(c.serverId + ".carrier." + c.carrier + ".goodput_mibps");
      });
      return fetchSeries(keys, 120).then(function (series) {
        var scoreSeries = [], goodSeries = [];
        carriers.forEach(function (c, i) {
          var base = c.serverId + ".carrier." + c.carrier;
          scoreSeries.push({ name: c.carrier, color: PALETTE[i % PALETTE.length], points: seriesPoints(series, base + ".score") });
          goodSeries.push({ name: c.carrier, color: PALETTE[i % PALETTE.length], points: seriesPoints(series, base + ".goodput_mibps") });
        });
        view.appendChild(el("div", { cls: "grid-2" }, [
          el("div", { cls: "card" }, [el("h3", { text: "Carrier score over time" }), lineChart({ series: scoreSeries, yMax: 1, yDigits: 2 })]),
          el("div", { cls: "card" }, [el("h3", { text: "Carrier goodput (MiB/s)" }), lineChart({ series: goodSeries, unit: "MiB/s" })])
        ]));
        (d.notes || []).forEach(function (n) { view.appendChild(el("div", { cls: "notice", text: n })); });
      });
    });
  }

  // ---- Routing rules editor (Germany C4 routing plane) -------------------------
  // Operator edits an ordered list of routing rules. Client-side validation
  // mirrors the server validator (pkg/routing). "Validate" POSTs the rules
  // object to routing-validate (no host I/O); "Preview diff" shows the
  // redacted before/after; "Apply" is gated by the routingApply flag and
  // requires the RESTART confirm token. No secrets in any request/response.
  function renderRouting(view) {
    return v2("/schema/routing-plane").then(function (schema) {
      clear(view);
      var editable = !!schema.editable;
      view.appendChild(el("div", { cls: "notice" }, [
        el("h3", { text: "Routing rules — " + (schema.status || "read-only") }),
        el("span", { cls: "muted small", text: "Germany outbound routing engine. The first enabled rule whose match criteria are satisfied selects the outbound (direct / warp / block). When no rule matches, the default action applies (never block)." })
      ]));

      // --- default action selector ---
      var defaultAction = el("select", { cls: "editor-select" }, [
        el("option", { value: "direct", text: "direct (default)" }),
        el("option", { value: "warp", text: "warp" })
      ]);
      view.appendChild(el("div", { cls: "field-row" }, [
        el("label", { cls: "k", text: "Default action (when no rule matches)" }),
        defaultAction
      ]));

      // --- rules table (editable) ---
      var rulesState = [
        { id: "rule-1", enabled: true, domain: "", keyword: "", ipCidr: "", portMin: "", portMax: "", action: "direct", fallback: "", comment: "" }
      ];
      var ruleSeq = 1;
      var rulesBody = el("tbody");
      var rulesTable = el("table", { cls: "rules-editor" }, [
        el("thead", null, [el("tr", null, ["#","ID","Enabled","Match type","Match value","Action","Fallback","Comment","▲","▼","✕"].map(function(h){return el("th",{text:h});}))]),
        rulesBody
      ]);

      function renderRulesTable() {
        clear(rulesBody);
        rulesState.forEach(function (r, i) {
          var idIn = el("input", { cls: "editor-input", value: r.id });
          var enCb = el("input", { type: "checkbox" });
          enCb.checked = r.enabled;
          var mType = el("select", null, [
            el("option", { value: "", text: "—none—" }),
            el("option", { value: "domain", text: "domain (suffix/exact)" }),
            el("option", { value: "keyword", text: "keyword (substring)" }),
            el("option", { value: "ip_cidr", text: "IP CIDR" }),
            el("option", { value: "port_range", text: "port range (AND)" })
          ]);
          mType.value = mType.value || "";
          var mVal = el("input", { cls: "editor-input", placeholder: "e.g. .example.com / myapp / 10.0.0.0/8 / 443" });
          var portMinIn = el("input", { cls: "editor-input editor-input-sm", type: "number", min: "0", max: "65535", placeholder: "min" });
          var portMaxIn = el("input", { cls: "editor-input editor-input-sm", type: "number", min: "0", max: "65535", placeholder: "max" });
          var actionSel = el("select", null, [
            el("option", { value: "direct", text: "direct" }),
            el("option", { value: "warp", text: "warp" }),
            el("option", { value: "block", text: "block" })
          ]);
          var fbSel = el("select", null, [
            el("option", { value: "", text: "none (fail-closed)" }),
            el("option", { value: "direct", text: "direct" })
          ]);
          var cmIn = el("input", { cls: "editor-input", placeholder: "note" });

          // sync initial values
          function syncValues() {
            var mt = mType.value;
            mVal.value = mt === "domain" ? r.domain : mt === "keyword" ? r.keyword : mt === "ip_cidr" ? r.ipCidr : "";
            portMinIn.value = r.portMin || "";
            portMaxIn.value = r.portMax || "";
            actionSel.value = r.action;
            fbSel.value = r.fallback;
            cmIn.value = r.comment;
            idIn.value = r.id;
          }
          mType.addEventListener("change", function () {
            r.domain = r.keyword = r.ipCidr = "";
            if (mType.value === "port_range") { r.portMin = ""; r.portMax = ""; }
            syncValues();
          });
          mVal.addEventListener("input", function () {
            var mt = mType.value;
            r.domain = r.keyword = r.ipCidr = "";
            if (mt === "domain") r.domain = mVal.value;
            else if (mt === "keyword") r.keyword = mVal.value;
            else if (mt === "ip_cidr") r.ipCidr = mVal.value;
          });
          portMinIn.addEventListener("input", function(){ r.portMin = portMinIn.value; });
          portMaxIn.addEventListener("input", function(){ r.portMax = portMaxIn.value; });
          actionSel.addEventListener("change", function(){ r.action = actionSel.value; fbSel.disabled = (r.action !== "warp"); if (r.action!=="warp") { r.fallback=""; fbSel.value=""; } });
          fbSel.addEventListener("change", function(){ r.fallback = fbSel.value; });
          cmIn.addEventListener("input", function(){ r.comment = cmIn.value; });
          idIn.addEventListener("input", function(){ r.id = idIn.value; });
          enCb.addEventListener("change", function(){ r.enabled = enCb.checked; });

          syncValues();
          // set mType based on which field is populated
          if (r.domain) mType.value = "domain";
          else if (r.keyword) mType.value = "keyword";
          else if (r.ipCidr) mType.value = "ip_cidr";
          else if (r.portMin || r.portMax) mType.value = "port_range";
          mVal.value = r.domain || r.keyword || r.ipCidr || "";
          if (r.action !== "warp") fbSel.disabled = true;

          var upBtn = el("button", { cls: "btn btn-sm", type: "button", text: "▲", attrs: { title: "Move up" } });
          var dnBtn = el("button", { cls: "btn btn-sm", type: "button", text: "▼", attrs: { title: "Move down" } });
          var delBtn = el("button", { cls: "btn btn-sm btn-danger", type: "button", text: "✕", attrs: { title: "Delete rule" } });
          upBtn.addEventListener("click", function(){ if (i > 0) { var tmp = rulesState[i-1]; rulesState[i-1] = rulesState[i]; rulesState[i] = tmp; renderRulesTable(); } });
          dnBtn.addEventListener("click", function(){ if (i < rulesState.length-1) { var tmp = rulesState[i+1]; rulesState[i+1] = rulesState[i]; rulesState[i] = tmp; renderRulesTable(); } });
          delBtn.addEventListener("click", function(){ rulesState.splice(i,1); if (!rulesState.length) rulesState.push({id:"rule-"+(++ruleSeq),enabled:true,domain:"",keyword:"",ipCidr:"",portMin:"",portMax:"",action:"direct",fallback:"",comment:""}); renderRulesTable(); });

          var typeCell = el("td", null, [mType, mVal]);
          var portCell = el("td", null, [portMinIn, el("span",{text:"–"}), portMaxIn]);
          var row = el("tr", null, [
            el("td", { text: String(i+1) }),
            el("td", null, [idIn]),
            el("td", null, [enCb]),
            typeCell,
            el("td", null, [actionSel]),
            el("td", null, [fbSel]),
            el("td", null, [cmIn]),
            el("td", null, [upBtn]),
            el("td", null, [dnBtn]),
            el("td", null, [delBtn])
          ]);
          rulesBody.appendChild(row);
        });
      }

      var addRuleBtn = el("button", { cls: "btn", type: "button", text: "+ Add rule" });
      addRuleBtn.addEventListener("click", function(){
        ruleSeq++;
        rulesState.push({ id: "rule-" + ruleSeq, enabled: true, domain: "", keyword: "", ipCidr: "", portMin: "", portMax: "", action: "direct", fallback: "", comment: "" });
        renderRulesTable();
      });

      view.appendChild(el("div", { cls: "card editor-card" }, [
        el("h3", { text: "Rules (" + rulesState.length + ")" }),
        el("div", { cls: "table-wrap" }, [rulesTable]),
        el("div", { cls: "btn-row" }, [addRuleBtn])
      ]));

      // --- live client-side validation indicator ---
      var liveErrs = el("div", { cls: "editor-live-errs", hidden: "hidden" });
      view.appendChild(liveErrs);
      function updateLiveErrors() {
        var rs = buildRulesObject({ defaultAction: defaultAction.value, rules: rulesState });
        var errs = validateRoutingRulesClient(rs);
        if (errs.length) {
          liveErrs.hidden = false;
          liveErrs.textContent = errs.join("; ");
          liveErrs.className = "editor-live-errs bad";
        } else {
          liveErrs.hidden = true;
          liveErrs.className = "editor-live-errs";
        }
      }
      // observe changes via interval-light approach: re-validate on any input
      view.querySelectorAll("input, select").forEach(function(n){ n.addEventListener("change", updateLiveErrors); n.addEventListener("input", updateLiveErrors); });

      // --- action buttons: Validate / Preview diff / Apply ---
      var resultNode = el("div", { cls: "editor-result" });
      var validateBtn = el("button", { cls: "btn", type: "button", text: "Validate" });
      var diffBtn = el("button", { cls: "btn", type: "button", text: "Preview diff" });
      var applyBtn = el("button", { cls: "btn btn-danger", type: "button", text: "Apply" });
      if (!editable) {
        applyBtn.disabled = true;
        applyBtn.title = schema.editDisabledReason || "routingApply flag is off";
      }
      validateBtn.addEventListener("click", function() {
        var rs = buildRulesObject({ defaultAction: defaultAction.value, rules: rulesState });
        var localErrs = validateRoutingRulesClient(rs);
        if (localErrs.length) {
          resultNode.textContent = "Client-side validation failed: " + localErrs.join("; ");
          resultNode.className = "editor-result bad";
          return;
        }
        resultNode.textContent = "Sending to server validator…";
        resultNode.className = "editor-result";
        postJSON("/changes/germany/routing-validate", { role: "germany", set: {}, rules: rs })
          .then(function (resp) {
            if (resp.valid) {
              resultNode.textContent = "✓ Valid. " + ((resp.errors||[]).length ? "Notes: "+resp.errors.join("; ") : "");
              resultNode.className = "editor-result ok";
            } else {
              resultNode.textContent = "✗ Invalid: " + (resp.errors||[]).join("; ");
              resultNode.className = "editor-result bad";
            }
            if (resp.rulesDiff) { resultNode.appendChild(el("div",{cls:"muted small",text:"Rules diff: " + resp.rulesDiff.length + " entr(y/ies)"})); }
          })
          .catch(function(e){ resultNode.textContent = "Error: " + e.message; resultNode.className = "editor-result bad"; });
      });
      diffBtn.addEventListener("click", function() {
        var rs = buildRulesObject({ defaultAction: defaultAction.value, rules: rulesState });
        var localErrs = validateRoutingRulesClient(rs);
        if (localErrs.length) { resultNode.textContent = "Fix client-side errors first: " + localErrs.join("; "); resultNode.className = "editor-result bad"; return; }
        resultNode.textContent = "Computing diff…";
        postJSON("/changes/germany/routing-validate", { role: "germany", set: {}, rules: rs })
          .then(function (resp) {
            clear(resultNode);
            if (resp.rulesDiff) {
              resultNode.appendChild(el("h4",{text:"Redacted before/after diff"}));
              renderDiffList(resultNode, resp.rulesDiff, "Rules diff");
            } else {
              resultNode.appendChild(el("div",{cls:"notice",text:"No rules diff returned (agent env-set plane unchanged)."}));
            }
            resultNode.className = "editor-result";
          })
          .catch(function(e){ resultNode.textContent = "Error: " + e.message; resultNode.className = "editor-result bad"; });
      });
      applyBtn.addEventListener("click", function() {
        if (!editable) return;
        var rs = buildRulesObject({ defaultAction: defaultAction.value, rules: rulesState });
        var localErrs = validateRoutingRulesClient(rs);
        if (localErrs.length) { resultNode.textContent = "Fix client-side errors first."; resultNode.className = "editor-result bad"; return; }
        clear(resultNode);
        resultNode.appendChild(el("div",{cls:"notice warn",text:"⚠ Applying routing rules RESTARTS the splitter service (~10 s tunnel downtime). The old config is retained for rollback."}));
        confirmModal("Confirm restart", "RESTART", function() {
          postJSON("/changes/germany/routing-apply", { role: "germany", set: {}, rules: rs, confirm: "RESTART", reason: "dashboard routing editor apply" })
            .then(function(resp){
              resultNode.appendChild(el("div",{cls:"notice ok",text:"✓ Applied. Outcome: "+(resp.outcome||"ok")+" · revision "+(resp.revision||"—")+" · "+(resp.restartWarning||"")+(resp.peerChangeRequired?" · Peer change required: "+resp.peerChangeRequired:"")}));
              resultNode.className = "editor-result ok";
            })
            .catch(function(e){
              var msg = e.status === 503 ? ("Apply refused: " + e.message) : ("Error: " + e.message);
              resultNode.appendChild(el("div",{cls:"notice bad",text:msg}));
              resultNode.className = "editor-result bad";
            });
        }, resultNode);
      });

      view.appendChild(el("div", { cls: "btn-row editor-actions" }, [validateBtn, diffBtn, applyBtn]));
      view.appendChild(resultNode);
    }).catch(function(e) {
      clear(view);
      view.appendChild(el("div", { cls: "notice bad", text: "Could not load routing schema: " + e.message }));
    });
  }

  // ---- Outbounds (read-only) ---------------------------------------------------
  function renderOutbounds(view) {
    return v2("/outbounds").then(function (d) {
      clear(view);
      view.appendChild(el("div", { cls: "notice", text: "Configured Reality/Xray outbounds from the dashboard configuration. Public identity only: no keys, UUIDs, or credentials are shown." }));
      var list = d.outbounds || [];
      if (!list.length) {
        view.appendChild(missingNote(d.empty || "No outbounds are configured."));
        return;
      }
      view.appendChild(el("div", { cls: "table-wrap" }, [
        el("table", null, [
          el("thead", null, [el("tr", null, ["Name", "Protocol", "Port", "SNI", "Transport", "Enabled", "Status", "Validation"].map(function (h) { return el("th", { text: h }); }))]),
          el("tbody", null, list.map(function (o) {
            return el("tr", null, [
              el("td", { text: o.name }),
              el("td", { text: o.protocol }),
              valueCell(o.port),
              el("td", { text: o.serverName }),
              el("td", { text: o.transport }),
              el("td", null, [o.enabled ? badge("enabled", "ok") : badge("disabled", "")]),
              el("td", { text: o.status || "—" }),
              el("td", null, [(o.validation && o.validation.length) ? badge(o.validation.length + " issue(s)", "bad") : badge("valid", "ok")])
            ]);
          }))
        ])
      ]));
      view.appendChild(el("div", { cls: "notice", text: "Editing is disabled in this build (Apply controls are inert)." }));
    });
  }

  // ---- Reality / consumer inbounds (C3 editing surface) --------------------------
  // Read-only list of the Germany Reality + Iran consumer inbounds driven by the
  // public-field C3 schemas. The API never returns key material — only a 12-hex
  // fingerprint (keyRef). The Edit affordance is disabled with a tooltip when the
  // per-capability flag is off; when the schema is editable it shows the (stubbed)
  // validate + diff + confirm flow behind the restart warning. No CDN, CSP intact.
  var C3_CONCEPTS = [
    { concept: "germany-inbounds", role: "germany", label: "Germany Reality inbounds" },
    { concept: "iran-inbounds", role: "iran", label: "Iran consumer inbounds" }
  ];
  // Per-role inbound editor: instance cards with editable public fields
  // (port, SNI, shortId, enabled). Key material is shown as a 12-hex
  // fingerprint only (keyRef) and is never editable or accepted. Validate /
  // diff / apply (confirm RESTART) are gated by the per-role inbound flag.
  function inboundEditorCard(view, entry) {
    var schema = entry.schema;
    var concept = entry.meta;
    var editable = !!schema.editable;
    var role = concept.role;

    // One editable instance per card (the primary inbound). Operators add
    // more instances by editing the instance id + fields below.
    var inst = {
      instance: role === "germany" ? "reality-1" : "consumer-1",
      enabled: true,
      port: "",
      sni: "",
      shortId: "",
      keyRef: "(fingerprint only — never editable)"
    };

    function inb(label, node, hint) {
      return el("div", { cls: "field-row" }, [
        el("label", { cls: "k", text: label }), node,
        hint ? el("span", { cls: "muted small", text: hint }) : el("span")
      ]);
    }
    var instIn = el("input", { cls: "editor-input", value: inst.instance });
    var enCb = el("input", { type: "checkbox", cls: "editor-check" }); enCb.checked = true;
    var portIn = el("input", { cls: "editor-input editor-input-sm", type: "number", min: "1", max: "65535", placeholder: "port" });
    var sniIn = el("input", { cls: "editor-input", placeholder: "lowercase SNI" });
    var shortIn = el("input", { cls: "editor-input editor-input-sm", placeholder: "16-hex shortId" });
    var keyRefRow = el("div", { cls: "field-row" }, [
      el("label", { cls: "k", text: "keyRef" }),
      el("input", { cls: "editor-input", readonly: "readonly", value: inst.keyRef }),
      el("span", { cls: "muted small", text: "fingerprint; key material is never shown or accepted" })
    ]);

    var card = el("div", { cls: "card editor-card" }, [
      el("h3", { text: concept.label + " — " + (schema.status || "read-only") }),
      inb("instance", instIn, "the inbound instance name"),
      inb("enabled", enCb, "true = inbound active"),
      inb("port", portIn, "1..65535"),
      inb("sni", sniIn, "lowercase RFC 1123 hostname"),
      inb("shortId", shortIn, "16 hex chars"),
      keyRefRow
    ]);
    view.appendChild(card);

    var resultNode = el("div", { cls: "editor-result" });
    function inboundsObj() {
      var o = { instance: instIn.value.trim(), enabled: enCb.checked };
      if (portIn.value) o.port = parseInt(portIn.value, 10);
      o.sni = sniIn.value.trim();
      if (shortIn.value) o.shortId = shortIn.value.trim();
      return o;
    }
    function clientInboundErrors() {
      var errs = [];
      if (!instIn.value.trim()) errs.push("instance is required");
      if (!sniIn.value.trim()) errs.push("sni is required");
      if (portIn.value) { var p = parseInt(portIn.value,10); if (isNaN(p)||p<1||p>65535) errs.push("port must be 1..65535"); }
      if (shortIn.value && !/^[0-9a-f]{16}$/.test(shortIn.value)) errs.push("shortId must be 16 hex chars");
      return errs;
    }

    var validateBtn = el("button", { cls: "btn", type: "button", text: "Validate" });
    var applyBtn = el("button", { cls: "btn btn-danger", type: "button", text: "Apply" });
    if (!editable) { applyBtn.disabled = true; applyBtn.title = schema.editDisabledReason || "the " + role + " inbound flag is off"; }

    validateBtn.addEventListener("click", function () {
      var ce = clientInboundErrors();
      if (ce.length) { resultNode.textContent = "Client-side: " + ce.join("; "); resultNode.className = "editor-result bad"; return; }
      resultNode.textContent = "Validating…"; resultNode.className = "editor-result";
      postJSON("/changes/" + role + "/inbounds-validate", { role: role, inbounds: [inboundsObj()] })
        .then(function (resp) {
          resultNode.textContent = "✓ validate ok (role " + (resp.role || role) + ")" + (resp.flagEnabled ? " · flag enabled" : " · flag disabled (apply will refuse)");
          resultNode.className = "editor-result ok";
        })
        .catch(function (e) { resultNode.textContent = "Error: " + e.message; resultNode.className = "editor-result bad"; });
    });
    applyBtn.addEventListener("click", function () {
      if (!editable) return;
      var ce = clientInboundErrors();
      if (ce.length) { resultNode.textContent = "Fix client-side errors first: " + ce.join("; "); resultNode.className = "editor-result bad"; return; }
      clear(resultNode);
      resultNode.appendChild(el("div", { cls: "notice warn", text: "⚠ Applying inbounds RESTARTS the affected xray service (~10 s). A Germany-side edit stages a Blob B export for the Iran host (peer change required; there is no coordinated apply)." }));
      confirmModal("Confirm restart", "RESTART", function () {
        postJSON("/changes/" + role + "/inbounds-apply", { role: role, inbounds: [inboundsObj()], confirm: "RESTART", reason: "dashboard inbound editor apply" })
          .then(function (resp) {
            resultNode.appendChild(el("div", { cls: "notice ok", text: "✓ Applied. " + (resp.restartWarning || "") + (resp.peerChangeRequired ? " · " + resp.peerChangeRequired : "") }));
            resultNode.className = "editor-result ok";
          })
          .catch(function (e) {
            var msg = e.status === 503 ? ("Apply refused: " + e.message) : ("Error: " + e.message);
            resultNode.appendChild(el("div", { cls: "notice bad", text: msg }));
            resultNode.className = "editor-result bad";
          });
      }, resultNode);
    });
    view.appendChild(el("div", { cls: "btn-row editor-actions" }, [validateBtn, applyBtn]));
    view.appendChild(resultNode);
  }

  // Rotate-key affordance: gated by the key-rotation flag. Requires the typed
  // ROTATE confirm. The old key is always retained for rollback; the response
  // carries only the new key's fingerprint.
  function rotateKeyCard(view, rotationSchema) {
    var editable = !!rotationSchema.editable;
    view.appendChild(el("div", { cls: "card editor-card" }, [
      el("h3", { text: "Rotate key — " + (rotationSchema.status || "read-only") })
    ]));
    var roleSel = el("select", null, [
      el("option", { value: "germany", text: "germany" }),
      el("option", { value: "iran", text: "iran" })
    ]);
    var instIn = el("input", { cls: "editor-input", placeholder: "inbound instance (e.g. reality-1)" });
    var resultNode = el("div", { cls: "editor-result" });

    var rotateBtn = el("button", { cls: "btn btn-danger", type: "button", text: "Rotate key" });
    if (!editable) {
      rotateBtn.disabled = true;
      rotateBtn.title = rotationSchema.editDisabledReason || "the keyRotation flag is off";
    }
    rotateBtn.addEventListener("click", function () {
      if (!editable) return;
      var role = roleSel.value;
      var instance = instIn.value.trim();
      if (!instance) { resultNode.textContent = "An instance name is required."; resultNode.className = "editor-result bad"; return; }
      clear(resultNode);
      resultNode.appendChild(el("div", { cls: "notice warn", text: "⚠ Rotating the keypair generates a NEW key. The OLD key is retained for the rollback window. The affected xray service restarts. Type ROTATE to confirm." }));
      confirmModal("Confirm rotate", "ROTATE", function () {
        postJSON("/changes/" + role + "/inbounds-rotate", { role: role, instance: instance, confirm: "ROTATE", reason: "dashboard rotate-key" })
          .then(function (resp) {
            resultNode.appendChild(el("div", { cls: "notice ok", text: "✓ Rotated. New key fingerprint: " + (resp.newKeyFingerprint || "—") + " · old key retained: " + (resp.oldKeyRetained ? "yes" : "no") }));
            resultNode.className = "editor-result ok";
          })
          .catch(function (e) {
            var msg = e.status === 503 ? ("Rotate refused: " + e.message) : ("Error: " + e.message);
            resultNode.appendChild(el("div", { cls: "notice bad", text: msg }));
            resultNode.className = "editor-result bad";
          });
      }, resultNode);
    });

    view.appendChild(el("div", { cls: "field-row" }, [el("label", { cls: "k", text: "Role" }), roleSel, el("span")]));
    view.appendChild(el("div", { cls: "field-row" }, [el("label", { cls: "k", text: "Instance" }), instIn, el("span")]));
    view.appendChild(el("div", { cls: "btn-row editor-actions" }, [rotateBtn]));
    view.appendChild(resultNode);
  }

  function renderInbounds(view) {
    var prompts = C3_CONCEPTS.map(function (c) {
      return v2("/schema/" + c.concept).then(function (schema) {
        return { meta: c, schema: schema };
      });
    });
    return Promise.all(prompts.concat([v2("/schema/inbounds-rotation").catch(function () {
      return { concept: "inbounds-rotation", editable: false, status: "read-only", editDisabledReason: "key rotation is off (flag disabled or schema unavailable)" };
    })])).then(function (entries) {
      clear(view);
      view.appendChild(el("div", { cls: "notice", text: "Public inbound fields only. Keys are shown as a 12-hex fingerprint (keyRef) — key material is never displayed or accepted. Inbound applies and rotate-key are gated by per-capability flags (default off)." }));
      for (var i = 0; i < C3_CONCEPTS.length; i++) {
        inboundEditorCard(view, entries[i]);
      }
      rotateKeyCard(view, entries[entries.length - 1]);
    });
  }

  // ---- C4 multi-carrier control editor -------------------------------------------
  // Master toggle + second carrier listener/dial/SNI + policy knobs. Enabling
  // requires a valid SNI + second-carrier fields; disabling is always allowed.
  // Validate/diff/confirm/apply are gated by the multiCarrierApply flag
  // (default off → Apply disabled with a tooltip naming the flag). No secrets
  // are sent: only public operator config. No CDN, CSP intact.
  function renderControl(view) {
    return v2("/schema/multi-carrier-control").then(function (schema) {
      clear(view);
      var editable = !!schema.editable;
      view.appendChild(el("div", { cls: "notice" }, [
        el("h3", { text: "Multi-carrier control — " + (schema.status || "read-only") }),
        el("span", { cls: "muted small", text: "Second down-carrier + policy engine. Enabling requires a valid SNI and second-carrier listener/dial; disabling is always allowed. Applying restarts the affected splitter service (and xray when SNI/listener changes)." })
      ]));

      var st = {
        enabled: false,
        listen2: "", dial2: "", sni2: "",
        policyMode: "static", topK: 1,
        probing: false, probeUrl: "", probeBudget: 0, ttfbBaseline: 0
      };

      function field(label, node, hint) {
        return el("div", { cls: "field-row" }, [
          el("label", { cls: "k", text: label }),
          node,
          hint ? el("span", { cls: "muted small", text: hint }) : el("span")
        ]);
      }

      var enabledCb = el("input", { type: "checkbox", cls: "editor-check" });
      var listen2In = el("input", { cls: "editor-input", placeholder: "e.g. 127.0.0.1:40002", value: st.listen2 });
      var dial2In = el("input", { cls: "editor-input", placeholder: "e.g. 127.0.0.1:40003", value: st.dial2 });
      var sni2In = el("input", { cls: "editor-input", placeholder: "lowercase RFC 1123 SNI", value: st.sni2 });
      var modeSel = el("select", null, [el("option",{value:"static",text:"static"}), el("option",{value:"adaptive",text:"adaptive"})]);
      modeSel.value = st.policyMode;
      var topKIn = el("input", { cls: "editor-input editor-input-sm", type: "number", min: "1", max: "8", value: String(st.topK) });
      var probeCb = el("input", { type: "checkbox", cls: "editor-check" });
      var probeUrlIn = el("input", { cls: "editor-input", placeholder: "operator-owned probe URL" });
      var probeBudgetIn = el("input", { cls: "editor-input editor-input-sm", type: "number", min: "0", value: "0" });
      var ttfbIn = el("input", { cls: "editor-input editor-input-sm", type: "number", min: "0", max: "30000", value: "0" });

      var formCard = el("div", { cls: "card editor-card" }, [
        el("h3", { text: "Master toggle" }),
        field("SPLIT_MULTI_CARRIER_ENABLED", enabledCb, "true = second carrier active"),
        el("h3", { text: "Second carrier" }),
        field("SPLIT_DOWN_LISTEN_2", listen2In, "host:port (Germany)"),
        field("SPLIT_DOWN_CARRIER_ADDR_2", dial2In, "host:port (Iran)"),
        field("SPLIT_DOWN_CARRIER2_SNI", sni2In, "lowercase SNI"),
        el("h3", { text: "Policy" }),
        field("SPLIT_POLICY_MODE", modeSel, "static|adaptive"),
        field("SPLIT_POLICY_TOP_K", topKIn, "1..8"),
        field("SPLIT_PROBING_ENABLED", probeCb, "enable probing"),
        field("SPLIT_PROBE_URL", probeUrlIn, "operator-owned http(s) URL"),
        field("SPLIT_PROBE_DAILY_BUDGET", probeBudgetIn, "bytes/day (0 = off)"),
        field("SPLIT_TTFB_BASELINE_MS", ttfbIn, "0..30000 ms")
      ]);
      view.appendChild(formCard);

      function currentSet() {
        var set = {
          "SPLIT_MULTI_CARRIER_ENABLED": enabledCb.checked ? "true" : "false"
        };
        if (enabledCb.checked) {
          set["SPLIT_DOWN_CARRIER2_SNI"] = sni2In.value.trim();
          if (listen2In.value.trim()) set["SPLIT_DOWN_LISTEN_2"] = listen2In.value.trim();
          if (dial2In.value.trim()) set["SPLIT_DOWN_CARRIER_ADDR_2"] = dial2In.value.trim();
          set["SPLIT_POLICY_MODE"] = modeSel.value;
          set["SPLIT_POLICY_TOP_K"] = topKIn.value || "1";
          set["SPLIT_PROBING_ENABLED"] = probeCb.checked ? "true" : "false";
          if (probeCb.checked) {
            set["SPLIT_PROBE_URL"] = probeUrlIn.value.trim();
            set["SPLIT_PROBE_DAILY_BUDGET"] = probeBudgetIn.value || "0";
            set["SPLIT_TTFB_BASELINE_MS"] = ttfbIn.value || "0";
          }
        }
        return set;
      }

      var resultNode = el("div", { cls: "editor-result" });
      var validateBtn = el("button", { cls: "btn", type: "button", text: "Validate" });
      var diffBtn = el("button", { cls: "btn", type: "button", text: "Preview diff" });
      var applyBtn = el("button", { cls: "btn btn-danger", type: "button", text: "Apply" });
      if (!editable) {
        applyBtn.disabled = true;
        applyBtn.title = schema.editDisabledReason || "multiCarrierApply flag is off";
      }

      // Enabling requires SNI + a valid second carrier; disabling always allowed.
      function enablingErrors() {
        if (!enabledCb.checked) return [];
        var errs = [];
        if (!sni2In.value.trim()) errs.push("SNI is required when the second carrier is enabled");
        var tK = parseInt(topKIn.value, 10);
        if (isNaN(tK) || tK < 1 || tK > 8) errs.push("top-k must be 1..8");
        if (probeCb.checked && !probeUrlIn.value.trim()) errs.push("a probe URL is required when probing is enabled");
        return errs;
      }

      validateBtn.addEventListener("click", function () {
        var errs = enablingErrors();
        if (errs.length) { resultNode.textContent = "Client-side: " + errs.join("; "); resultNode.className = "editor-result bad"; return; }
        resultNode.textContent = "Sending to server validator…"; resultNode.className = "editor-result";
        postJSON("/changes/germany/multicarrier-validate", { role: "germany", set: currentSet() })
          .then(function (resp) {
            if (resp.valid) { resultNode.textContent = "✓ Valid" + ((resp.xrayAffected) ? " · xray will restart" : ""); resultNode.className = "editor-result ok"; }
            else { resultNode.textContent = "✗ Invalid: " + (resp.errors||[]).join("; "); resultNode.className = "editor-result bad"; }
          })
          .catch(function(e){ resultNode.textContent = "Error: " + e.message; resultNode.className = "editor-result bad"; });
      });
      diffBtn.addEventListener("click", function () {
        var errs = enablingErrors();
        if (errs.length) { resultNode.textContent = "Fix client-side errors first: " + errs.join("; "); resultNode.className = "editor-result bad"; return; }
        clear(resultNode);
        resultNode.textContent = "Computing diff…";
        postJSON("/changes/germany/multicarrier-validate", { role: "germany", set: currentSet() })
          .then(function (resp) {
            clear(resultNode);
            var diffs = (resp.diff || []);
            if (diffs.length) {
              resultNode.appendChild(el("h4", { text: "Env-set diff (redacted)" }));
              var rows = diffs.map(function (d) {
                return el("tr", null, [
                  el("td", { text: d.key || d.name || "—" }),
                  el("td", { cls: "mono small", text: String(d.before == null ? "(unset)" : d.before) }),
                  el("td", { cls: "mono small", text: String(d.after == null ? "(unset)" : d.after) })
                ]);
              });
              resultNode.appendChild(el("div", { cls: "table-wrap" }, [el("table", null, [
                el("thead", null, [el("tr", null, [el("th",{text:"Key"}), el("th",{text:"Before"}), el("th",{text:"After"})])]),
                el("tbody", null, rows)
              ])]));
            } else {
              resultNode.appendChild(el("div", { cls: "notice", text: "No env-set diff returned (no changes or agent not available)." }));
            }
            resultNode.className = "editor-result";
          })
          .catch(function(e){ resultNode.textContent = "Error: " + e.message; resultNode.className = "editor-result bad"; });
      });
      applyBtn.addEventListener("click", function () {
        if (!editable) return;
        var errs = enablingErrors();
        if (errs.length) { resultNode.textContent = "Fix client-side errors first: " + errs.join("; "); resultNode.className = "editor-result bad"; return; }
        clear(resultNode);
        resultNode.appendChild(el("div", { cls: "notice warn", text: "⚠ Applying multi-carrier settings RESTARTS the splitter service (and xray if the SNI/listener changed, ~10 s). The old config is retained for rollback." }));
        confirmModal("Confirm restart", "RESTART", function () {
          postJSON("/changes/germany/multicarrier-apply", { role: "germany", set: currentSet(), confirm: "RESTART", reason: "dashboard multi-carrier editor apply" })
            .then(function (resp) {
              resultNode.appendChild(el("div", { cls: "notice ok", text: "✓ Applied. " + (resp.restartWarning || "") + (resp.peerChangeRequired ? " · Peer change required: " + resp.peerChangeRequired : "") }));
              resultNode.className = "editor-result ok";
            })
            .catch(function (e) {
              var msg = e.status === 503 ? ("Apply refused: " + e.message) : ("Error: " + e.message);
              resultNode.appendChild(el("div", { cls: "notice bad", text: msg }));
              resultNode.className = "editor-result bad";
            });
        }, resultNode);
      });

      view.appendChild(el("div", { cls: "btn-row editor-actions" }, [validateBtn, diffBtn, applyBtn]));
      view.appendChild(resultNode);
    }).catch(function (e) {
      clear(view);
      view.appendChild(el("div", { cls: "notice bad", text: "Could not load multi-carrier schema: " + e.message }));
    });
  }

  // ---- Network speed history -----------------------------------------------------
  function renderNetwork(view) {
    return v2("/hosts").then(function (d) {
      var keys = [];
      (d.hosts || []).forEach(function (h) { keys.push(h.id + ".up_mibps", h.id + ".down_mibps"); });
      return fetchSeries(keys, 360).then(function (series) {
        clear(view);
        view.appendChild(el("div", { cls: "notice", text: "Byte-counter rates derived from consecutive collections. History is kept in memory only and resets when the dashboard restarts." }));
        var cards = [];
        (d.hosts || []).forEach(function (h, i) {
          var up = seriesPoints(series, h.id + ".up_mibps");
          var down = seriesPoints(series, h.id + ".down_mibps");
          cards.push(el("div", { cls: "card" }, [
            el("h3", { text: (h.name || h.id) + " — throughput (MiB/s)" }),
            lineChart({ series: [{ name: "upload", color: PALETTE[i * 2 % PALETTE.length], points: up }, { name: "download", color: PALETTE[(i * 2 + 1) % PALETTE.length], points: down }], unit: "MiB/s", area: true })
          ]));
        });
        if (!cards.length) view.appendChild(missingNote("No hosts are configured."));
        else view.appendChild(el("div", { cls: "grid-2" }, cards));
      });
    });
  }

  // ---- Configuration (redacted) ----------------------------------------------------
  function renderConfig(view) {
    return v2("/config").then(function (d) {
      clear(view);
      view.appendChild(el("div", { cls: "notice", text: "Current dashboard configuration with secrets redacted. The TLS base path, credential sources, key paths and SSH identity paths are never shown." }));
      var rows = (d.values || []).map(function (v) {
        return el("tr", null, [
          el("td", { text: v.key }),
          el("td", { text: v.value }),
          el("td", null, [v.redacted ? badge("redacted", "warn") : badge("shown", "")]),
          el("td", null, [v.mutable ? badge("editable later", "") : badge("read-only", "")])
        ]);
      });
      view.appendChild(el("div", { cls: "table-wrap" }, [
        el("table", null, [
          el("thead", null, [el("tr", null, ["Key", "Value", "Redaction", "Mode"].map(function (h) { return el("th", { text: h }); }))]),
          el("tbody", null, rows)
        ])
      ]));
      (d.notes || []).forEach(function (n) { view.appendChild(el("div", { cls: "notice", text: n })); });
      view.appendChild(el("div", { cls: "card" }, [
        el("h3", { text: "Dry-run config plan (v1)" }),
        el("div", { cls: "notice", text: "Plan creation is available per host in the v1 detail view. It never applies anything; the Apply button is disabled." })
      ]));
    });
  }

  // ---- Logs / Events -----------------------------------------------------------------
  function renderEvents(view) {
    return v2("/events?limit=100").then(function (d) {
      clear(view);
      view.appendChild(el("div", { cls: "notice", text: "Recent audit and collector events. Messages are redacted before display." }));
      var events = d.events || [];
      if (!events.length) {
        view.appendChild(missingNote("No events recorded yet."));
        return;
      }
      view.appendChild(el("div", { cls: "card" }, [
        el("div", { cls: "log-list" }, events.map(function (e) {
          return el("div", { cls: "log-line " + (e.level || "info") }, [
            el("span", { cls: "ts", text: fmtTime(e.time) }),
            el("span", { cls: "lvl", text: (e.level || "info").toUpperCase() }),
            el("span", { text: (e.serverId ? "[" + e.serverId + "] " : "") + e.type + " — " + e.message })
          ]);
        }))
      ]));
    });
  }

  // ---- v1 host detail (kept; /api/v1 read endpoints, Apply disabled) ---------------
  // Services, listeners, resource gauges, and the per-metric table are rendered
  // from the v1 snapshot. The dry-run config plan form never applies anything.
  function v1Snapshot(id) {
    return getJSON(API_V1 + "/servers/" + encodeURIComponent(id));
  }

  function v1ResourceRows(snap) {
    var rows = [];
    if (snap.memoryMB) rows.push(["Memory (used)", snap.memoryMB + " MiB"]);
    if (snap.diskBytes) rows.push(["Disk (used)", fmtNum(snap.diskBytes / histGiBytes, 1) + " GiB"]);
    if (snap.uptimeSec) rows.push(["Uptime", fmtHours(snap.uptimeSec / 3600)]);
    return rows;
  }

  function v1ServicesTable(snap) {
    var rows = (snap.services || []).map(function (s) {
      var enabled = s.enabled ? " (" + s.enabled + ")" : "";
      return el("tr", null, [
        el("td", { text: s.unit }),
        el("td", { text: (s.state || "—") + enabled }),
        el("td", { text: s.subState || "—" }),
        el("td", { text: s.mainPid ? "pid " + s.mainPid : "—" })
      ]);
    });
    return el("div", { cls: "table-wrap" }, [
      el("table", null, [
        el("thead", null, [el("tr", null, ["Unit", "State", "SubState", "PID"].map(function (h) { return el("th", { text: h }); }))]),
        el("tbody", null, rows)
      ])
    ]);
  }

  function v1ListenersTable(snap) {
    var rows = (snap.listeners || []).map(function (l) {
      return el("tr", null, [el("td", { text: l.protocol }), el("td", { text: l.address }), el("td", { text: l.pid ? String(l.pid) : "—" })]);
    });
    return el("div", { cls: "table-wrap" }, [
      el("table", null, [
        el("thead", null, [el("tr", null, ["Proto", "Address", "PID"].map(function (h) { return el("th", { text: h }); }))]),
        el("tbody", null, rows)
      ])
    ]);
  }

  function v1MetricsTable(snap) {
    var samples = (snap.metrics && snap.metrics.samples) || [];
    var rows = samples.map(function (s) {
      var name = s.labels
        ? s.name + "{" + Object.keys(s.labels).map(function (k) { return k + "=" + s.labels[k]; }).join(",") + "}"
        : s.name;
      var rate = snap.rates ? snap.rates[name] : null;
      return el("tr", null, [el("td", { text: name }), valueCell(s.value), el("td", { cls: "num", text: rate ? fmtNum(rate.perSec, 2) + "/s" : "—" })]);
    });
    return el("div", { cls: "table-wrap" }, [
      el("table", null, [
        el("thead", null, [el("tr", null, ["Metric", "Value", "Rate"].map(function (h) { return el("th", { text: h }); }))]),
        el("tbody", null, rows)
      ])
    ]);
  }

  function renderV1Detail(id, view) {
    return v1Snapshot(id).then(function (snap) {
      clear(view);
      view.appendChild(el("div", { cls: "notice", text: "v1 host detail (read-only). Mode: dry-run plans only; no host is changed." }));
      (snap.errors || []).forEach(function (e) { view.appendChild(el("div", { cls: "notice warn", text: e })); });
      var res = v1ResourceRows(snap);
      if (res.length) {
        view.appendChild(el("div", { cls: "card" }, [el("h3", { text: "Resources" }),
          el("table", null, res.map(function (r) { return el("tr", null, [el("td", { text: r[0] }), el("td", { text: r[1] })]); }))]));
      }
      view.appendChild(el("div", { cls: "card" }, [el("h3", { text: "Services" }), v1ServicesTable(snap)]));
      view.appendChild(el("div", { cls: "card" }, [el("h3", { text: "Listeners" }), v1ListenersTable(snap)]));
      view.appendChild(el("div", { cls: "card" }, [el("h3", { text: "Metrics" }), v1MetricsTable(snap)]));
      view.appendChild(v1PlanForm(id));
    });
  }

  // Dry-run plan form (v1). The Apply button is disabled and inert.
  function v1PlanForm(id) {
    var policy = el("select", { id: "planPolicy" }, [
      el("option", { value: "default", text: "default (dual-stack)" }),
      el("option", { value: "prefer-ipv4", text: "prefer-ipv4 (v4-first, v6 fallback)" }),
      el("option", { value: "ipv4-only", text: "ipv4-only (hard A-filter — risky)" })
    ]);
    var onlyV4 = el("select", { id: "planOnlyV4" }, [
      el("option", { value: "false", text: "false" }),
      el("option", { value: "true", text: "true" })
    ]);
    var port = el("input", { id: "planMetricsPort", type: "number", min: "1", max: "65535", value: "9101" });
    var relay = el("input", { id: "planRelayBuf", type: "number", min: "1024", max: "8388608", value: "32768" });
    var result = el("div", { id: "planResult", cls: "notice", hidden: "hidden" });
    var submit = el("button", { cls: "btn", type: "button", id: "submitPlanBtn", text: "Create dry-run plan" });
    var apply = el("button", { cls: "btn btn-disabled", type: "button", id: "applyBtn", disabled: "disabled", title: "Mutations disabled in this build", text: "Apply (disabled)" });
    submit.addEventListener("click", function () {
      var changes = [
        { key: "SPLIT_TARGET_ADDR_POLICY", value: policy.value },
        { key: "SPLIT_TARGET_ONLY_IPV4", value: onlyV4.value },
        { key: "SPLIT_METRICS_PORT", value: port.value },
        { key: "SPLIT_RELAY_BUF", value: relay.value }
      ];
      result.hidden = false;
      result.textContent = "Submitting…";
      fetch(API_V1 + "/servers/" + encodeURIComponent(id) + "/config/plan", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ changes: changes })
      }).then(function (r) { return r.json().then(function (b) { return { ok: r.ok, body: b }; }); })
        .then(function (res) {
          if (!res.ok) { result.textContent = "Error: " + (res.body.error || "request failed"); return; }
          var out = "Plan ID: " + res.body.planId + "\n";
          (res.body.changes || []).forEach(function (c) { out += "  " + c.key + ": " + (c.before || "(unknown)") + " → " + c.after + "\n"; });
          if (res.body.restartRequired) out += "Restart required: yes\n";
          out += "\n⚠ This is a DRY-RUN plan. No host was contacted or modified.";
          result.textContent = out;
        })
        .catch(function (e) { result.textContent = "Error: " + e.message; });
    });
    return el("div", { cls: "card plan-form" }, [
      el("h3", { text: "Dry-run config plan" }),
      el("div", { cls: "field-row" }, [el("div", { cls: "k", text: "SPLIT_TARGET_ADDR_POLICY" }), policy, el("span")]),
      el("div", { cls: "field-row" }, [el("div", { cls: "k", text: "SPLIT_TARGET_ONLY_IPV4" }), onlyV4, el("span")]),
      el("div", { cls: "field-row" }, [el("div", { cls: "k", text: "SPLIT_METRICS_PORT" }), port, el("span")]),
      el("div", { cls: "field-row" }, [el("div", { cls: "k", text: "SPLIT_RELAY_BUF" }), relay, el("span")]),
      el("div", { cls: "btn-row" }, [submit, apply]),
      result
    ]);
  }

  var histGiBytes = 1073741824;
  window.__tunnelDashV1 = { renderDetail: renderV1Detail, mode: "dry-run" };

  // ---- navigation, polling, theme ----------------------------------------------------
  function sectionFromHash() {
    var h = (window.location.hash || "#overview").replace(/^#/, "");
    return SECTIONS[h] ? h : "overview";
  }

  function setActive(section) {
    document.querySelectorAll(".nav-link").forEach(function (a) {
      a.classList.toggle("active", a.getAttribute("data-section") === section);
    });
    document.querySelectorAll(".view").forEach(function (v) {
      v.hidden = v.getAttribute("data-view") !== section;
    });
    document.getElementById("pageTitle").textContent = SECTIONS[section].title;
    document.getElementById("sidebar").classList.remove("open");
  }
  var inFlight = false;

  // Build a clean, redacted diagnostics snapshot for the "Copy Diagnostics"
  // button. Never includes secrets — only public, operator-visible state.
  function buildDiagnostics() {
    var out = {
      generatedAt: new Date().toISOString(),
      section: state.section,
      lastPollSuccess: state.lastPollSuccess ? new Date(state.lastPollSuccess).toISOString() : null,
      lastApiError: state.lastApiError,
      overview: state.lastOverview || null,
      carriers: state.lastCarriers || null,
      notes: [
        "This diagnostics snapshot is read-only. No secrets or credentials are included."
      ]
    };
    return JSON.stringify(out, null, 2);
  }

  function copyDiagnostics() {
    var text = buildDiagnostics();
    var btn = document.getElementById("copyDiagnosticsBtn");
    function done(ok) {
      if (!btn) return;
      btn.textContent = ok ? "✓ Copied" : "✗ Copy failed";
      btn.disabled = true;
      setTimeout(function () { btn.textContent = "⧉ Diagnostics"; btn.disabled = false; }, 2000);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
    } else {
      // Fallback: select a temporary textarea and use execCommand.
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      try { done(document.execCommand("copy")); } catch (e) { done(false); }
      document.body.removeChild(ta);
    }
  }

  function refresh() {
    if (inFlight) return Promise.resolve();
    inFlight = true;
    var section = state.section;
    var view = document.querySelector('.view[data-view="' + section + '"]');
    var api = document.getElementById("apiStatus");
    return SECTIONS[section].render(view).then(function () {
      state.lastApiError = null;
      api.textContent = "API: ok";
      api.className = "small";
      updateGlobalBadges();
    }).catch(function (err) {
      var msg = (err && err.message) ? err.message : "unknown error";
      state.lastApiError = { status: err.status || null, message: msg, at: new Date().toISOString() };
      clear(view);
      var status = err && err.status;
      var node;
      if (status === 401 || status === 403) {
        node = el("div", { cls: "notice bad", attrs: { role: "alert" } }, [
          el("h3", { text: "Permission denied (" + status + ")" }),
          el("p", { text: "The dashboard rejected this request. You do not have the required credentials for this host." }),
          el("p", { cls: "muted small", text: "Action: verify your HTTP Basic credentials or Bearer token, then retry." })
        ]);
      } else if (status === 503) {
        node = el("div", { cls: "notice warn", attrs: { role: "alert" } }, [
          el("h3", { text: "Control plane unavailable (503)" }),
          el("p", { text: "The control agent socket is not reachable or the required capability flag is off. Read-only telemetry continues normally." })
        ]);
      } else {
        node = el("div", { cls: "notice bad", attrs: { role: "alert" } }, [
          el("h3", { text: "Could not load section" }),
          el("p", { text: msg + ". Check that the dashboard is reachable." })
        ]);
      }
      view.appendChild(node);
      api.textContent = "API: " + (status ? status : "error");
      api.className = "small badge bad";
      updateGlobalBadges();
    }).then(function () {
      inFlight = false;
      document.getElementById("lastPoll").textContent = "Last update: " + new Date().toLocaleTimeString();
    });
  }

  function startPolling() {
    if (state.pollTimer) clearInterval(state.pollTimer);
    var sec = parseInt(document.getElementById("pollSec").value, 10);
    if (isNaN(sec) || sec < 2) sec = 5;
    state.pollSec = sec;
    state.pollTimer = setInterval(refresh, sec * 1000);
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    try { window.localStorage.setItem("tunneldash.theme", theme); } catch (e) { /* storage may be blocked */ }
  }

  function initTheme() {
    var saved = null;
    try { saved = window.localStorage.getItem("tunneldash.theme"); } catch (e) { saved = null; }
    if (saved !== "light" && saved !== "dark") {
      saved = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
    }
    applyTheme(saved);
  }

  function init() {
    initTheme();
    document.getElementById("themeBtn").addEventListener("click", function () {
      var cur = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
      applyTheme(cur);
    });
    var menuBtn = document.getElementById("menuBtn");
    menuBtn.addEventListener("click", function () {
      var sidebar = document.getElementById("sidebar");
      var open = sidebar.classList.toggle("open");
      menuBtn.setAttribute("aria-expanded", String(open));
    });
    document.getElementById("refreshBtn").addEventListener("click", function () { refresh(); });
    document.getElementById("pollSec").addEventListener("change", startPolling);
    var copyBtn = document.getElementById("copyDiagnosticsBtn");
    if (copyBtn) copyBtn.addEventListener("click", copyDiagnostics);
    // Keyboard: Escape closes the mobile sidebar; 'r' refreshes when not in an input.
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape") {
        var sidebar = document.getElementById("sidebar");
        if (sidebar.classList.contains("open")) {
          sidebar.classList.remove("open");
          menuBtn.setAttribute("aria-expanded", "false");
          menuBtn.focus();
        }
      } else if (ev.key === "r" && !ev.metaKey && !ev.ctrlKey) {
        var tag = (document.activeElement && document.activeElement.tagName) || "";
        if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
        refresh();
      }
    });
    window.addEventListener("hashchange", function () {
      state.section = sectionFromHash();
      setActive(state.section);
      refresh();
    });
    state.section = sectionFromHash();
    setActive(state.section);
    updateGlobalBadges();
    refresh();
    startPolling();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
