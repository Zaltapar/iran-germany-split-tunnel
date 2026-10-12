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
    detailHost: null
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

  function renderOverview(view) {
    return Promise.all([v2("/overview"), fetchSeries(["iran.up_mibps", "iran.down_mibps", "germany.up_mibps", "germany.down_mibps"], 120)]).then(function (res) {
      var d = res[0], series = res[1];
      clear(view);
      var c = d.counts || {};
      view.appendChild(metaNotice(d.meta));
      view.appendChild(el("div", { cls: "grid" }, [
        statCard("Hosts", c.hosts, (c.hostsStale || 0) + " stale · " + (c.hostsUnreachable || 0) + " unreachable"),
        statCard("Collectors missing", c.hostsCollectorMissing || 0, "hosts without a metrics source"),
        statCard("Carriers", c.carriers, (c.carriersEligible || 0) + " eligible"),
        statCard("Outbounds", c.outbounds, (c.outboundsEnabled || 0) + " enabled (config)"),
        statCard("Routing rules", c.routingRules, "mode: " + (d.routingMode || "—"))
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
      (d.notes || []).forEach(function (n) { view.appendChild(el("div", { cls: "notice", text: n })); });
    });
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
      view.appendChild(metaNotice(d.meta));
      var carriers = d.carriers || [];
      if (!carriers.length) {
        view.appendChild(missingNote("No carrier metrics are available. Carrier health appears only when a host exports multi-carrier metrics (multi-carrier enabled)."));
        return;
      }
      var rows = carriers.map(function (c) {
        return el("tr", null, [
          el("td", { text: c.serverId + " / " + c.carrier }),
          el("td", null, [badge(c.state || "unknown", stateTone(c.state))]),
          valueCell(c.score, function (v) { return fmtNum(v, 3); }),
          valueCell(c.goodputMiBps, function (v) { return fmtNum(v, 2); }),
          valueCell(c.successRatio, function (v) { return fmtNum(v, 3); }),
          valueCell(c.stallRatePer100MiB, function (v) { return fmtNum(v, 2); }),
          el("td", null, [c.eligible == null ? badge("—", "") : (c.eligible ? badge("eligible", "ok") : badge(c.gateReason || "excluded", "bad"))]),
          valueCell(c.cooldownRemainingSec, function (v) { return v + " s"; }),
          valueCell(c.probeBytesToday, function (v) { return fmtNum(v / 1048576, 1) + " MiB"; }),
          valueCell(c.lossEvents),
          valueCell(c.reconnects)
        ]);
      });
      view.appendChild(el("div", { cls: "table-wrap" }, [
        el("table", null, [
          el("thead", null, [el("tr", null, ["Carrier", "State", "Score", "Goodput MiB/s", "Success", "Stalls /100 MiB", "Eligibility", "Cooldown", "Probe today", "Losses", "Reconnects"].map(function (h) { return el("th", { text: h }); }))]),
          el("tbody", null, rows)
        ])
      ]));

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

  // ---- Routing (read-only; editing-ready schema) -----------------------------
  function renderRouting(view) {
    return Promise.all([v2("/routing"), v2("/schema/routing-policy")]).then(function (res) {
      var d = res[0], schema = res[1];
      clear(view);
      view.appendChild(el("div", { cls: "notice", text: "Routing settings shown here come from the dashboard configuration. Live routing state is not collected in this phase." }));
      if (!d.declared) {
        view.appendChild(missingNote("No routing policy is declared in the dashboard configuration; the default split mode applies."));
      }
      var fields = (schema.fields || []).map(function (f) {
        var current = d.policy ? d.policy[f.name] : undefined;
        var value = f.name === "rules" ? ((d.policy && d.policy.rules ? d.policy.rules.length : 0) + " rule(s)") : (current == null ? "—" : String(current));
        return el("div", { cls: "field-row" }, [
          el("div", { cls: "k", text: f.name + (f.required ? " *" : "") }),
          el("input", { readonly: "readonly", value: value }),
          el("button", { cls: "btn btn-disabled", type: "button", disabled: "disabled", title: "editing lands in the next phase", text: "Apply" })
        ]);
      });
      view.appendChild(el("div", { cls: "card" }, [el("h3", { text: "Routing policy" })].concat(fields)));
      if (d.errors && d.errors.length) view.appendChild(el("div", { cls: "notice bad", text: "Validation: " + d.errors.join("; ") }));
      var rules = (d.policy && d.policy.rules) || [];
      if (rules.length) {
        view.appendChild(el("div", { cls: "table-wrap" }, [
          el("table", null, [
            el("thead", null, [el("tr", null, ["ID", "Match", "Value", "Action", "Outbound"].map(function (h) { return el("th", { text: h }); }))]),
            el("tbody", null, rules.map(function (r) {
              return el("tr", null, [el("td", { text: r.id }), el("td", { text: r.match }), el("td", { text: r.value }), el("td", { text: r.action }), el("td", { text: r.outbound || "—" })]);
            }))
          ])
        ]));
      }
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
  function renderInbounds(view) {
    var prompts = C3_CONCEPTS.map(function (c) {
      return v2("/schema/" + c.concept).then(function (schema) {
        return { meta: c, schema: schema };
      });
    });
    return Promise.all(prompts).then(function (entries) {
      clear(view);
      view.appendChild(el("div", { cls: "notice", text: "Public inbound fields only. Keys are shown as a 12-hex fingerprint (keyRef) — key material is never displayed or accepted. A Germany-side edit stages a Blob B export for the Iran host and vice versa (peer change required; there is no coordinated apply)." }));
      entries.forEach(function (entry) {
        var schema = entry.schema;
        var concept = entry.meta;
        var editable = !!schema.editable;
        var head = el("h3", { text: concept.label + " — " + (schema.status || "read-only") });
        view.appendChild(el("div", { cls: "card" }, [head]));
        var rows = (schema.fields || []).map(function (f) {
          var isKey = f.name === "keyRef";
          return el("tr", null, [
            el("td", { text: f.name }),
            el("td", { text: f.type || "—" }),
            el("td", { text: f.required ? "yes" : "no" }),
            el("td", { text: isKey ? "fingerprint (key material never editable)" : (f.pattern || "—") })
          ]);
        });
        view.appendChild(el("div", { cls: "table-wrap" }, [
          el("table", null, [
            el("thead", null, [el("tr", null, ["Field", "Type", "Required", "Constraint"].map(function (h) { return el("th", { text: h }); }))]),
            el("tbody", null, rows)
          ])
        ]));
        if (editable) {
          // Flag ON: the working form + validate + diff + confirm + restart
          // countdown is still a stub in this phase. We render the affordance
          // and an explicit "deferred" notice rather than a half-wired form.
          view.appendChild(el("div", { cls: "notice" }, [
            el("button", {
              cls: "btn",
              text: "Edit inbounds",
              attrs: { disabled: "" }
            }),
            el("span", { cls: "muted small", text: " — validate + diff + confirm form is deferred; the flag gates the API plane but the in-browser form lands in a later phase." })
          ]));
        } else {
          view.appendChild(el("div", { cls: "notice" }, [
            el("button", {
              cls: "btn",
              text: "Edit",
              attrs: { disabled: "", title: schema.editDisabledReason || "editing lands in the next phase" }
            }),
            el("span", { cls: "muted small", text: " — " + (schema.editDisabledReason || "editing lands in the next phase") })
          ]));
        }
      });
    });
  }

  // ---- C4 control plane: routing + multi-carrier (read-only) ---------------------
  // Driven by the C4 public-field schemas. Both sections are READ-ONLY in this
  // build: the in-browser editing form is deferred (like C3), so the Edit
  // affordance is a disabled button whose tooltip names the per-capability
  // flag that gates the API plane. No CDN, CSP intact. The SOCKS allowlist
  // value is shown as a fingerprint (the agent redacts it); SNI / policy
  // values are operator config and shown in full.
  var C4_CONCEPTS = [
    { concept: "routing-plane", label: "Routing plane (C4)" },
    { concept: "multi-carrier-control", label: "Multi-carrier control (C4)" }
  ];
  function renderControl(view) {
    var prompts = C4_CONCEPTS.map(function (c) {
      return v2("/schema/" + c.concept).then(function (schema) {
        return { meta: c, schema: schema };
      });
    });
    return Promise.all(prompts).then(function (entries) {
      clear(view);
      view.appendChild(el("div", { cls: "notice", text: "Read-only C4 control plane. Routing (target-address policy + SOCKS source allowlist) and multi-carrier (master toggle, second carrier listener/dial + SNI, policy knobs) are shown. Editing is deferred in this build; the Edit button is disabled and its tooltip names the per-capability flag that must be enabled before the API plane is live. SNI and policy values are shown in full; the SOCKS allowlist is shown as a fingerprint." }));
      entries.forEach(function (entry) {
        var schema = entry.schema;
        var concept = entry.meta;
        var editable = !!schema.editable;
        var head = el("h3", { text: concept.label + " — " + (schema.status || "read-only") });
        var card = el("div", { cls: "card" }, [head]);
        var rows = (schema.fields || []).map(function (f) {
          return el("tr", null, [
            el("td", { text: f.name }),
            el("td", { text: f.type || "—" }),
            el("td", { text: f.required ? "yes" : "no" }),
            el("td", { text: (f.pattern || "—") })
          ]);
        });
        card.appendChild(el("div", { cls: "table-wrap" }, [
          el("table", null, [
            el("thead", null, [el("tr", null, ["Field", "Type", "Required", "Constraint"].map(function (h) { return el("th", { text: h }); }))]),
            el("tbody", null, rows)
          ])
        ]));
        // Flag-gated, disabled Edit affordance + tooltip (deferred editing form).
        var editBtn = el("button", { cls: "btn", text: "Edit", attrs: { disabled: "" } });
        if (!editable) {
          editBtn.setAttribute("title", schema.editDisabledReason || "editing lands in the next phase");
        }
        var noteText = editable
          ? " — the API plane is enabled, but the in-browser editing form is deferred to a later phase."
          : " — " + (schema.editDisabledReason || "editing lands in the next phase");
        card.appendChild(el("div", { cls: "notice" }, [
          editBtn,
          el("span", { cls: "muted small", text: noteText })
        ]));
        view.appendChild(card);
      });
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
  function refresh() {
    if (inFlight) return Promise.resolve();
    inFlight = true;
    var section = state.section;
    var view = document.querySelector('.view[data-view="' + section + '"]');
    var api = document.getElementById("apiStatus");
    return SECTIONS[section].render(view).then(function () {
      api.textContent = "API: ok";
      api.className = "small";
    }).catch(function (err) {
      clear(view);
      view.appendChild(el("div", { cls: "notice bad", text: "Could not load this section: " + (err && err.message ? err.message : "unknown error") + ". Check that the dashboard is reachable." }));
      api.textContent = "API: error";
      api.className = "small badge bad";
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
    document.getElementById("menuBtn").addEventListener("click", function () {
      document.getElementById("sidebar").classList.toggle("open");
    });
    document.getElementById("refreshBtn").addEventListener("click", function () { refresh(); });
    document.getElementById("pollSec").addEventListener("change", startPolling);
    window.addEventListener("hashchange", function () {
      state.section = sectionFromHash();
      setActive(state.section);
      refresh();
    });
    state.section = sectionFromHash();
    setActive(state.section);
    refresh();
    startPolling();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
