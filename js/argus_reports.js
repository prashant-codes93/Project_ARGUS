/* ARGUS Reports page (frontend prototype).

   ALL record data below is SAMPLE data, matching the other ARGUS prototype pages.
   The backend (app.py) only exposes GET /api/events, GET /api/incidents,
   GET /api/incidents/<id> and GET /api/scans for reading. There is no reports,
   alerts, detections, investigations, assets or risk-history API.
   This page makes NO network requests. Reports are generated here, in the
   browser, from the sample arrays and kept in memory (not saved).

   To connect real data later, replace the sample arrays (EVENTS, INCIDENTS, ...)
   with data fetched from the verified endpoints; the builders and exporters
   below do not need to change. */
"use strict";

/* =====================================================================
   1. SAMPLE DATA
   ===================================================================== */
const AS_OF = "2026-11-13";              // "today" for the sample data set
const AS_OF_TIME = "2026-11-13 10:05";
const SAMPLE_START = "2026-11-08";       // first day that has sample records
const REPORTER = "Rohan Kumar";
const SEVS = ["critical", "high", "medium", "low"];
// Same thresholds as the Risk Scoring and Assets pages.
const levelOf = s => s >= 75 ? "critical" : s >= 50 ? "high" : s >= 25 ? "medium" : "low";

// The three real rules from detection.py. `category` groups them for display only.
const RULES = {
  known_malicious_ip: { label: "Known Malicious IP Detected", category: "Threat intelligence match", guide: "Block the source and review recent connections of the targeted host." },
  brute_force_login:  { label: "Brute Force Login Attempt",   category: "Credential attack",         guide: "Lock affected accounts, reset passwords and confirm no login succeeded." },
  large_data_export:  { label: "Large Data Export",           category: "Data exfiltration",         guide: "Confirm the export with the data owner and check where the data was sent." }
};

// Same sample alerts as the Alerts page.
const ALERTS = [
  ["AL-1009", "large_data_export",  "medium", "10.0.0.30",     "svc_backup", "2026-11-11 10:20", "open",         "A-004"],
  ["AL-1008", "brute_force_login",  "high",   "10.0.0.20",     "admin",      "2026-11-11 10:00", "open",         "A-001"],
  ["AL-1007", "brute_force_login",  "high",   "45.83.64.1",    "root",       "2026-11-11 09:05", "acknowledged", "A-001"],
  ["AL-1006", "known_malicious_ip", "high",   "45.83.64.1",    "admin",      "2026-11-10 22:41", "resolved",     ""],
  ["AL-1005", "large_data_export",  "medium", "10.0.0.31",     "analyst1",   "2026-11-10 16:12", "acknowledged", "A-005"],
  ["AL-1004", "known_malicious_ip", "high",   "185.220.101.4", "unknown",    "2026-11-09 13:30", "open",         "A-003"],
  ["AL-1003", "brute_force_login",  "high",   "10.0.0.22",     "dev_user",   "2026-11-08 18:55", "resolved",     "A-002"]
].map(([id, rule, sev, ip, user, time, status, asset]) => ({ id, rule, name: RULES[rule].label, sev, ip, user, time, status, asset }));

// Same incident catalog as the Assets page. Level comes from the score.
const INCIDENTS = [
  ["INC-1", "Suspicious Malicious IP Activity",  84, "open",          "2026-11-09", "A-003", "known_malicious_ip"],
  ["INC-3", "Unusual Data Export",               69, "open",          "2026-11-11", "A-004", "large_data_export"],
  ["INC-4", "Brute Force Login Investigation",   82, "investigating", "2026-11-11", "A-001", "brute_force_login"],
  ["INC-5", "Forgotten Password Lockout",        34, "closed",        "2026-11-08", "A-002", "brute_force_login"]
].map(([id, title, score, status, time, asset, rule]) => ({ id, title, score, sev: levelOf(score), status, time, asset, rule }));

// Illustrative only: the Investigations page has no backend either.
const INVESTIGATIONS = [
  ["INV-101", "Malicious IP Activity Review",    "AL-1004", "high",   "Rohan Kumar", "2026-11-09", "in progress", "A-003"],
  ["INV-102", "Brute Force Login Investigation", "AL-1008", "high",   "Rohan Kumar", "2026-11-11", "open",        "A-001"],
  ["INV-103", "Data Export Review",              "AL-1009", "medium", "Unassigned",  "2026-11-11", "open",        "A-004"],
  ["INV-104", "Forgotten Password Lockout",      "AL-1003", "high",   "Rohan Kumar", "2026-11-08", "closed",      "A-002"]
].map(([id, title, alert, sev, analyst, time, status, asset]) => ({ id, title, alert, sev, analyst, time, status, asset }));

// Illustrative events. Time column is the full timestamp.
const EVENTS = [
  ["EV-4120", "data_export",        "critical", "10.0.0.30",     "2026-11-11 10:20", "open",          "A-004"],
  ["EV-4119", "failed_login",       "high",     "10.0.0.20",     "2026-11-11 10:00", "open",          "A-001"],
  ["EV-4118", "failed_login",       "high",     "45.83.64.1",    "2026-11-11 09:05", "investigating", "A-001"],
  ["EV-4117", "failed_login",       "medium",   "45.83.64.1",    "2026-11-11 09:03", "investigating", "A-001"],
  ["EV-4116", "login",              "low",      "10.0.0.22",     "2026-11-11 08:45", "closed",        "A-002"],
  ["EV-4110", "network_connection", "high",     "45.83.64.1",    "2026-11-10 22:41", "closed",        ""],
  ["EV-4104", "data_export",        "high",     "10.0.0.31",     "2026-11-10 16:12", "investigating", "A-005"],
  ["EV-4101", "login",              "low",      "10.0.0.31",     "2026-11-10 09:10", "closed",        "A-005"],
  ["EV-4095", "port_scan",          "medium",   "203.0.113.4",   "2026-11-09 15:02", "closed",        "A-006"],
  ["EV-4091", "network_connection", "high",     "185.220.101.4", "2026-11-09 13:30", "open",          "A-003"],
  ["EV-4085", "login",              "low",      "10.0.0.22",     "2026-11-09 08:55", "closed",        "A-002"],
  ["EV-4080", "failed_login",       "medium",   "10.0.0.22",     "2026-11-08 18:55", "closed",        "A-002"],
  ["EV-4078", "login",              "low",      "10.0.0.31",     "2026-11-08 09:00", "closed",        "A-005"],
  ["EV-4074", "dns_query",          "low",      "10.0.1.12",     "2026-11-08 08:15", "closed",        "A-007"]
].map(([id, type, sev, ip, time, status, asset]) => ({ id, type, sev, ip, time, status, asset }));

// Same first seven assets as the Assets page (risk values are illustrative there too).
const ASSETS = [
  ["A-001", "auth-server-01",    "Server",         "10.0.0.5",  "critical", "risk",    78],
  ["A-002", "hr-workstation-14", "Workstation",    "10.0.0.22", "low",      "secure",  18],
  ["A-003", "core-db-01",        "Database",       "10.0.0.8",  "critical", "risk",    81],
  ["A-004", "backup-service",    "Server",         "10.0.0.30", "high",     "warning", 52],
  ["A-005", "analyst-laptop-01", "Workstation",    "10.0.0.31", "medium",   "warning", 36],
  ["A-006", "edge-router-01",    "Network Device", "10.0.0.1",  "high",     "secure",  22],
  ["A-007", "app-cloud-vm",      "Cloud Resource", "10.0.1.12", "medium",   "secure",  15]
].map(([id, name, type, ip, crit, secStatus, risk]) => ({ id, name, type, ip, crit, secStatus, risk, sev: levelOf(risk) }));

/* =====================================================================
   2. CONSTANTS AND SMALL HELPERS
   ===================================================================== */
const TYPES = {
  overview:      { label: "Security Overview Report",  icon: "◉", desc: "One-page summary of events, threats, incidents, investigations and assets.", cover: "Events, alerts, incidents, investigations, assets", api: "Partial API", apiNote: "GET /api/events and /api/incidents exist" },
  threat:        { label: "Threat Detection Report",   icon: "~", desc: "Alerts raised by the three detection rules, with severity and trend.",        cover: "Alerts, detection rules",                          api: "Prototype",   apiNote: "No alerts API yet" },
  incident:      { label: "Incident Analysis Report",  icon: "△", desc: "Incident counts, severity, status and trend.",                                 cover: "Incidents",                                        api: "API exists",  apiNote: "GET /api/incidents" },
  investigation: { label: "Investigation Report",      icon: "⌕", desc: "Investigation workload by status, severity and analyst.",                      cover: "Investigations",                                   api: "Prototype",   apiNote: "No investigations API yet" },
  risk:          { label: "Risk Assessment Report",    icon: "◆", desc: "Risk distribution and the highest-risk incidents and assets.",                 cover: "Incident scores, asset risk",                      api: "Prototype",   apiNote: "No risk API yet" },
  asset:         { label: "Asset Security Report",     icon: "▤", desc: "Current asset inventory by security status, criticality and risk.",             cover: "Assets",                                           api: "Prototype",   apiNote: "No assets API yet" },
  event:         { label: "Event Activity Report",     icon: "▣", desc: "Collected events by severity, type, source IP and time.",                      cover: "Events",                                           api: "API exists",  apiNote: "GET /api/events (latest 200)" }
};
const ANALYTICS_TABS = ["overview", "threat", "incident", "risk"];
const STATUS_GROUP = { open: "open", acknowledged: "in progress", investigating: "in progress", "in progress": "in progress", resolved: "closed", closed: "closed" };
const FILTER_HINTS = {
  overview: "Date, severity and asset filters apply. The asset summary is a current inventory, so date and status filters are not applied to it.",
  asset: "Assets are a current inventory. Severity (risk level) and asset filters apply; date and status filters are ignored.",
  risk: "Date, severity, status and asset filters apply to incidents. Asset risk uses severity and asset filters only."
};

const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cap = s => s ? s[0].toUpperCase() + s.slice(1) : s;
const pad2 = n => String(n).padStart(2, "0");
const dayOf = s => s.slice(0, 10);
const nowStamp = () => { const d = new Date(); return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`; };
const shiftDay = (d, n) => { const t = new Date(d + "T00:00:00Z"); t.setUTCDate(t.getUTCDate() + n); return t.toISOString().slice(0, 10); };
const daysBetween = (a, b) => { const out = []; for (let d = a; d <= b && out.length < 400; d = shiftDay(d, 1)) out.push(d); return out; };
const periodRange = v => v === "all" ? { start: SAMPLE_START, end: AS_OF } : { start: shiftDay(AS_OF, -(Number(v) - 1)), end: AS_OF };
const assetName = id => { const a = ASSETS.find(x => x.id === id); return a ? a.name : "N/A"; };

/* =====================================================================
   3. REPORT BUILDERS (pure functions: config in, report body out)
   cfg = { type, start, end, sev, status, asset }
   body = { records, summary:[[label,value]], charts:[{title,kind,items}],
            tables:[{title,cols,rows}], findings:[], guidance:[], notes:[] }
   ===================================================================== */
function pick(list, c, skip = []) {
  return list.filter(r =>
    (skip.includes("date") || (dayOf(r.time) >= c.start && dayOf(r.time) <= c.end)) &&
    (!c.sev || r.sev === c.sev) &&
    (skip.includes("status") || !c.status || STATUS_GROUP[r.status] === c.status) &&
    (!c.asset || r.asset === c.asset));
}
const pickAssets = c => ASSETS.filter(a => (!c.asset || a.id === c.asset) && (!c.sev || a.sev === c.sev));

const tally = (list, keyFn) => { const m = new Map(); list.forEach(r => { const k = keyFn(r); m.set(k, (m.get(k) || 0) + 1); }); return m; };
const sevItems = (list, key = "sev") => SEVS.map(s => [cap(s), list.filter(r => r[key] === s).length, s]);
const topOf = (list, keyFn) => [...tally(list, keyFn)].sort((a, b) => b[1] - a[1])[0];
function trendItems(list, c) {
  const days = daysBetween(c.start > SAMPLE_START ? c.start : SAMPLE_START, c.end < AS_OF ? c.end : AS_OF);
  const m = tally(list, r => dayOf(r.time));
  return days.map(d => [d.slice(5), m.get(d) || 0]);
}
const ruleGuidance = list => [...new Set(list.filter(a => a.status !== "resolved" && a.status !== "closed").map(a => a.rule))]
  .map(k => `${RULES[k].label}: ${RULES[k].guide}`);

const TBL = {
  alerts: l => ({ title: "Alerts", cols: ["Alert ID", "Alert", "Rule", "Severity", "Source IP", "Status", "Time"], rows: l.map(a => [a.id, a.name, a.rule, a.sev, a.ip, a.status, a.time]) }),
  incidents: l => ({ title: "Incidents", cols: ["Incident ID", "Title", "Risk score", "Level", "Status", "Created", "Asset"], rows: l.map(i => [i.id, i.title, i.score, i.sev, i.status, dayOf(i.time), assetName(i.asset)]) }),
  investigations: l => ({ title: "Investigations", cols: ["Investigation ID", "Title", "Related alert", "Severity", "Analyst", "Created", "Status"], rows: l.map(i => [i.id, i.title, i.alert, i.sev, i.analyst, i.time, i.status]) }),
  events: l => ({ title: "Events", cols: ["Event ID", "Type", "Severity", "Source IP", "Status", "Time"], rows: l.map(e => [e.id, e.type, e.sev, e.ip, e.status, e.time]) }),
  assets: l => ({ title: "Assets", cols: ["Asset ID", "Name", "Type", "IP address", "Criticality", "Security", "Risk score", "Level"], rows: l.map(a => [a.id, a.name, a.type, a.ip, a.crit, a.secStatus, a.risk, a.sev]) })
};
const unresolved = l => l.filter(a => a.status !== "resolved" && a.status !== "closed");

const BUILDERS = {
  overview(c) {
    const ev = pick(EVENTS, c), al = pick(ALERTS, c), inc = pick(INCIDENTS, c), inv = pick(INVESTIGATIONS, c), as = pickAssets(c);
    const openInc = inc.filter(i => i.status !== "closed").length, atRisk = as.filter(a => a.secStatus === "risk");
    const findings = [`${unresolved(al).filter(a => a.sev === "high" || a.sev === "critical").length} high or critical alert(s) are not yet resolved.`, `${openInc} incident(s) are open or under investigation.`];
    const topRule = topOf(al, a => a.rule);
    if (topRule) findings.push(`Most active detection rule: ${RULES[topRule[0]].label} (${topRule[1]} alert(s)).`);
    if (atRisk.length) findings.push(`Assets with an At Risk security status: ${atRisk.map(a => a.name).join(", ")}.`);
    return {
      records: ev.length + al.length + inc.length + inv.length,
      summary: [["Total events", ev.length], ["Detected threats", al.length], ["Open incidents", openInc], ["Resolved incidents", inc.length - openInc], ["Investigations", inv.length], ["Assets at risk", atRisk.length]],
      charts: [{ title: "Alert severity distribution", kind: "bar", items: sevItems(al) }, { title: "Incident severity (by risk level)", kind: "bar", items: sevItems(inc) }, { title: "Events over time", kind: "line", items: trendItems(ev, c) }],
      tables: [TBL.incidents(inc), TBL.investigations(inv), TBL.assets(as)],
      findings, guidance: ruleGuidance(al),
      notes: ["Asset summary is a current inventory; date and status filters are not applied to it.", "Investigations and assets are illustrative sample records."]
    };
  },
  threat(c) {
    const al = pick(ALERTS, c), topRule = topOf(al, a => a.rule);
    const cats = [...tally(al, a => RULES[a.rule].category)].sort((a, b) => b[1] - a[1]);
    const findings = [`${unresolved(al).length} of ${al.length} alert(s) are unresolved.`];
    if (topRule) findings.push(`Most active detection rule: ${RULES[topRule[0]].label} (${topRule[1]} alert(s)).`);
    return {
      records: al.length,
      summary: [["Alerts", al.length], ["High or critical", al.filter(a => a.sev === "high" || a.sev === "critical").length], ["Rules that fired", new Set(al.map(a => a.rule)).size + " of 3"], ["Unresolved", unresolved(al).length]],
      charts: [
        { title: "Threats by severity", kind: "bar", items: sevItems(al) },
        { title: "Detection rule activity", kind: "bar", items: Object.keys(RULES).map(k => [RULES[k].label, al.filter(a => a.rule === k).length]) },
        { title: "Top threat categories", kind: "bar", items: cats },
        { title: "Threat trend", kind: "line", items: trendItems(al, c) }
      ],
      tables: [TBL.alerts(al)], findings, guidance: ruleGuidance(al),
      notes: ["detection.py currently emits only high and medium severities, so zero critical alerts is expected.", "Threat categories are a display grouping of the 3 existing rules. No rules are added."]
    };
  },
  incident(c) {
    const inc = pick(INCIDENTS, c), open = inc.filter(i => i.status !== "closed"), top = [...inc].sort((a, b) => b.score - a.score)[0];
    const findings = [`${open.length} of ${inc.length} incident(s) remain open or under investigation.`];
    if (top) findings.push(`Highest risk score: ${top.id} "${top.title}" at ${top.score} (${top.sev}).`);
    return {
      records: inc.length,
      summary: [["Total incidents", inc.length], ["Open incidents", open.length], ["Resolved incidents", inc.length - open.length], ["Critical incidents", inc.filter(i => i.sev === "critical").length]],
      charts: [
        { title: "Incident severity (by risk level)", kind: "bar", items: sevItems(inc) },
        { title: "Incident status", kind: "bar", items: [["Open", inc.filter(i => i.status === "open").length], ["Investigating", inc.filter(i => i.status === "investigating").length], ["Closed", inc.filter(i => i.status === "closed").length]] },
        { title: "Incidents created over time", kind: "line", items: trendItems(inc, c) }
      ],
      tables: [TBL.incidents(inc)], findings, guidance: ruleGuidance(open.map(i => ({ rule: i.rule, status: i.status }))),
      notes: ["Risk level uses the Risk Scoring page thresholds: 75 critical, 50 high, 25 medium."]
    };
  },
  investigation(c) {
    const inv = pick(INVESTIGATIONS, c), g = s => inv.filter(i => STATUS_GROUP[i.status] === s).length;
    return {
      records: inv.length,
      summary: [["Investigations", inv.length], ["Open", g("open")], ["In progress", g("in progress")], ["Closed", g("closed")]],
      charts: [{ title: "Investigations by status", kind: "bar", items: [["Open", g("open")], ["In progress", g("in progress")], ["Closed", g("closed")]] }, { title: "Investigations by severity", kind: "bar", items: sevItems(inv) }],
      tables: [TBL.investigations(inv)],
      findings: [`${inv.filter(i => i.analyst === "Unassigned" && i.status !== "closed").length} active investigation(s) have no assigned analyst.`],
      guidance: [], notes: ["Investigations are illustrative sample records. No investigations API exists yet."]
    };
  },
  risk(c) {
    const inc = pick(INCIDENTS, c), as = pickAssets(c);
    const topInc = [...inc].sort((a, b) => b.score - a.score), topAs = [...as].sort((a, b) => b.risk - a.risk);
    const avg = inc.length ? Math.round(inc.reduce((n, i) => n + i.score, 0) / inc.length) : 0;
    const cats = [...tally(inc, i => RULES[i.rule].category)].sort((a, b) => b[1] - a[1]);
    const findings = [`${inc.filter(i => i.sev === "critical" || i.sev === "high").length} incident(s) score high or critical.`];
    if (topInc[0]) findings.push(`Highest-risk incident: ${topInc[0].id} "${topInc[0].title}" (${topInc[0].score}).`);
    if (topAs[0]) findings.push(`Highest-risk asset: ${topAs[0].name} (${topAs[0].risk}).`);
    return {
      records: inc.length,
      summary: [["Incidents assessed", inc.length], ["Average score", avg], ["Highest score", topInc[0] ? topInc[0].score : 0], ["Assets at risk", as.filter(a => a.secStatus === "risk").length]],
      charts: [{ title: "Risk distribution (incidents)", kind: "bar", items: sevItems(inc) }, { title: "Risk category breakdown", kind: "bar", items: cats }, { title: "Asset risk distribution", kind: "bar", items: sevItems(as) }],
      tables: [
        { title: "Highest-risk incidents", cols: ["Incident ID", "Title", "Risk score", "Level", "Status"], rows: topInc.slice(0, 5).map(i => [i.id, i.title, i.score, i.sev, i.status]) },
        { title: "Highest-risk assets", cols: ["Asset ID", "Name", "Risk score", "Level", "Criticality"], rows: topAs.slice(0, 5).map(a => [a.id, a.name, a.risk, a.sev, a.crit]) }
      ],
      findings, guidance: [],
      notes: ["Scores are the sample values from the Risk Scoring and Assets pages. No new scoring algorithm is used.", "Risk trend is not shown: no historical risk scores are stored."]
    };
  },
  asset(c) {
    const as = pickAssets(c), n = s => as.filter(a => a.secStatus === s).length, top = [...as].sort((a, b) => b.risk - a.risk)[0];
    const avg = as.length ? Math.round(as.reduce((t, a) => t + a.risk, 0) / as.length) : 0;
    const findings = [`${n("risk")} asset(s) are At Risk and ${n("warning")} have a Warning status.`];
    if (top) findings.push(`Highest-risk asset: ${top.name} (${top.risk}).`);
    return {
      records: as.length,
      summary: [["Assets", as.length], ["At risk", n("risk")], ["Warning", n("warning")], ["Secure", n("secure")], ["Average risk score", avg]],
      charts: [
        { title: "Security status", kind: "bar", items: [["At risk", n("risk"), "critical"], ["Warning", n("warning"), "medium"], ["Secure", n("secure"), "low"]] },
        { title: "Business criticality", kind: "bar", items: SEVS.map(s => [cap(s), as.filter(a => a.crit === s).length, s]) },
        { title: "Risk level", kind: "bar", items: sevItems(as) }
      ],
      tables: [TBL.assets(as)], findings, guidance: [],
      notes: ["Assets are a current inventory; date and status filters are ignored.", "Asset records are illustrative sample data. No assets API exists yet."]
    };
  },
  event(c) {
    const ev = pick(EVENTS, c), type = topOf(ev, e => e.type), ip = topOf(ev, e => e.ip);
    const findings = [`${ev.filter(e => e.status === "open").length} event(s) are still open.`];
    if (type) findings.push(`Most common event type: ${type[0]} (${type[1]}).`);
    if (ip) findings.push(`Most active source IP: ${ip[0]} (${ip[1]} events).`);
    return {
      records: ev.length,
      summary: [["Total events", ev.length], ["High or critical", ev.filter(e => e.sev === "high" || e.sev === "critical").length], ["Open", ev.filter(e => e.status === "open").length], ["Source IPs", new Set(ev.map(e => e.ip)).size]],
      charts: [{ title: "Events by severity", kind: "bar", items: sevItems(ev) }, { title: "Events by type", kind: "bar", items: [...tally(ev, e => e.type)].sort((a, b) => b[1] - a[1]) }, { title: "Events over time", kind: "line", items: trendItems(ev, c) }],
      tables: [TBL.events(ev)], findings, guidance: [],
      notes: ["GET /api/events returns the latest 200 events for the signed-in user. This report uses sample events."]
    };
  }
};

/* =====================================================================
   4. RENDERING A REPORT BODY (used by analytics tabs and the preview)
   ===================================================================== */
function barChart(items) {
  const max = Math.max(0, ...items.map(i => i[1]));
  if (!items.length || max === 0) return '<p class="nodata">No data for this selection.</p>';
  return items.map(([l, v, cls]) => `<div class="brow"><span title="${esc(l)}">${esc(l)}</span><div class="bar"><i class="${esc(cls || "")}" data-w="${(v / max * 100).toFixed(1)}"></i></div><b>${v}</b></div>`).join("");
}
function lineChart(items) {
  if (!items.length) return '<p class="nodata">No data for this selection.</p>';
  const W = 400, H = 130, L = 26, R = 8, T = 10, B = 20, n = items.length, max = Math.max(1, ...items.map(i => i[1]));
  const x = i => n === 1 ? (W + L - R) / 2 : L + i / (n - 1) * (W - L - R);
  const y = v => H - B - v / max * (H - B - T);
  const pts = items.map((it, i) => `${x(i).toFixed(1)},${y(it[1]).toFixed(1)}`).join(" ");
  return `<svg class="line" viewBox="0 0 ${W} ${H}" role="img" aria-label="Trend, peak ${max}">
    <line class="ax" x1="${L}" y1="${H - B}" x2="${W - R}" y2="${H - B}"/>
    <text x="0" y="${T + 3}">${max}</text><text x="0" y="${H - B}">0</text>
    <polyline class="ln" points="${pts}"/>
    ${items.map((it, i) => `<circle class="dt" cx="${x(i).toFixed(1)}" cy="${y(it[1]).toFixed(1)}" r="3"><title>${esc(it[0])}: ${it[1]}</title></circle>`).join("")}
    <text x="${L}" y="${H - 4}">${esc(items[0][0])}</text><text x="${W - R}" y="${H - 4}" text-anchor="end">${esc(items[n - 1][0])}</text></svg>`;
}
function tableHtml(t) {
  const badge = (col, v) => (col === "Severity" || col === "Level") && SEVS.includes(v) ? `<span class="badge ${v}">${v.toUpperCase()}</span>` : esc(v);
  const head = t.cols.map(c => `<th>${esc(c)}</th>`).join("");
  const rows = t.rows.map(r => `<tr>${r.map((v, i) => `<td>${badge(t.cols[i], v)}</td>`).join("")}</tr>`).join("");
  return `<h3>${esc(t.title)}</h3>` + (t.rows.length
    ? `<div class="scroll"><table><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table></div>`
    : '<p class="nodata">No records for this selection.</p>');
}
function renderBody(b) {
  const list = (arr) => `<ul>${arr.map(f => `<li>${esc(f)}</li>`).join("")}</ul>`;
  return `<h3>Summary</h3><div class="kv">${b.summary.map(([l, v]) => `<div><b>${esc(v)}</b><span>${esc(l)}</span></div>`).join("")}</div>
    <h3>Charts</h3><div class="charts">${b.charts.map(ch => `<div class="chart"><h4>${esc(ch.title)}</h4>${ch.kind === "line" ? lineChart(ch.items) : barChart(ch.items)}</div>`).join("")}</div>
    ${b.tables.map(tableHtml).join("")}
    <h3>Key findings</h3>${list(b.findings)}
    ${b.guidance.length ? `<h3>Recommendations</h3><p class="guide-label">Analyst guidance by detection rule. Not generated by the ARGUS backend.</p>${list(b.guidance)}` : ""}
    ${b.notes.length ? `<p class="notes">${b.notes.map(esc).join("<br>")}</p>` : ""}`;
}
function hydrateBars(root) { root.querySelectorAll("[data-w]").forEach(el => { el.style.width = el.dataset.w + "%"; }); }

/* =====================================================================
   5. EXPORTERS (real files: PDF, CSV, JSON)
   ===================================================================== */
const rangeText = r => `${r.cfg.start} to ${r.cfg.end}`;
const filterText = c => [c.sev && "severity " + c.sev, c.status && "status " + c.status, c.asset && "asset " + c.asset].filter(Boolean).join(", ") || "none";
const SOURCE_TEXT = "Local prototype report built from sample data (not generated by the ARGUS backend)";

function csvCell(v) {
  let s = String(v ?? "");
  if (/^[=+\-@\t\r]/.test(s) && isNaN(Number(s))) s = "'" + s;   // block spreadsheet formula injection
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
function toCsv(r) {
  const b = r.body, rows = [
    ["ARGUS report"], ["Report ID", r.id], ["Name", r.name], ["Type", TYPES[r.type].label], ["Generated", r.generatedAt], ["Generated by", r.by],
    ["Period", rangeText(r)], ["Filters", filterText(r.cfg)], ["Source", SOURCE_TEXT], [], ["Summary"], ["Metric", "Value"], ...b.summary, []
  ];
  b.charts.forEach(ch => rows.push(["Chart: " + ch.title], ["Label", "Value"], ...ch.items.map(i => [i[0], i[1]]), []));
  b.tables.forEach(t => rows.push(["Table: " + t.title], t.cols, ...t.rows, []));
  rows.push(["Key findings"], ...b.findings.map(f => [f]), []);
  if (b.guidance.length) rows.push(["Analyst guidance (not generated by the backend)"], ...b.guidance.map(g => [g]), []);
  b.notes.forEach(n => rows.push(["Note", n]));
  return "\ufeff" + rows.map(row => row.map(csvCell).join(",")).join("\r\n");
}
function toJson(r) {
  const b = r.body;
  return JSON.stringify({
    report: { id: r.id, name: r.name, type: r.type, type_label: TYPES[r.type].label, generated_at: r.generatedAt, generated_by: r.by, period: { start: r.cfg.start, end: r.cfg.end }, filters: { severity: r.cfg.sev || null, status: r.cfg.status || null, asset: r.cfg.asset || null }, source: "local-prototype-sample-data" },
    summary: Object.fromEntries(b.summary),
    charts: b.charts.map(ch => ({ title: ch.title, kind: ch.kind, data: ch.items.map(i => ({ label: i[0], value: i[1] })) })),
    tables: b.tables.map(t => ({ title: t.title, columns: t.cols, rows: t.rows.map(row => Object.fromEntries(t.cols.map((c, i) => [c, row[i]]))) })),
    key_findings: b.findings, analyst_guidance: b.guidance, notes: b.notes
  }, null, 2);
}

// Minimal text-only PDF writer (no dependencies). Helvetica for prose, Courier for tables.
const pdfSafe = s => String(s).replace(/[–—]/g, "-").replace(/[·•]/g, "|").replace(/[‘’]/g, "'").replace(/[“”]/g, '"').replace(/→/g, "->").replace(/[^\x20-\x7e]/g, "?");
const pdfEsc = s => pdfSafe(s).replace(/([\\()])/g, "\\$1");
function wrapText(s, w) {
  const out = []; let line = "";
  for (const word of String(s).split(/\s+/)) {
    if ((line + " " + word).trim().length > w) { if (line) out.push(line); line = word; } else line = (line + " " + word).trim();
  }
  if (line) out.push(line);
  return out.length ? out : [""];
}
function textTable(cols, rows, width = 104) {
  const cells = rows.map(r => r.map(v => pdfSafe(v)));
  const w = cols.map((c, i) => Math.max(c.length, ...cells.map(r => r[i].length)));
  let total = w.reduce((a, b) => a + b, 0) + 2 * (cols.length - 1);
  while (total > width) { const i = w.indexOf(Math.max(...w)); if (w[i] <= 6) break; w[i]--; total--; }
  const fmt = r => r.map((v, i) => (v.length > w[i] ? v.slice(0, w[i] - 1) + "~" : v).padEnd(w[i])).join("  ").trimEnd();
  return [fmt(cols), "-".repeat(Math.min(total, width)), ...cells.map(fmt)];
}
function pdfItems(r) {
  const it = [], add = (t, f = 1, s = 10) => it.push({ t, f, s }), para = (t, f = 1, s = 10) => wrapText(t, 92).forEach(l => add(l, f, s));
  const b = r.body;
  add("ARGUS Security Report", 2, 16); para(r.name, 2, 12); add("", 1, 6);
  [["Report ID", r.id], ["Type", TYPES[r.type].label], ["Generated", `${r.generatedAt} by ${r.by}`], ["Period", rangeText(r)], ["Filters", filterText(r.cfg)]].forEach(([k, v]) => para(`${k}: ${v}`));
  para(SOURCE_TEXT, 1, 9); add("", 1, 8);
  add("Summary", 2, 12); b.summary.forEach(([l, v]) => add(`${l}: ${v}`)); add("", 1, 8);
  b.charts.forEach(ch => {
    add(ch.title, 2, 10);
    const max = Math.max(1, ...ch.items.map(i => i[1]));
    if (!ch.items.length) add("No data for this selection.", 1, 9);
    ch.items.forEach(i => add(`${pdfSafe(i[0]).padEnd(30).slice(0, 30)} ${"#".repeat(Math.round(i[1] / max * 30)).padEnd(30)} ${i[1]}`, 3, 8));
    add("", 1, 6);
  });
  b.tables.forEach(t => { add(t.title, 2, 12); if (!t.rows.length) add("No records for this selection.", 1, 9); else textTable(t.cols, t.rows).forEach(l => add(l, 3, 8)); add("", 1, 8); });
  add("Key findings", 2, 12); b.findings.forEach(f => para("- " + f));
  if (b.guidance.length) { add("", 1, 6); add("Recommendations (analyst guidance, not generated by the backend)", 2, 10); b.guidance.forEach(g => para("- " + g)); }
  if (b.notes.length) { add("", 1, 6); b.notes.forEach(n => para(n, 1, 8)); }
  return it;
}
function buildPdf(items) {
  const W = 595, H = 842, M = 40, pages = []; let cur, y;
  const newPage = () => { cur = []; pages.push(cur); y = H - M; };
  newPage();
  items.forEach(i => {
    const lead = i.s * 1.35;
    if (y - lead < M) newPage();
    y -= lead;
    if (i.t) cur.push(`BT /F${i.f} ${i.s} Tf ${M} ${y.toFixed(1)} Td (${pdfEsc(i.t)}) Tj ET`);
  });
  const objs = [];
  objs[1] = "<< /Type /Catalog /Pages 2 0 R >>";
  objs[2] = `<< /Type /Pages /Kids [${pages.map((_, i) => `${6 + i * 2} 0 R`).join(" ")}] /Count ${pages.length} >>`;
  objs[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>";
  objs[4] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>";
  objs[5] = "<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>";
  pages.forEach((c, i) => {
    const pid = 6 + i * 2, stream = c.join("\n");
    objs[pid] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${W} ${H}] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents ${pid + 1} 0 R >>`;
    objs[pid + 1] = `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`;
  });
  let out = "%PDF-1.4\n"; const offs = [];
  for (let i = 1; i < objs.length; i++) { offs[i] = out.length; out += `${i} 0 obj\n${objs[i]}\nendobj\n`; }
  const xref = out.length;
  out += `xref\n0 ${objs.length}\n0000000000 65535 f \n` + offs.slice(1).map(o => String(o).padStart(10, "0") + " 00000 n \n").join("") +
    `trailer\n<< /Size ${objs.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return new Blob([out], { type: "application/pdf" });
}
const slug = s => String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "report";
function makeFile(r) {
  const name = `${r.id}_${slug(r.name)}.${r.format}`;
  if (r.format === "pdf") return { name, blob: buildPdf(pdfItems(r)) };
  if (r.format === "csv") return { name, blob: new Blob([toCsv(r)], { type: "text/csv;charset=utf-8" }) };
  if (r.format === "json") return { name, blob: new Blob([toJson(r)], { type: "application/json" }) };
  throw new Error("Unsupported format: " + r.format);
}
function saveBlob(blob, name) {
  const url = URL.createObjectURL(blob), a = document.createElement("a");
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/* =====================================================================
   6. GENERATED REPORTS (in-memory store)
   ===================================================================== */
const PS = 6;
let REPORTS = [], nextNum = 1001, page = 1, tab = "overview", pendingDelete = null, toastTimer = null;

function createReport(cfg, name, format, generatedAt) {
  return { id: "RPT-" + nextNum++, name, type: cfg.type, cfg, format, by: REPORTER, generatedAt, status: "processing", error: "", body: null, file: null };
}
// Builds the data and the real file. Marks the report completed only when both succeed.
function finishReport(r) {
  try {
    const body = BUILDERS[r.type](r.cfg);
    if (!body.records) { r.status = "failed"; r.error = "No records match the selected filters and date range."; return; }
    r.body = body; r.file = makeFile(r); r.status = "completed"; r.error = "";
  } catch (err) {
    console.error(err);
    r.status = "failed"; r.error = "The report could not be built: " + err.message;
  }
}
function seedReports() {
  const base = { sev: "", status: "", asset: "" };
  [
    [{ type: "overview", ...periodRange("7") },  "Weekly Security Overview", "pdf",  "2026-11-13 09:00"],
    [{ type: "threat", start: "2026-11-01", end: AS_OF }, "Threat Detection - November", "csv", "2026-11-12 17:30"],
    [{ type: "incident", start: "2026-11-01", end: AS_OF }, "Incident Analysis - November", "json", "2026-11-12 11:15"],
    [{ type: "risk", ...periodRange("7"), sev: "critical" }, "Critical Risk Assessment", "pdf", "2026-11-11 16:40"],
    [{ type: "event", start: "2026-11-12", end: AS_OF }, "Event Activity - Last 24h", "csv", "2026-11-13 08:10"],
    [{ type: "asset", ...periodRange("all") }, "Asset Security Snapshot", "pdf", "2026-11-10 10:00"]
  ].forEach(([cfg, name, fmt, at]) => { const r = createReport({ ...base, ...cfg }, name, fmt, at); finishReport(r); REPORTS.push(r); });
  REPORTS.sort((a, b) => b.generatedAt.localeCompare(a.generatedAt));
}

function filteredReports() {
  const q = $("q").value.trim().toLowerCase(), t = $("ft").value, st = $("fst").value, d = $("fd").value;
  return REPORTS.filter(r =>
    (!t || r.type === t) && (!st || r.status === st) && (!d || r.generatedAt.startsWith(d)) &&
    (!q || [r.id, r.name, TYPES[r.type].label].join(" ").toLowerCase().includes(q)));
}
function renderTable() {
  const L = filteredReports(), pages = Math.max(1, Math.ceil(L.length / PS));
  page = Math.min(page, pages);
  $("rows").innerHTML = L.slice((page - 1) * PS, page * PS).map(r => `
    <tr data-id="${esc(r.id)}">
      <td class="mono">${esc(r.id)}</td><td class="ev">${esc(r.name)}</td><td>${esc(TYPES[r.type].label)}</td>
      <td class="mono">${esc(r.generatedAt)}</td><td class="rng">${esc(rangeText(r))}</td><td>${esc(r.by)}</td><td>${r.format.toUpperCase()}</td>
      <td class="st-${r.status}">${cap(r.status)}</td>
      <td class="act">
        <button data-a="view" ${r.status === "processing" ? "disabled" : ""}>View</button>
        <button data-a="dl" ${r.status !== "completed" ? "disabled" : ""}>Download</button>
        <button data-a="del" ${r.status === "processing" ? "disabled" : ""}>Delete</button>
      </td>
    </tr>`).join("");
  $("none").hidden = L.length > 0;
  $("cnt").textContent = L.length + (L.length === 1 ? " report" : " reports");
  $("pn").textContent = page + " / " + pages;
  $("prev").disabled = page <= 1; $("next").disabled = page >= pages;
}

function currentCfg(type) { const p = periodRange($("period").value); return { type, start: p.start, end: p.end, sev: "", status: "", asset: "" }; }
function renderStats() {
  const c = currentCfg("overview"), al = pick(ALERTS, c), inc = pick(INCIDENTS, c);
  const cards = [[REPORTS.length, "Total Reports", ""], [pick(EVENTS, c).length, "Security Events", ""], [al.length, "Detected Threats", "c-high"],
    [inc.filter(i => i.status !== "closed").length, "Open Incidents", "c-medium"], [al.filter(a => a.sev === "critical").length, "Critical Alerts", "c-critical"]];
  $("stats").innerHTML = cards.map(x => `<div class="stat"><b class="${x[2]}">${x[0]}</b><span>${x[1]}</span></div>`).join("");
}
function renderCategories() {
  $("cats").innerHTML = Object.entries(TYPES).map(([k, t]) => `
    <article class="cat">
      <div class="cat-h"><span class="cat-ic" aria-hidden="true">${t.icon}</span><h3>${esc(t.label)}</h3></div>
      <p>${esc(t.desc)}</p>
      <div class="cov">Coverage: ${esc(t.cover)}</div>
      <div class="tag-row"><span class="tag">Sample data</span><span class="tag ${t.api === "API exists" ? "api" : ""}" title="${esc(t.apiNote)}">${esc(t.api)}</span></div>
      <button data-type="${k}">Generate Report</button>
    </article>`).join("");
}
function renderTabs() {
  $("tabs").innerHTML = ANALYTICS_TABS.map(k => `<button role="tab" id="tab-${k}" data-tab="${k}" aria-selected="${k === tab}" aria-controls="an">${esc(TYPES[k].label.replace(" Report", ""))}</button>`).join("");
}
function renderAnalytics() {
  const body = BUILDERS[tab](currentCfg(tab));
  $("an").setAttribute("aria-labelledby", "tab-" + tab);
  $("an").innerHTML = body.records ? renderBody(body) : '<p class="nodata">No records in this period. Choose a longer report period.</p>';
  hydrateBars($("an"));
}
function renderAll() { renderStats(); renderTabs(); renderAnalytics(); renderTable(); }

function toast(msg, isErr) {
  const t = $("toast"); t.textContent = msg; t.className = "toast" + (isErr ? " err" : ""); t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, 5000);
}

/* =====================================================================
   7. PREVIEW, GENERATE, DELETE
   ===================================================================== */
function openPreview(id) {
  const r = REPORTS.find(x => x.id === id); if (!r) return;
  const dlBtn = r.file ? '<button class="pri" id="pv-dl">Download ' + r.format.toUpperCase() + "</button>" : "";
  $("pv").setAttribute("aria-labelledby", "pv-t");
  $("pv").innerHTML = `
    <div class="pv-head"><div><h2 id="pv-t">${esc(r.name)}</h2><span class="st-${r.status}">${cap(r.status)}</span></div><button id="pv-x" aria-label="Close preview">✕</button></div>
    <dl class="pv-meta">
      <dt>Report ID</dt><dd class="mono">${esc(r.id)}</dd><dt>Type</dt><dd>${esc(TYPES[r.type].label)}</dd>
      <dt>Generated</dt><dd class="mono">${esc(r.generatedAt)} by ${esc(r.by)}</dd><dt>Reporting period</dt><dd class="mono">${esc(rangeText(r))}</dd>
      <dt>Filters</dt><dd>${esc(filterText(r.cfg))}</dd><dt>Source</dt><dd>${esc(SOURCE_TEXT)}</dd>
    </dl>
    <div class="rt">${r.status === "failed" ? `<p class="pv-fail" role="alert">This report failed. ${esc(r.error)}</p>` : renderBody(r.body)}</div>
    <div class="acts">${dlBtn}<button id="pv-c">Close</button></div>`;
  hydrateBars($("pv"));
  $("pv-x").onclick = $("pv-c").onclick = () => $("pv").close();
  if (r.file) $("pv-dl").onclick = () => saveBlob(r.file.blob, r.file.name);
  $("pv").showModal();
}

function setRange(v) {
  if (v === "custom") return;
  const p = periodRange(v); $("g-start").value = p.start; $("g-end").value = p.end;
}
function updateHint() { $("g-hint").textContent = FILTER_HINTS[$("g-type").value] || "Date, severity, status and asset filters apply."; }
function openGenerate(type) {
  $("g-type").value = type || "overview";
  $("g-name").value = `${TYPES[$("g-type").value].label} ${AS_OF}`;
  $("g-fmt").value = "pdf"; $("g-range").value = $("period").value; setRange($("g-range").value);
  $("g-sev").value = ""; $("g-status").value = ""; $("g-asset").value = "";
  $("g-err").textContent = ""; updateHint(); $("gs").disabled = false;
  $("gd").showModal(); $("g-name").focus(); $("g-name").select();
}
function readForm() {
  return { name: $("g-name").value.trim(), format: $("g-fmt").value, cfg: { type: $("g-type").value, start: $("g-start").value, end: $("g-end").value, sev: $("g-sev").value, status: $("g-status").value, asset: $("g-asset").value } };
}
function validate(f) {
  if (f.name.length < 3 || f.name.length > 80) return "Enter a report name between 3 and 80 characters.";
  if (!TYPES[f.cfg.type]) return "Choose a report type.";
  if (!["pdf", "csv", "json"].includes(f.format)) return "Choose an output format.";
  if (!f.cfg.start || !f.cfg.end) return "Enter both a start date and an end date.";
  if (f.cfg.start > f.cfg.end) return "The start date must be on or before the end date.";
  if (daysBetween(f.cfg.start, f.cfg.end).length > 366) return "Choose a date range of 366 days or less.";
  return "";
}
function submitGenerate(e) {
  e.preventDefault();
  const f = readForm(), err = validate(f);
  $("g-err").textContent = err;
  if (err) return;
  const r = createReport(f.cfg, f.name, f.format, nowStamp());
  REPORTS.unshift(r); page = 1;
  ["q", "ft", "fst", "fd"].forEach(id => { $(id).value = ""; });
  $("gd").close(); renderAll();
  setTimeout(() => {       // short processing state; the build itself is synchronous
    finishReport(r); renderAll();
    if (r.status === "completed") toast(`${r.id} generated as a local prototype report. Use Download to save the ${r.format.toUpperCase()} file.`);
    else toast(`${r.id} failed. ${r.error}`, true);
  }, 350);
}
function askDelete(id) {
  const r = REPORTS.find(x => x.id === id); if (!r) return;
  pendingDelete = id;
  $("cf-msg").textContent = `${r.id} "${r.name}" and its file will be removed from this page. This cannot be undone.`;
  $("cf").showModal();
}

/* =====================================================================
   8. EVENTS AND START-UP
   ===================================================================== */
function init() {
  Object.entries(TYPES).forEach(([k, t]) => { $("ft").add(new Option(t.label, k)); $("g-type").add(new Option(t.label, k)); });
  $("g-asset").add(new Option("All assets", ""));
  ASSETS.forEach(a => $("g-asset").add(new Option(`${a.id} · ${a.name}`, a.id)));
  $("asof").textContent = `Data as of ${AS_OF_TIME}.`;
  seedReports(); renderCategories(); renderAll();

  $("period").onchange = () => { renderStats(); renderAnalytics(); };
  $("tabs").onclick = e => { const b = e.target.closest("[data-tab]"); if (b) { tab = b.dataset.tab; renderTabs(); renderAnalytics(); } };
  $("cats").onclick = e => { const b = e.target.closest("[data-type]"); if (b) openGenerate(b.dataset.type); };
  $("genBtn").onclick = () => openGenerate();
  $("exp").onclick = () => {
    const cfg = currentCfg(tab), body = BUILDERS[tab](cfg);
    const r = { id: "VIEW", name: TYPES[tab].label + " (analytics view)", type: tab, cfg, by: REPORTER, generatedAt: nowStamp(), body };
    try { saveBlob(new Blob([toCsv(r)], { type: "text/csv;charset=utf-8" }), `argus_${tab}_view_${cfg.start}_${cfg.end}.csv`); }
    catch (err) { toast("Export failed: " + err.message, true); }
  };

  ["q", "ft", "fst", "fd"].forEach(id => { $(id).oninput = () => { page = 1; renderTable(); }; });
  $("clr").onclick = () => { ["q", "ft", "fst", "fd"].forEach(id => { $(id).value = ""; }); page = 1; renderTable(); };
  $("prev").onclick = () => { page--; renderTable(); };
  $("next").onclick = () => { page++; renderTable(); };
  $("rows").onclick = e => {
    const b = e.target.closest("button[data-a]"); if (!b || b.disabled) return;
    const id = b.closest("tr").dataset.id, r = REPORTS.find(x => x.id === id);
    if (b.dataset.a === "view") openPreview(id);
    else if (b.dataset.a === "dl" && r && r.file) saveBlob(r.file.blob, r.file.name);
    else if (b.dataset.a === "del") askDelete(id);
  };

  $("gf").onsubmit = submitGenerate;
  $("gc").onclick = () => $("gd").close();
  $("g-type").onchange = updateHint;
  $("g-range").onchange = () => setRange($("g-range").value);
  ["g-start", "g-end"].forEach(id => { $(id).oninput = () => { $("g-range").value = "custom"; }; });

  $("cf-no").onclick = () => { pendingDelete = null; $("cf").close(); };
  $("cf-yes").onclick = () => {
    const r = REPORTS.find(x => x.id === pendingDelete);
    REPORTS = REPORTS.filter(x => x.id !== pendingDelete); pendingDelete = null; $("cf").close();
    renderAll(); if (r) toast(`${r.id} deleted.`);
  };
}
init();