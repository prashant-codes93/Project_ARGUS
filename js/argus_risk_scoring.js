/* ARGUS Risk Scoring page (frontend prototype).
   ALL data is SAMPLE data. Scores are computed in the browser from the
   illustrative weights below. The real ARGUS backend scoring
   (score_incident in detection_engine/risk.py) was NOT inspected and is
   NOT used here. Later, replace INCIDENTS with data from GET /api/incidents. */

// Proposed factors. Weights are illustrative and must sum to 100.
const FACTORS = [
  { key:"sev",  name:"Threat Severity",      w:25, info:"How dangerous the detected activity is." },
  { key:"conf", name:"Detection Confidence", w:15, info:"Confidence that the activity is a genuine threat." },
  { key:"asset",name:"Asset Criticality",    w:20, info:"Importance of the affected system." },
  { key:"freq", name:"Threat Frequency",     w:15, info:"How often the suspicious activity repeats." },
  { key:"imp",  name:"Potential Impact",     w:15, info:"Possible consequences (access, data exposure)." },
  { key:"exp",  name:"Threat Exposure",      w:10, info:"How exposed the asset or service is." }
];

// Thresholds used everywhere on this page (0-100).
const levelOf = s => s >= 75 ? "critical" : s >= 50 ? "high" : s >= 25 ? "medium" : "low";
const PRIORITY = { critical:"P1 · Immediate", high:"P2 · Today", medium:"P3 · This week", low:"P4 · Monitor" };

const ACTIONS = {
  critical:["Prioritize immediate investigation.","Verify affected assets.","Review associated alerts and events.","Consider containment after analyst verification."],
  high:["Investigate suspicious activity.","Review related authentication and network logs.","Verify affected accounts."],
  medium:["Review suspicious event patterns.","Monitor affected assets.","Validate whether the activity was authorized."],
  low:["Continue monitoring.","Review if additional suspicious activity occurs."]
};

// f = factor values 0-100 in FACTORS order; hist = earlier [time, score] points.
const INCIDENTS = [
 { id:"INC-1", title:"Suspicious Malicious IP Activity", alert:"AL-1004", cat:"Malicious IP", asset:"10.0.0.8", at:"2026-11-11 10:30", inv:"In Progress", ver:"sample-v1",
   alerts:["AL-1004"], events:["EV-4091"], f:[85,90,90,60,85,90], hist:[["09:00",35],["09:45",58],["10:10",72]],
   desc:"Inbound traffic from an address on the threat-intelligence list reached an internal host.",
   why:"Known malicious source, high asset value and direct exposure drive this score." },
 { id:"INC-2", title:"Malicious IP Followed by Root Logins", alert:"AL-1006", cat:"Malicious IP", asset:"10.0.0.5", at:"2026-11-10 23:00", inv:"Resolved", ver:"sample-v1",
   alerts:["AL-1006","AL-1007"], events:["EV-4110","EV-4118"], f:[80,85,60,40,70,70], hist:[["22:45",40],["22:55",61]],
   desc:"A malicious IP match and root login failures came from the same external address.",
   why:"High severity and confidence; frequency is moderate and the source was blocked." },
 { id:"INC-3", title:"Unusual Data Export", alert:"AL-1009", cat:"Data Export", asset:"10.0.0.30", at:"2026-11-11 10:25", inv:"Open", ver:"sample-v1",
   alerts:["AL-1009","AL-1008"], events:["EV-4120","EV-4119"], f:[60,70,80,75,70,60], hist:[["10:00",45],["10:15",58]],
   desc:"A critical-severity export from a backup account followed repeated admin login failures.",
   why:"Asset criticality and repeat activity raise the score; severity is medium." },
 { id:"INC-4", title:"Brute Force Login Investigation", alert:"AL-1007", cat:"Brute Force", asset:"10.0.0.5", at:"2026-11-11 09:10", inv:"In Progress", ver:"sample-v1",
   alerts:["AL-1007","AL-1008"], events:["EV-4118","EV-4119"], f:[75,80,85,90,80,85], hist:[["08:30",35],["09:00",63]],
   desc:"Many failed logins for root and admin from external and internal addresses.",
   why:"Very high frequency against a critical, exposed authentication host." },
 { id:"INC-5", title:"Forgotten Password Lockout", alert:"AL-1003", cat:"Brute Force", asset:"10.0.0.22", at:"2026-11-08 19:00", inv:"Resolved", ver:"sample-v1",
   alerts:["AL-1003"], events:["EV-4080"], f:[30,40,35,45,25,25], hist:[["18:50",41]],
   desc:"Five failed logins from a regular user, confirmed as a forgotten password.",
   why:"Low confidence and low-value asset; score fell once the user confirmed." },
 { id:"INC-6", title:"Repeated Authentication Failures", alert:"AL-1008", cat:"Brute Force", asset:"10.0.0.5", at:"2026-11-11 10:05", inv:"Open", ver:"sample-v1",
   alerts:["AL-1008"], events:["EV-4119"], f:[50,60,50,70,50,40], hist:[["09:30",30],["09:50",44]],
   desc:"Repeated failures for the admin account within five minutes.",
   why:"Frequency is the main contributor; asset and exposure are moderate." },
 { id:"INC-7", title:"Low-Volume Export Review", alert:"AL-1005", cat:"Data Export", asset:"10.0.0.31", at:"2026-11-10 16:30", inv:"Not started", ver:"sample-v1",
   alerts:["AL-1005"], events:["EV-4104"], f:[20,30,20,15,15,20], hist:[["16:15",24]],
   desc:"A single export flagged by the detection rule.",
   why:"Single occurrence on a standard asset keeps all factors low." },
 { id:"INC-8", title:"Analyst Account Data Export", alert:"AL-1005", cat:"Data Export", asset:"10.0.0.31", at:"2026-11-10 17:00", inv:"Open", ver:"sample-v1",
   alerts:["AL-1005"], events:["EV-4104"], f:[45,50,45,35,45,30], hist:[["16:20",28],["16:40",36]],
   desc:"Export to an external address by an analyst account, awaiting approval check.",
   why:"Moderate severity and impact; destination is unverified." }
];

// Score = sum(value * weight / 100), rounded, kept in 0-100.
const scoreOf = i => Math.max(0, Math.min(100, Math.round(FACTORS.reduce((s, x, n) => s + i.f[n] * x.w / 100, 0))));
INCIDENTS.forEach(i => {
  i.score = scoreOf(i);
  i.history = i.hist.map(h => [h[0], h[1]]).concat([[i.at.slice(11), i.score]]);
  i.prev = i.hist[i.hist.length - 1][1];
});

const $ = id => document.getElementById(id);
const cap = s => s[0].toUpperCase() + s.slice(1);
const LEVELS = ["critical","high","medium","low"];
let selected = null;

function getFiltered() {
  const q = $("q").value.toLowerCase(), lv = $("fl").value, cat = $("fc").value, day = $("fd").value;
  const min = $("fmin").value === "" ? 0 : +$("fmin").value, max = $("fmax").value === "" ? 100 : +$("fmax").value;
  const list = INCIDENTS.filter(i =>
    (!lv || levelOf(i.score) === lv) && (!cat || i.cat === cat) && (!day || i.at.startsWith(day)) &&
    i.score >= min && i.score <= max && (!q || (i.id + " " + i.title).toLowerCase().includes(q)));
  const s = $("fsort").value;
  return list.sort((a, b) => s === "low" ? a.score - b.score : s === "new" ? b.at.localeCompare(a.at) : b.score - a.score);
}

function renderStats() {
  const n = l => INCIDENTS.filter(i => levelOf(i.score) === l).length;
  const cards = [[INCIDENTS.length,"Total Assessed Incidents",""],[n("critical"),"Critical Risk","lv-critical"],[n("high"),"High Risk","lv-high"],[n("medium"),"Medium Risk","lv-medium"],[n("low"),"Low Risk","lv-low"]];
  $("stats").innerHTML = cards.map(c => `<div class="stat"><b class="${c[2]}">${c[0]}</b><span>${c[1]}</span></div>`).join("");
}

function renderOverview() {
  const scores = INCIDENTS.map(i => i.score), top = INCIDENTS.reduce((a, b) => b.score > a.score ? b : a);
  const avg = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
  const overall = Math.round(0.5 * top.score + 0.5 * avg), lv = levelOf(overall), last = INCIDENTS.map(i => i.at).sort().pop();
  const C = 2 * Math.PI * 54;
  $("gauge").innerHTML = `<svg viewBox="0 0 140 140" aria-hidden="true"><circle cx="70" cy="70" r="54" fill="none" stroke="#e8ecf3" stroke-width="14"/><circle cx="70" cy="70" r="54" fill="none" stroke="var(--r-${lv})" stroke-width="14" stroke-linecap="round" stroke-dasharray="${C * overall / 100} ${C}"/></svg><div class="gv" role="img" aria-label="Overall risk ${overall} of 100"><span class="lv-${lv}">${overall}</span><small>/ 100</small></div>`;
  $("ovDl").innerHTML = `<dt>Risk level</dt><dd class="lv-${lv}">${cap(lv)}</dd><dt>Assessed incidents</dt><dd>${INCIDENTS.length}</dd><dt>Highest risk</dt><dd>${top.id} (${top.score})</dd><dt>Average score</dt><dd>${avg}</dd><dt>Assessment time</dt><dd class="mono">${last}</dd>`;
  $("method").textContent = "Sample method only: overall = 50% highest incident score + 50% average incident score. A real method must be defined and approved before backend implementation.";
  $("hStatus").textContent = cap(lv); $("hStatus").className = "lv-" + lv; $("hLast").textContent = last;
}

function renderDist(list) {
  $("dist").innerHTML = LEVELS.map(l => {
    const c = list.filter(i => levelOf(i.score) === l).length, p = list.length ? Math.round(c * 100 / list.length) : 0;
    return `<div class="dist-row"><span class="lv-${l}">${cap(l)}</span><div class="bar"><i class="bg-${l}" style="width:${p}%"></i></div><span>${c} · ${p}%</span></div>`;
  }).join("");
}

function renderTop() {
  const top = INCIDENTS.slice().sort((a, b) => b.score - a.score).slice(0, 5);
  $("top").innerHTML = top.map(i => { const l = levelOf(i.score);
    return `<li data-id="${i.id}" tabindex="0"><span><b class="mono">${i.id}</b> ${i.title}</span><span><span class="badge rk-${l}">${i.score} · ${l.toUpperCase()}</span></span><small>${i.asset} · ${PRIORITY[l]}</small></li>`; }).join("");
}

function renderFactors() {
  $("factors").innerHTML = FACTORS.map(f => `<div class="fct"><div class="top"><b>${f.name}</b><span class="mono">weight ${f.w}%</span></div><small>${f.info}</small></div>`).join("") +
    `<p class="note small">Proposed model. Not confirmed as implemented in the ARGUS backend.</p>`;
}

function render() {
  const list = getFiltered();
  $("rows").innerHTML = list.map(i => { const l = levelOf(i.score);
    return `<tr tabindex="0" data-id="${i.id}" class="${selected === i.id ? "sel" : ""}"><td class="mono">${i.id}</td><td class="ev">${i.title}</td><td class="mono">${i.alert}</td><td>${i.cat}</td><td class="score mono lv-${l}">${i.score}</td><td><span class="badge rk-${l}">${l.toUpperCase()}</span></td><td class="mono">${i.asset}</td><td class="mono">${i.at}</td><td><button data-id="${i.id}">View Details</button></td></tr>`; }).join("");
  $("none").hidden = list.length > 0;
  $("cnt").textContent = list.length + " incidents";
  renderDist(list);
}

function lineChart(h) {
  const W = 300, H = 120, p = 20, step = h.length > 1 ? (W - 2 * p) / (h.length - 1) : 0;
  const pts = h.map((x, n) => [p + n * step, H - p - x[1] * (H - 2 * p) / 100]);
  return `<svg class="hist" viewBox="0 0 ${W} ${H}" role="img" aria-label="Risk score history"><polyline fill="none" stroke="var(--acc)" stroke-width="2" points="${pts.map(q => q.join(",")).join(" ")}"/>${pts.map((q, n) => `<circle cx="${q[0]}" cy="${q[1]}" r="3.5" fill="var(--acc)"/><text x="${q[0]}" y="${q[1] - 7}" font-size="9" text-anchor="middle" fill="currentColor">${h[n][1]}</text>`).join("")}</svg>`;
}

function openDrawer(id, msg) {
  const i = INCIDENTS.find(x => x.id === id), l = levelOf(i.score), d = i.score - i.prev;
  selected = id;
  const hist = i.history.map((h, n) => n === 0 ? null : `<tr><td class="mono">${h[0]}</td><td>${i.history[n - 1][1]}</td><td>${h[1]}</td><td>${h[1] - i.history[n - 1][1] >= 0 ? "+" : ""}${h[1] - i.history[n - 1][1]}</td></tr>`).filter(Boolean).join("");
  $("dr").innerHTML = `
    <button class="x" id="cl" aria-label="Close details">✕</button>
    <span class="badge rk-${l}">${l.toUpperCase()}</span>
    <h2>${i.title}</h2><div class="mono" style="color:var(--mute)">${i.id} · ${i.at}</div>
    <p class="msg">${msg || "Prototype: sample data, nothing is sent to the backend."}</p>
    <h3>Incident information</h3>
    <dl><dt>Description</dt><dd>${i.desc}</dd><dt>Related alerts</dt><dd class="mono">${i.alerts.join(", ")}</dd><dt>Related events</dt><dd class="mono">${i.events.join(", ")}</dd><dt>Affected asset</dt><dd class="mono">${i.asset}</dd><dt>Threat category</dt><dd>${i.cat}</dd><dt>Investigation</dt><dd>${i.inv}</dd></dl>
    <h3>Risk assessment</h3>
    <dl><dt>Risk score</dt><dd class="mono lv-${l}">${i.score} / 100 (${cap(l)})</dd><dt>Previous score</dt><dd class="mono">${i.prev}</dd><dt>Score change</dt><dd class="mono">${d >= 0 ? "+" : ""}${d}</dd><dt>Assessed</dt><dd class="mono">${i.at}</dd><dt>Version</dt><dd class="mono">${i.ver}</dd></dl>
    <h3>Risk factor breakdown</h3>
    ${FACTORS.map((f, n) => `<div class="fct"><div class="top"><span>${f.name}</span><span class="mono">value ${i.f[n]} · weight ${f.w}% · +${(i.f[n] * f.w / 100).toFixed(1)}</span></div><div class="bar"><i class="bg-${levelOf(i.f[n])}" style="width:${i.f[n]}%"></i></div></div>`).join("")}
    <h3>Why this incident has this risk score</h3><p class="note">${i.why} <small>(Predefined sample explanation.)</small></p>
    <h3>Risk history</h3>${lineChart(i.history)}
    <table><thead><tr><th>Time</th><th>Previous</th><th>New</th><th>Change</th></tr></thead><tbody>${hist}</tbody></table>
    <h3>Recommended actions</h3><ul>${ACTIONS[l].map(a => `<li>${a}</li>`).join("")}</ul>
    <p class="note small">Recommendations only. ARGUS takes no automatic action.</p>
    <div class="links"><a href="argus_investigations.html">View Investigation</a><a href="argus_alerts.html">View Related Alerts</a><a href="argus_events.html">View Related Events</a></div>
    <div class="acts" style="margin-top:14px"><button id="rc" class="pri">Recalculate Risk</button></div>`;
  $("dr").classList.add("open"); $("dr").setAttribute("aria-hidden", "false");
  $("cl").onclick = closeDrawer;
  $("rc").onclick = () => { i.prev = i.score; i.score = scoreOf(i); openDrawer(id, "Sample recalculation in this browser only. The backend score was not changed."); };
  render();
}
function closeDrawer() { selected = null; $("dr").classList.remove("open"); $("dr").setAttribute("aria-hidden", "true"); render(); }

// ---------- events ----------
const open = e => { const r = e.target.closest("[data-id]"); if (r) openDrawer(r.dataset.id); };
$("rows").onclick = open; $("top").onclick = open;
$("rows").onkeydown = $("top").onkeydown = e => { if (e.key === "Enter") open(e); };
document.onkeydown = e => { if (e.key === "Escape") closeDrawer(); };
const FILTERS = ["q","fl","fc","fmin","fmax","fd","fsort"];
FILTERS.forEach(id => $(id).oninput = render);
$("clr").onclick = () => { FILTERS.forEach(id => $(id).value = ""); $("fsort").value = "high"; render(); };
$("refresh").onclick = () => { renderStats(); renderOverview(); renderTop(); render(); $("note").textContent = "Refreshed from sample data. No backend request was made."; };

[...new Set(INCIDENTS.map(i => i.cat))].forEach(c => $("fc").insertAdjacentHTML("beforeend", `<option>${c}</option>`));
renderStats(); renderOverview(); renderTop(); renderFactors(); render();