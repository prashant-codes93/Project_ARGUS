/* ARGUS Assets page (frontend prototype).
   ALL data is SAMPLE data. The backend has no assets, vulnerabilities or
   relationships tables or API, so everything here lives in this page only.
   Later, replace ASSETS with data from a future GET /api/assets. */

const TYPES = ["Server","Workstation","Network Device","Cloud Resource","Database","Other"];
// Same thresholds as the Risk Scoring page.
const levelOf = s => s >= 75 ? "critical" : s >= 50 ? "high" : s >= 25 ? "medium" : "low";

// Minimal sample catalogs for related records. IDs match the Alerts / Risk Scoring samples.
const ALERTS = {
  "AL-1009":["Large Data Export","medium","large_data_export","2026-11-11 10:20","open"],
  "AL-1008":["Brute Force Login Attempt","high","brute_force_login","2026-11-11 10:00","open"],
  "AL-1007":["Brute Force Login Attempt","high","brute_force_login","2026-11-11 09:05","acknowledged"],
  "AL-1004":["Known Malicious IP Detected","high","known_malicious_ip","2026-11-09 13:30","open"],
  "AL-1005":["Large Data Export","medium","large_data_export","2026-11-10 16:12","acknowledged"],
  "AL-1003":["Brute Force Login Attempt","high","brute_force_login","2026-11-08 18:55","resolved"]
};
const INCS = {
  "INC-1":["Suspicious Malicious IP Activity",84,"open","2026-11-09"],
  "INC-3":["Unusual Data Export",69,"open","2026-11-11"],
  "INC-4":["Brute Force Login Investigation",82,"investigating","2026-11-11"],
  "INC-5":["Forgotten Password Lockout",34,"closed","2026-11-08"]
};
const EVS = {
  "EV-4091":["failed_login","high","2026-11-09 13:30"], "EV-4118":["failed_login","high","2026-11-11 09:05"],
  "EV-4119":["failed_login","high","2026-11-11 10:00"], "EV-4120":["data_export","critical","2026-11-11 10:20"],
  "EV-4104":["data_export","high","2026-11-10 16:12"], "EV-4080":["failed_login","medium","2026-11-08 18:55"]
};

// Security status (secure/warning/risk) is separate from availability (online/offline).
// risk values are ILLUSTRATIVE sample asset scores, not derived from incident scores.
let ASSETS = [
 { id:"A-001", name:"auth-server-01", type:"Server", ip:"10.0.0.5", mac:"", host:"auth01.corp.local", os:"Ubuntu", osv:"22.04", owner:"IT Operations", loc:"Data centre A", crit:"critical", env:"Production", dept:"IT", sec:"risk", online:true, risk:78, seen:"2026-11-13 09:40", created:"2025-03-02", desc:"Central authentication server.", al:["AL-1008","AL-1007"], inc:["INC-4"], ev:["EV-4119","EV-4118"], rel:[["A-003","connects to"],["A-002","serves"]] },
 { id:"A-002", name:"hr-workstation-14", type:"Workstation", ip:"10.0.0.22", mac:"", host:"hr14", os:"Windows", osv:"11", owner:"D. Mehta", loc:"Office 2F", crit:"low", env:"Production", dept:"HR", sec:"secure", online:true, risk:18, seen:"2026-11-13 10:02", created:"2025-06-12", desc:"HR staff workstation.", al:["AL-1003"], inc:["INC-5"], ev:["EV-4080"], rel:[["A-001","uses"]] },
 { id:"A-003", name:"core-db-01", type:"Database", ip:"10.0.0.8", mac:"", host:"coredb01", os:"Debian", osv:"12", owner:"Data Team", loc:"Data centre A", crit:"critical", env:"Production", dept:"Engineering", sec:"risk", online:true, risk:81, seen:"2026-11-13 10:05", created:"2025-01-20", desc:"Primary application database.", al:["AL-1004"], inc:["INC-1"], ev:["EV-4091"], rel:[["A-001","accessed by"]] },
 { id:"A-004", name:"backup-service", type:"Server", ip:"10.0.0.30", mac:"", host:"backup01", os:"Ubuntu", osv:"20.04", owner:"IT Operations", loc:"Data centre B", crit:"high", env:"Production", dept:"IT", sec:"warning", online:true, risk:52, seen:"2026-11-13 08:30", created:"2025-04-18", desc:"Nightly backup host.", al:["AL-1009"], inc:["INC-3"], ev:["EV-4120"], rel:[["A-003","backs up"]] },
 { id:"A-005", name:"analyst-laptop-01", type:"Workstation", ip:"10.0.0.31", mac:"", host:"an01", os:"macOS", osv:"14", owner:"Analyst team", loc:"Office 3F", crit:"medium", env:"Production", dept:"Security", sec:"warning", online:false, risk:36, seen:"2026-11-12 18:20", created:"2025-09-01", desc:"Security analyst laptop.", al:["AL-1005"], inc:[], ev:["EV-4104"], rel:[] },
 { id:"A-006", name:"edge-router-01", type:"Network Device", ip:"10.0.0.1", mac:"", host:"edge01", os:"RouterOS", osv:"", owner:"Network Team", loc:"Server room", crit:"high", env:"Production", dept:"IT", sec:"secure", online:true, risk:22, seen:"2026-11-13 10:10", created:"2024-11-05", desc:"Perimeter router.", al:[], inc:[], ev:[], rel:[["A-001","connects"],["A-003","connects"]] },
 { id:"A-007", name:"app-cloud-vm", type:"Cloud Resource", ip:"10.0.1.12", mac:"", host:"appvm", os:"Linux", osv:"", owner:"Engineering", loc:"Cloud", crit:"medium", env:"Testing", dept:"Engineering", sec:"secure", online:true, risk:15, seen:"2026-11-13 09:55", created:"2026-02-10", desc:"Test application VM.", al:[], inc:[], ev:[], rel:[] },
 { id:"A-008", name:"badge-reader-02", type:"Other", ip:"10.0.2.4", mac:"", host:"", os:"", osv:"", owner:"Facilities", loc:"Lobby", crit:"low", env:"Production", dept:"", sec:"secure", online:false, risk:null, seen:"2026-11-10 07:00", created:"2025-08-08", desc:"Door access device.", al:[], inc:[], ev:[], rel:[] }
];

// Clearly fake vulnerability records: no real CVE IDs, no real findings.
const VULNS = [
 { id:"SV-001", name:"Sample: outdated service version", cve:null, sev:"high", cvss:7.5, asset:"A-004", date:"2026-11-05", rem:"open" },
 { id:"SV-002", name:"Sample: weak authentication policy", cve:null, sev:"critical", cvss:9.1, asset:"A-001", date:"2026-11-02", rem:"in progress" },
 { id:"SV-003", name:"Sample: missing OS patches", cve:null, sev:"medium", cvss:5.3, asset:"A-005", date:"2026-10-28", rem:"open" },
 { id:"SV-004", name:"Sample: exposed management port", cve:null, sev:"high", cvss:7.1, asset:"A-003", date:"2026-11-08", rem:"open" },
 { id:"SV-005", name:"Sample: verbose error pages", cve:null, sev:"low", cvss:3.1, asset:"A-007", date:"2026-10-20", rem:"fixed" }
];

const $ = id => document.getElementById(id);
const cap = s => s ? s[0].toUpperCase() + s.slice(1) : s;
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const show = v => v ? esc(v) : "N/A";
const SS = { secure:"Secure", warning:"Warning", risk:"At Risk" };
const vulnCount = a => VULNS.filter(v => v.asset === a.id && v.rem !== "fixed").length;
const hasVulns = a => vulnCount(a) > 0;
let selected = null, editing = null;

function getFiltered() {
  const q = $("q").value.toLowerCase(), t = $("ft").value, c = $("fc").value, s = $("fs").value, r = $("fr").value;
  const [lo, hi] = r ? r.split("-").map(Number) : [0, 100];
  const list = ASSETS.filter(a => (!t || a.type === t) && (!c || a.crit === c) && (!s || a.sec === s) &&
    (!r || (a.risk !== null && a.risk >= lo && a.risk <= hi)) && (!q || [a.name, a.id, a.ip].join(" ").toLowerCase().includes(q)));
  const k = $("fsort").value;
  return list.sort((a, b) => k === "name" ? a.name.localeCompare(b.name) : k === "risk" ? (b.risk ?? -1) - (a.risk ?? -1) : k === "seen" ? b.seen.localeCompare(a.seen) : a.id.localeCompare(b.id));
}

function renderStats() {
  const n = f => ASSETS.filter(f).length;
  const c = [[ASSETS.length,"Total Assets",""],[n(a => a.online),"Active Assets",""],[n(a => a.crit === "critical"),"Critical Assets","lv-critical"],[n(hasVulns),"Vulnerable Assets (sample)","lv-medium"],[n(a => a.risk !== null && a.risk >= 50),"High-Risk Assets","lv-high"]];
  $("stats").innerHTML = c.map(x => `<div class="stat"><b class="${x[2]}">${x[0]}</b><span>${x[1]}</span></div>`).join("");
  $("cats").innerHTML = TYPES.map(t => { const k = n(a => a.type === t), p = ASSETS.length ? Math.round(k * 100 / ASSETS.length) : 0;
    return `<div class="row"><span>${t}</span><div class="bar"><i style="width:${p}%"></i></div><span>${k} · ${p}%</span></div>`; }).join("");
  const m = [["Secure assets", n(a => a.sec === "secure")],["Requiring attention (Warning)", n(a => a.sec === "warning")],["At Risk", n(a => a.sec === "risk")],["High-risk assets (score ≥ 50)", n(a => a.risk !== null && a.risk >= 50)],["Critical infrastructure", n(a => a.crit === "critical")],["With related alerts", n(a => a.al.length)],["Offline (availability)", n(a => !a.online)]];
  $("mon").innerHTML = `<dl class="mon">${m.map(x => `<dt>${x[0]}</dt><dd>${x[1]}</dd>`).join("")}</dl>`;
}

function render() {
  const list = getFiltered();
  $("rows").innerHTML = list.map(a => `<tr tabindex="0" data-id="${a.id}" class="${selected === a.id ? "sel" : ""}">
    <td class="mono">${a.id}</td><td class="ev">${esc(a.name)}${a.online ? "" : '<span class="tag">offline</span>'}</td><td>${a.type}</td><td class="mono">${esc(a.ip)}</td><td>${show(a.os)}</td>
    <td><span class="badge ${a.crit}">${a.crit.toUpperCase()}</span></td><td class="ss ss-${a.sec}">${SS[a.sec]}</td>
    <td class="mono ${a.risk === null ? "" : "lv-" + levelOf(a.risk)}">${a.risk ?? "N/A"}</td><td class="mono">${a.seen}</td>
    <td><button data-id="${a.id}">View Details</button></td></tr>`).join("");
  $("none").hidden = list.length > 0;
  $("cnt").textContent = list.length + " assets";
  renderStats(); renderVulns();
}

function renderVulns() {
  const s = $("vs").value, r = $("vr").value;
  const l = VULNS.filter(v => (!s || v.sev === s) && (!r || v.rem === r)).sort((a, b) => $("vsort").value === "date" ? b.date.localeCompare(a.date) : b.cvss - a.cvss);
  $("vrows").innerHTML = l.map(v => `<tr><td class="mono">${v.id}</td><td>${v.name}</td><td class="mono">${v.cve || "N/A"}</td><td><span class="badge ${v.sev}">${v.sev.toUpperCase()}</span></td><td class="mono">${v.cvss.toFixed(1)}</td><td class="mono">${v.asset}</td><td class="mono">${v.date}</td><td>${cap(v.rem)}</td></tr>`).join("") || `<tr><td colspan="8">No sample vulnerabilities match.</td></tr>`;
}

function relDiagram(a) {
  if (!a.rel.length) return `<p class="note small">No relationships recorded for this asset.</p>`;
  const W = 300, H = 40 + a.rel.length * 36;
  const nodes = a.rel.map((r, n) => { const o = ASSETS.find(x => x.id === r[0]), y = 30 + n * 36;
    return `<line x1="70" y1="${H / 2}" x2="210" y2="${y}" stroke="var(--acc)"/><text x="140" y="${(H / 2 + y) / 2 - 3}" font-size="9" fill="currentColor" text-anchor="middle">${r[1]}</text><rect x="210" y="${y - 12}" width="86" height="24" rx="6" fill="#fff" stroke="#c9d1e0"/><text x="253" y="${y + 4}" font-size="10" text-anchor="middle" fill="currentColor">${esc(o ? o.name.slice(0, 12) : r[0])}</text>`; }).join("");
  return `<svg class="rel" viewBox="0 0 ${W} ${H}" role="img" aria-label="Sample relationships"><rect x="4" y="${H / 2 - 12}" width="86" height="24" rx="6" fill="var(--acc)"/><text x="47" y="${H / 2 + 4}" font-size="10" text-anchor="middle" fill="#fff">${esc(a.name.slice(0, 12))}</text>${nodes}</svg><p class="note small">Sample relationships, not discovered topology.</p>`;
}

function openDrawer(id, msg) {
  const a = ASSETS.find(x => x.id === id); selected = id;
  const lv = a.risk === null ? null : levelOf(a.risk), vs = VULNS.filter(v => v.asset === id);
  const tbl = (head, rows) => rows ? `<table><thead><tr>${head.map(h => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows}</tbody></table>` : `<p class="note small">None recorded.</p>`;
  $("dr").innerHTML = `
    <button class="x" id="cl" aria-label="Close details">✕</button>
    <span class="badge ${a.crit}">${a.crit.toUpperCase()}</span>
    <h2>${esc(a.name)}</h2><div class="mono" style="color:var(--mute)">${a.id} · ${esc(a.ip)}</div>
    <p class="msg">${msg || "Prototype: changes affect this page only."}</p>
    <h3>Asset overview</h3>
    <dl><dt>Type</dt><dd>${a.type}</dd><dt>Description</dt><dd>${show(a.desc)}</dd><dt>MAC address</dt><dd class="mono">${show(a.mac)}</dd><dt>Hostname</dt><dd class="mono">${show(a.host)}</dd><dt>Operating system</dt><dd>${show(a.os)} ${esc(a.osv)}</dd><dt>Owner</dt><dd>${show(a.owner)}</dd><dt>Location</dt><dd>${show(a.loc)}</dd><dt>Created</dt><dd class="mono">${a.created}</dd><dt>Last seen</dt><dd class="mono">${a.seen}</dd></dl>
    <h3>Classification</h3>
    <dl><dt>Business criticality</dt><dd>${cap(a.crit)}</dd><dt>Category</dt><dd>${a.type}</dd><dt>Environment</dt><dd>${a.env}</dd><dt>Department</dt><dd>${show(a.dept)}</dd><dt>Availability</dt><dd>${a.online ? "Online" : "Offline"}</dd></dl>
    <h3>Security overview</h3>
    <dl><dt>Security status</dt><dd class="ss ss-${a.sec}">${SS[a.sec]}</dd><dt>Asset risk score</dt><dd class="mono ${lv ? "lv-" + lv : ""}">${a.risk === null ? "N/A" : a.risk + " / 100 (" + cap(lv) + ")"}</dd><dt>Alerts / Incidents / Events</dt><dd class="mono">${a.al.length} / ${a.inc.length} / ${a.ev.length}</dd><dt>Open vulnerabilities</dt><dd class="mono">${vulnCount(a)} (sample)</dd></dl>
    <p class="note small">Asset risk is a separate illustrative sample value. It is not calculated from incident risk scores.</p>
    <h3>Related alerts</h3>${tbl(["ID","Name","Severity","Rule","Time","Status",""], a.al.map(i => { const x = ALERTS[i]; return `<tr><td class="mono">${i}</td><td>${x[0]}</td><td><span class="badge ${x[1]}">${x[1].toUpperCase()}</span></td><td class="mono">${x[2]}</td><td class="mono">${x[3]}</td><td>${cap(x[4])}</td><td class="links"><a href="argus_alerts.html">View Alert</a></td></tr>`; }).join(""))}
    <h3>Related incidents</h3>${tbl(["ID","Title","Risk","Status","Created",""], a.inc.map(i => { const x = INCS[i]; return `<tr><td class="mono">${i}</td><td>${x[0]}</td><td class="mono">${x[1]}</td><td>${cap(x[2])}</td><td class="mono">${x[3]}</td><td class="links"><a href="argus_risk_scoring.html">View Incident</a></td></tr>`; }).join(""))}
    <h3>Recent security events</h3>${tbl(["ID","Type","Severity","Time",""], a.ev.map(i => { const x = EVS[i]; return `<tr><td class="mono">${i}</td><td class="mono">${x[0]}</td><td><span class="badge ${x[1]}">${x[1].toUpperCase()}</span></td><td class="mono">${x[2]}</td><td class="links"><a href="argus_events.html">View Event</a></td></tr>`; }).join(""))}
    <h3>Vulnerabilities (sample)</h3>${tbl(["ID","Name","Severity","CVSS","Status"], vs.map(v => `<tr><td class="mono">${v.id}</td><td>${v.name}</td><td><span class="badge ${v.sev}">${v.sev.toUpperCase()}</span></td><td class="mono">${v.cvss}</td><td>${cap(v.rem)}</td></tr>`).join(""))}
    <h3>Relationships</h3>${relDiagram(a)}
    <div class="acts" style="margin-top:14px"><button id="ed">Edit</button><button id="tg">${a.online ? "Mark Offline" : "Mark Online"}</button><button id="dl">Delete</button></div>`;
  $("dr").classList.add("open"); $("dr").setAttribute("aria-hidden", "false");
  $("cl").onclick = closeDrawer;
  $("ed").onclick = () => openForm(id);
  $("tg").onclick = () => { a.online = !a.online; openDrawer(id, "Availability changed (this page only)."); };
  $("dl").onclick = () => { if (confirm("Delete " + a.name + " (" + a.id + ")? This only removes it from this page.")) { ASSETS = ASSETS.filter(x => x.id !== id); closeDrawer(); } };
  render();
}
function closeDrawer() { selected = null; $("dr").classList.remove("open"); $("dr").setAttribute("aria-hidden", "true"); render(); }

// ---------- add / edit ----------
const F = { name:"a-name", type:"a-type", ip:"a-ip", mac:"a-mac", host:"a-host", os:"a-os", osv:"a-osv", owner:"a-owner", loc:"a-loc", crit:"a-crit", env:"a-env", desc:"a-desc" };
const validIp = s => /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(s);
function nextId() { let n = ASSETS.reduce((m, a) => Math.max(m, +a.id.slice(2)), 0) + 1, id; do { id = "A-" + String(n++).padStart(3, "0"); } while (ASSETS.some(a => a.id === id)); return id; }
function openForm(id) {
  editing = id || null; $("a-err").textContent = ""; $("ndt").textContent = id ? "Edit Asset" : "Add New Asset";
  const a = id ? ASSETS.find(x => x.id === id) : { type:"Server", crit:"medium", env:"Production" };
  Object.entries(F).forEach(([k, el]) => $(el).value = a[k] ?? "");
  $("nd").showModal();
}
$("ndf").onsubmit = e => {
  e.preventDefault();
  const v = {}; Object.entries(F).forEach(([k, el]) => v[k] = $(el).value.trim());
  if (!v.name) return $("a-err").textContent = "Asset name is required.";
  if (!validIp(v.ip)) return $("a-err").textContent = "Enter a valid IPv4 address, e.g. 10.0.0.40.";
  if (ASSETS.some(a => a.ip === v.ip && a.id !== editing)) return $("a-err").textContent = "An asset with this IP already exists.";
  if (editing) Object.assign(ASSETS.find(a => a.id === editing), v);
  else ASSETS.push({ id:nextId(), ...v, dept:"", sec:"secure", online:true, risk:null, seen:"N/A", created:new Date().toISOString().slice(0, 10), al:[], inc:[], ev:[], rel:[] });
  $("nd").close(); render(); if (editing) openDrawer(editing, "Asset updated (this page only).");
};
$("addBtn").onclick = () => openForm(); $("ndc").onclick = () => $("nd").close();

// ---------- export (sample data -> CSV download from this page) ----------
$("exp").onclick = () => {
  const cols = ["id","name","type","ip","os","crit","sec","risk","seen"];
  const csv = [cols.join(",")].concat(getFiltered().map(a => cols.map(c => '"' + String(a[c] ?? "").replace(/"/g, '""') + '"').join(","))).join("\n");
  const l = document.createElement("a"); l.href = URL.createObjectURL(new Blob([csv], { type:"text/csv" })); l.download = "argus_assets_sample.csv"; l.click();
  $("note").textContent = "Exported the sample table shown here. No backend data was read.";
};
$("ref").onclick = () => { render(); $("note").textContent = "Refreshed from sample data. No backend request was made."; };

// ---------- events ----------
const pick = e => { const r = e.target.closest("[data-id]"); if (r) openDrawer(r.dataset.id); };
$("rows").onclick = pick; $("rows").onkeydown = e => { if (e.key === "Enter") pick(e); };
document.onkeydown = e => { if (e.key === "Escape" && !$("nd").open) closeDrawer(); };
const FL = ["q","ft","fc","fs","fr","fsort"];
FL.forEach(id => $(id).oninput = render);
["vs","vr","vsort"].forEach(id => $(id).oninput = renderVulns);
$("clr").onclick = () => { FL.forEach(id => $(id).value = ""); $("fsort").value = "id"; render(); };
TYPES.forEach(t => { $("ft").insertAdjacentHTML("beforeend", `<option>${t}</option>`); $("a-type").insertAdjacentHTML("beforeend", `<option>${t}</option>`); });
render();