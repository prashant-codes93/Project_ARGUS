/* ARGUS Investigations page (frontend prototype).
   All data is SAMPLE data kept in this page's memory. Nothing is read from
   or saved to the Flask backend, and changes are lost on refresh. */

const ME = "Rohan Kumar";   // signed-in analyst shown in the sidebar
const ANALYSTS = ["Priya Sharma", "Amit Verma", "Rohan Kumar", "Unassigned"];
const STATUS = { open:"Open", in_progress:"In Progress", under_review:"Under Review", resolved:"Resolved" };

// Sample alerts and events (match the Alerts page samples)
const ALERT_DB = {
  "AL-1009": { name:"Large Data Export",           rule:"large_data_export",  sev:"medium", time:"2026-11-11 10:20", status:"Open",         ev:"EV-4120" },
  "AL-1008": { name:"Brute Force Login Attempt",   rule:"brute_force_login",  sev:"high",   time:"2026-11-11 10:00", status:"Open",         ev:"EV-4119" },
  "AL-1007": { name:"Brute Force Login Attempt",   rule:"brute_force_login",  sev:"high",   time:"2026-11-11 09:05", status:"Acknowledged", ev:"EV-4118" },
  "AL-1006": { name:"Known Malicious IP Detected", rule:"known_malicious_ip", sev:"high",   time:"2026-11-10 22:41", status:"Resolved",     ev:"EV-4110" },
  "AL-1005": { name:"Large Data Export",           rule:"large_data_export",  sev:"medium", time:"2026-11-10 16:12", status:"Acknowledged", ev:"EV-4104" },
  "AL-1004": { name:"Known Malicious IP Detected", rule:"known_malicious_ip", sev:"high",   time:"2026-11-09 13:30", status:"Open",         ev:"EV-4091" },
  "AL-1003": { name:"Brute Force Login Attempt",   rule:"brute_force_login",  sev:"high",   time:"2026-11-08 18:55", status:"Resolved",     ev:"EV-4080" }
};
const EVENT_DB = {
  "EV-4120": { type:"data_export",  ip:"10.0.0.30",     dest:"203.0.113.50", user:"svc_backup", time:"2026-11-11 10:20", sev:"critical" },
  "EV-4119": { type:"failed_login", ip:"10.0.0.20",     dest:"10.0.0.5",     user:"admin",      time:"2026-11-11 10:00", sev:"high" },
  "EV-4118": { type:"failed_login", ip:"45.83.64.1",    dest:"10.0.0.5",     user:"root",       time:"2026-11-11 09:05", sev:"high" },
  "EV-4110": { type:"failed_login", ip:"45.83.64.1",    dest:null,           user:"admin",      time:"2026-11-10 22:41", sev:"high" },
  "EV-4104": { type:"data_export",  ip:"10.0.0.31",     dest:"198.51.100.7", user:"analyst1",   time:"2026-11-10 16:12", sev:"high" },
  "EV-4091": { type:"failed_login", ip:"185.220.101.4", dest:"10.0.0.8",     user:"unknown",    time:"2026-11-09 13:30", sev:"high" },
  "EV-4080": { type:"failed_login", ip:"10.0.0.22",     dest:"10.0.0.5",     user:"dev_user",   time:"2026-11-08 18:55", sev:"high" }
};

// Category and recommendations per real detection rule (recommendations only)
const RULE_INFO = {
  known_malicious_ip: { cat:"Malicious IP activity", recs:["Verify the source IP against trusted threat intelligence.","Review related security events.","Consider blocking the IP after analyst verification."] },
  brute_force_login:  { cat:"Credential attack (brute force)", recs:["Review authentication logs.","Verify the affected accounts.","Consider account protection and IP blocking."] },
  large_data_export:  { cat:"Possible data exfiltration", recs:["Verify whether the export was authorized.","Review the affected account.","Examine related access logs."] }
};

function makeInv(id, title, desc, sev, status, analyst, created, updated, incident, alerts, evidence, notes) {
  const events = [...new Set(alerts.map(a => ALERT_DB[a].ev))];
  return { id, title, desc, sev, status, analyst, created, updated, incident, alerts, events, escalated:false, log:[], evidence, notes };
}
const INVS = [
  makeInv("INV-304","Multiple Failed Authentication Attempts","Repeated failed logins for one developer account on the internal server.","medium","resolved","Priya Sharma","2026-11-08 19:10","2026-11-09 11:00",null,["AL-1003"],
    [["Finding","Failures were caused by an expired password.","2026-11-09 10:40"]],[["Priya Sharma","2026-11-09 10:45","Confirmed with the user. No malicious activity."]]),
  makeInv("INV-303","Unusual Data Export Investigation","Large exports from two hosts need an authorization check.","medium","under_review","Rohan Kumar","2026-11-11 10:35","2026-11-11 11:15","INC-3",["AL-1009","AL-1005"],
    [["Evidence description","Export size and destination copied from the proxy log.","2026-11-11 10:50"]],[["Rohan Kumar","2026-11-11 11:10","Waiting for the data owner to confirm the backup job."]]),
  makeInv("INV-302","Suspicious Malicious IP Activity","Two events came from IPs on the threat-intelligence list.","high","open","Amit Verma","2026-11-10 22:50","2026-11-10 22:50","INC-2",["AL-1006","AL-1004"],[],[]),
  makeInv("INV-301","Brute Force Login Investigation","Repeated failed logins against admin and root accounts.","high","in_progress","Priya Sharma","2026-11-11 10:10","2026-11-11 10:40",null,["AL-1008","AL-1007"],
    [["Suspicious IP","45.83.64.1","2026-11-11 10:25"],["Affected username","root","2026-11-11 10:26"]],[["Priya Sharma","2026-11-11 10:30","Source 45.83.64.1 also appears in INV-302."]])
];

const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const show = v => v ? esc(v) : "N/A";
const badge = s => `<span class="badge ${s}">${s.toUpperCase()}</span>`;
const stat = s => `<span class="st-${s}">${STATUS[s].toUpperCase()}</span>`;
const now = () => { const d = new Date(), p = n => String(n).padStart(2, "0"); return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`; };
const findInv = id => INVS.find(i => i.id === id);
const srcIp = i => EVENT_DB[i.events[0]].ip;
const rule = i => ALERT_DB[i.alerts[0]].rule;
let selected = null;

Object.entries(STATUS).forEach(([k, v]) => { $("fst").add(new Option(v, k)); $("ni-st").add(new Option(v, k)); });
ANALYSTS.forEach(a => { $("fa").add(new Option(a, a)); $("ni-an").add(new Option(a, a)); });
$("ni-an").value = "Unassigned";
$("alertList").innerHTML = Object.keys(ALERT_DB).map(a => `<option value="${a}">`).join("");

// ---------- list ----------
function filtered() {
  const q = $("q").value.toLowerCase(), s = $("fs").value, st = $("fst").value, a = $("fa").value, d = $("fd").value;
  return INVS.filter(i => (!s || i.sev === s) && (!st || i.status === st) && (!a || i.analyst === a) && (!d || i.created.startsWith(d)) &&
    (!q || [i.id, i.title, i.alerts.join(" "), srcIp(i), i.analyst].join(" ").toLowerCase().includes(q)))
    .sort((x, y) => y.created.localeCompare(x.created));
}
function render() {
  const n = st => INVS.filter(i => i.status === st).length;
  $("stats").innerHTML = [[INVS.length,"Total Investigations",""],[n("open"),"Open Investigations","c-critical"],[n("in_progress"),"In Progress",""],[n("resolved"),"Resolved Investigations","c-low"]]
    .map(c => `<div class="stat"><b class="${c[2]}">${c[0]}</b><span>${c[1]}</span></div>`).join("");
  const list = filtered();
  $("rows").innerHTML = list.map(i => `<tr tabindex="0" data-id="${i.id}" class="${selected === i.id ? "sel" : ""}">
    <td class="mono">${i.id}</td><td class="ev">${esc(i.title)}</td><td class="mono">${i.alerts.join(", ")}</td><td>${badge(i.sev)}</td>
    <td class="mono">${srcIp(i)}</td><td>${esc(i.analyst)}</td><td class="mono">${i.created}</td><td>${stat(i.status)}</td>
    <td><button class="view-btn" data-id="${i.id}">View</button></td></tr>`).join("");
  $("none").hidden = list.length > 0;
  $("cnt").textContent = list.length + " investigations";
}

// ---------- details drawer ----------
function timeline(i) {
  const items = [];
  i.events.forEach(e => items.push([EVENT_DB[e].time, `Security event received (${e})`, false]));
  i.alerts.forEach(a => items.push([ALERT_DB[a].time, `Rule ${ALERT_DB[a].rule} triggered, alert ${a} generated`, false]));
  items.push([i.created, "Investigation created", false]);
  i.log.forEach(l => items.push([l.t, l.text, true]));
  return items.sort((a, b) => a[0].localeCompare(b[0]));
}
function openInv(id) {
  const i = findInv(id), info = RULE_INFO[rule(i)], ev0 = EVENT_DB[i.events[0]]; selected = id;
  const users = [...new Set(i.events.map(e => EVENT_DB[e].user))].join(", ");
  $("dr").innerHTML = `<button class="x" id="cl" aria-label="Close details">✕</button>
    ${badge(i.sev)}${i.escalated ? '<span class="tag warn">ESCALATED</span>' : ""}<h2>${esc(i.title)}</h2>
    <div class="mono" style="color:var(--mute)">${i.id} · ${stat(i.status)}</div>
    <div class="bar"><label for="as">Assign</label><select id="as">${ANALYSTS.map(a => `<option ${a === i.analyst ? "selected" : ""}>${a}</option>`).join("")}</select>
      <label for="cs">Status</label><select id="cs">${Object.entries(STATUS).map(([k, v]) => `<option value="${k}" ${k === i.status ? "selected" : ""}>${v}</option>`).join("")}</select>
      <button data-act="esc" ${i.escalated || i.status === "resolved" ? "disabled" : ""}>Escalate</button>
      <button class="pri" data-act="res" ${i.status === "resolved" ? "disabled" : ""}>Resolve</button></div>
    <p class="msg">Prototype: changes stay in this page only and are not saved to the database.</p>

    <h3>Investigation overview</h3>
    <dl><dt>Description</dt><dd>${esc(i.desc)}</dd><dt>Assigned analyst</dt><dd>${esc(i.analyst)}</dd><dt>Created</dt><dd class="mono">${i.created}</dd>
      <dt>Last updated</dt><dd class="mono">${i.updated}</dd><dt>Incident ID</dt><dd class="mono">${show(i.incident)}</dd></dl>

    <h3>Threat summary</h3>
    <dl><dt>Threat category</dt><dd>${info.cat}</dd><dt>Detection rule</dt><dd class="mono">${rule(i)}</dd><dt>Source IP</dt><dd class="mono">${ev0.ip}</dd>
      <dt>Destination IP</dt><dd class="mono">${show(ev0.dest)}</dd><dt>Affected user</dt><dd>${esc(users)}</dd>
      <dt>Related events</dt><dd>${i.events.length}</dd><dt>Related alerts</dt><dd>${i.alerts.length}</dd>
      <dt>Risk score</dt><dd>Not available <span class="tag">from Risk Scoring</span></dd></dl>

    <h3>Related alerts</h3><div class="scroll"><table><thead><tr><th>Alert</th><th>Name</th><th>Rule</th><th>Severity</th><th>Time</th><th>Status</th><th></th></tr></thead><tbody>
      ${i.alerts.map(a => { const x = ALERT_DB[a]; return `<tr><td class="mono">${a}</td><td>${x.name}</td><td class="mono">${x.rule}</td><td>${badge(x.sev)}</td><td class="mono">${x.time}</td><td>${x.status}</td><td><a class="view-btn" href="argus_alerts.html">View Alert</a></td></tr>`; }).join("")}</tbody></table></div>

    <h3>Related security events</h3><div class="scroll"><table><thead><tr><th>Event</th><th>Type</th><th>Source IP</th><th>User</th><th>Time</th><th>Severity</th><th></th></tr></thead><tbody>
      ${i.events.map(e => { const x = EVENT_DB[e]; return `<tr><td class="mono">${e}</td><td>${x.type}</td><td class="mono">${x.ip}</td><td>${x.user}</td><td class="mono">${x.time}</td><td>${badge(x.sev)}</td><td><a class="view-btn" href="argus_events.html">View Event</a></td></tr>`; }).join("")}</tbody></table></div>

    <h3>Investigation timeline <small>Times are sample data. SESSION entries were made on this page and are not saved.</small></h3>
    <ol class="tl">${timeline(i).map(t => `<li><span class="mono">${t[0]}</span>${t[2] ? '<span class="tag">SESSION</span>' : ""}<br>${esc(t[1])}</li>`).join("")}</ol>

    <h3>Evidence and findings <small>Stored locally only</small></h3>
    ${i.evidence.length ? i.evidence.map(e => `<div class="item"><b>${esc(e[0])}</b><br>${esc(e[1])}<br><span class="mono">${e[2]}</span></div>`).join("") : '<p class="msg">No evidence added yet.</p>'}
    <div class="add"><select id="ek">${["Evidence description","Suspicious IP","Affected username","Observation","Finding"].map(k => `<option>${k}</option>`).join("")}</select>
      <input id="et" placeholder="Enter details" aria-label="Evidence details"><button data-act="ev">Add Evidence</button></div>

    <h3>Analyst notes</h3>
    ${i.notes.length ? i.notes.map(n => `<div class="item"><b>${esc(n[0])}</b> <span class="mono">${n[1]}</span><br>${esc(n[2])}</div>`).join("") : '<p class="msg">No notes yet.</p>'}
    <div class="add"><textarea id="nt" rows="2" placeholder="Write a note..." aria-label="New note"></textarea><button data-act="note">Add Note</button></div>

    <h3>Recommended actions <small>Recommendations only. ARGUS does not perform these automatically.</small></h3>
    <ul class="recs">${info.recs.map(r => `<li>${r}</li>`).join("")}</ul>`;
  $("dr").classList.add("open"); $("dr").setAttribute("aria-hidden", "false");
  $("cl").onclick = closeDrawer;
  render();
}
function closeDrawer() { selected = null; $("dr").classList.remove("open"); $("dr").setAttribute("aria-hidden", "true"); render(); }

// ---------- local actions ----------
function change(i, text) { i.updated = now(); i.log.push({ t:i.updated, text }); openInv(i.id); }
$("dr").onclick = e => {
  const act = e.target.dataset.act; if (!act) return;
  const i = findInv(selected);
  if (act === "esc") { i.escalated = true; change(i, `Escalated by ${ME}`); }
  if (act === "res") { i.status = "resolved"; change(i, `Resolved by ${ME}`); }
  if (act === "ev") { const t = $("et").value.trim(); if (!t) return $("et").focus(); i.evidence.push([$("ek").value, t, now()]); change(i, `${$("ek").value} added`); }
  if (act === "note") { const t = $("nt").value.trim(); if (!t) return $("nt").focus(); i.notes.push([ME, now(), t]); change(i, `Note added by ${ME}`); }
};
$("dr").onchange = e => {
  const i = findInv(selected);
  if (e.target.id === "as") { i.analyst = e.target.value; change(i, `Assigned to ${i.analyst}`); }
  if (e.target.id === "cs") { i.status = e.target.value; change(i, `Status changed to ${STATUS[i.status]}`); }
};

// ---------- new investigation ----------
$("newBtn").onclick = () => { $("ndf").reset(); $("ni-err").textContent = ""; $("nd").showModal(); };
$("ndc").onclick = () => $("nd").close();
$("ndf").onsubmit = e => {
  e.preventDefault();
  const title = $("ni-title").value.trim(), alertId = $("ni-alert").value.trim().toUpperCase();
  if (!title) { $("ni-err").textContent = "Title is required."; return $("ni-title").focus(); }
  if (!alertId) { $("ni-err").textContent = "Related alert ID is required."; return $("ni-alert").focus(); }
  if (!ALERT_DB[alertId]) { $("ni-err").textContent = "Alert not found in sample data. Try " + Object.keys(ALERT_DB).join(", ") + "."; return $("ni-alert").focus(); }
  const id = "INV-" + (Math.max(...INVS.map(i => Number(i.id.slice(4)))) + 1), t = now();
  INVS.push(makeInv(id, title, $("ni-desc").value.trim() || "No description provided.", $("ni-sev").value, $("ni-st").value, $("ni-an").value, t, t, $("ni-inc").value.trim() || null, [alertId], [], []));
  $("nd").close(); render(); openInv(id);
};

// ---------- events ----------
$("rows").onclick = e => { const r = e.target.closest("tr"); if (r) openInv(r.dataset.id); };
$("rows").onkeydown = e => { if (e.key === "Enter") { const r = e.target.closest("tr"); if (r) openInv(r.dataset.id); } };
document.onkeydown = e => { if (e.key === "Escape" && !$("nd").open) closeDrawer(); };
["q","fs","fst","fa","fd"].forEach(id => $(id).oninput = render);
$("clr").onclick = () => { ["q","fs","fst","fa","fd"].forEach(id => $(id).value = ""); render(); };
render();