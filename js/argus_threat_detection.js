/* ARGUS Threat Detection page (frontend prototype).
   Everything here is SAMPLE data and simulated logic running in the browser.
   Nothing is read from or sent to the Flask backend. */

// The 3 real rules from detection_engine/detection.py
const RULES = [
  { name:"known_malicious_ip", sev:"high",   enabled:true, desc:"Detects an event matching a known malicious IP address.",
    logic:"ioc_match is truthy (set by check_threat_intel)" },
  { name:"brute_force_login",  sev:"high",   enabled:true, desc:"Detects five or more failed login events within five minutes.",
    logic:"COUNT(failed_login) for the same user in the last 5 min >= 5" },
  { name:"large_data_export",  sev:"medium", enabled:true, desc:"Detects a high or critical severity data export event.",
    logic:"event_type = data_export AND event severity in (high, critical)" }
];
const SAMPLE_IOCS = ["45.83.64.1", "185.220.101.4"];   // simulation only
const SAMPLE_EVENTS_PROCESSED = 128;                    // sample number

// id, rule, eventId, srcIP, destIP, user, severity, time, result, alertId, reason, action
const DETECTIONS = [
 ["DT-2009","large_data_export","EV-4120","10.0.0.30","203.0.113.50","svc_backup","medium","2026-11-11 10:20","detected","AL-1009","Data export event with critical event severity.","Confirm the export with the data owner."],
 ["DT-2008","brute_force_login","EV-4119","10.0.0.20","10.0.0.5","admin","high","2026-11-11 10:00","detected","AL-1008","Failed logins for this user reached the threshold of 5 within 5 minutes.","Lock the account and reset the password."],
 ["DT-2007","brute_force_login","EV-4118","45.83.64.1","10.0.0.5","root","high","2026-11-11 09:05","detected","AL-1007","Failed logins for this user reached the threshold of 5 within 5 minutes.","Block the source IP and review auth logs."],
 ["DT-2006","known_malicious_ip","EV-4110","45.83.64.1",null,"admin","high","2026-11-10 22:41","detected","AL-1006","Event IP matched the threat-intelligence list.","Block the IP at the firewall."],
 ["DT-2005","known_malicious_ip","EV-4117","10.0.0.12",null,"analyst1","n/a","2026-11-10 17:30","clear",null,"Event IP did not match any known malicious IP.","No action needed."],
 ["DT-2004","large_data_export","EV-4112","10.0.0.31","198.51.100.7","analyst1","n/a","2026-11-10 17:03","clear",null,"Data export event had low severity, below the high threshold.","No action needed."],
 ["DT-2003","brute_force_login","EV-4108","10.0.0.22","10.0.0.5","dev_user","n/a","2026-11-10 16:40","clear",null,"Only 3 failed logins in the window, below the threshold of 5.","No action needed."],
 ["DT-2002","large_data_export","EV-4104","10.0.0.31","198.51.100.7","analyst1","medium","2026-11-10 16:12","detected","AL-1005","Data export event with high event severity.","Verify the export was approved."],
 ["DT-2001","known_malicious_ip","EV-4091","185.220.101.4","10.0.0.8","unknown","high","2026-11-09 13:30","detected","AL-1004","Event IP matched the threat-intelligence list.","Isolate the targeted host."]
].map(r => ({id:r[0],rule:r[1],ev:r[2],ip:r[3],dest:r[4],user:r[5],sev:r[6],time:r[7],res:r[8],alert:r[9],why:r[10],act:r[11]}));

const $ = id => document.getElementById(id);
const show = v => v ? v : "N/A";
const ruleOf = n => RULES.find(r => r.name === n);
const resText = r => r === "detected" ? "DETECTED" : "NO THREAT";
const badge = s => `<span class="badge ${s === "n/a" ? "na" : s}">${s.toUpperCase()}</span>`;
let selected = null;

// ---------- engine status ----------
// Later: call setEngine() with the state returned by a real status API.
function setEngine(state) {
  const labels = { unknown:"ENGINE: NOT CONNECTED", active:"ENGINE: ACTIVE", inactive:"ENGINE: INACTIVE", error:"ENGINE: ERROR" };
  $("eng").className = "eng " + state;
  $("eng").textContent = labels[state];
  $("eng").title = state === "unknown" ? "No backend status API is connected yet" : "";
}

// ---------- stats, overview, rule cards ----------
const hits = name => DETECTIONS.filter(d => d.res === "detected" && (!name || d.rule === name));

function renderTop() {
  const threats = hits().length, active = RULES.filter(r => r.enabled).length;
  const cards = [[RULES.length,"Total Detection Rules"],[active,"Active Detection Rules"],[threats,"Threats Detected"],[SAMPLE_EVENTS_PROCESSED,"Detection Events Processed"]];
  $("stats").innerHTML = cards.map(c => `<div class="stat"><b>${c[0]}</b><span>${c[1]}</span></div>`).join("");
  const last = hits().map(d => d.time).sort().pop();
  const ov = [["Engine status", $("eng").textContent.replace("ENGINE: ","")],["Events processed", SAMPLE_EVENTS_PROCESSED],["Rules executed", SAMPLE_EVENTS_PROCESSED * RULES.length],["Threats identified", threats],["Last detection", last]];
  $("overview").innerHTML = ov.map(o => `<div><b class="mono">${o[1]}</b><span>${o[0]}</span></div>`).join("");
}

function renderRules() {
  $("rules").innerHTML = RULES.map(r => {
    const h = hits(r.name), last = h.map(d => d.time).sort().pop();
    return `<div class="rcard ${r.enabled ? "" : "off"}">
      <h3>${r.name}</h3>${badge(r.sev)}
      <p>${r.desc}</p><code>${r.logic}</code>
      <div class="rmeta"><span>Last triggered: ${show(last)}</span><span>Triggers: ${h.length}</span></div>
      <div class="rbar"><label><input type="checkbox" data-toggle="${r.name}" ${r.enabled ? "checked" : ""}>${r.enabled ? "Enabled" : "Disabled"}</label>
        <button class="view-btn" data-rule="${r.name}">Details</button>
        <button class="view-btn" data-test="${r.name}">Test Rule</button></div></div>`;
  }).join("");
}

// ---------- detections table ----------
[...RULES].forEach(r => $("fr").add(new Option(r.name, r.name)));

function filtered() {
  const q = $("q").value.toLowerCase(), s = $("fs").value, r = $("fr").value, res = $("fres").value, d = $("fd").value;
  return DETECTIONS.filter(x => (!s || x.sev === s) && (!r || x.rule === r) && (!res || x.res === res) && (!d || x.time.startsWith(d)) &&
    (!q || [x.rule, x.ip, x.ev, x.id, x.user].join(" ").toLowerCase().includes(q)));
}

function renderTable() {
  const list = filtered();
  $("rows").innerHTML = list.map(d => `<tr tabindex="0" data-id="${d.id}" class="${selected === d.id ? "sel" : ""}">
    <td class="mono">${d.id}</td><td class="rule">${d.rule}</td><td class="mono">${d.ev}</td><td class="mono">${d.ip}</td><td>${d.user}</td>
    <td>${badge(d.sev)}</td><td class="mono">${d.time}</td><td class="res-${d.res}">${resText(d.res)}</td>
    <td><button class="view-btn" data-id="${d.id}">View</button></td></tr>`).join("");
  $("none").hidden = list.length > 0;
  $("cnt").textContent = list.length + " detections";
}

function renderAll() { renderTop(); renderRules(); renderTable(); }

// ---------- drawer ----------
function openDrawer(html) {
  $("dr").innerHTML = `<button class="x" id="cl" aria-label="Close details">✕</button>` + html;
  $("dr").classList.add("open"); $("dr").setAttribute("aria-hidden", "false");
  $("cl").onclick = closeDrawer; $("cl").focus();
}
function closeDrawer() { selected = null; $("dr").classList.remove("open"); $("dr").setAttribute("aria-hidden", "true"); renderTable(); }

function openDetection(id) {
  const d = DETECTIONS.find(x => x.id === id), r = ruleOf(d.rule); selected = id;
  openDrawer(`${badge(d.sev)}<h2>${d.rule}</h2><div class="mono" style="color:var(--mute)">${d.id} · ${d.time}</div>
    <dl><dt>Result</dt><dd class="res-${d.res}">${resText(d.res)}</dd><dt>Source IP</dt><dd class="mono">${d.ip}</dd>
    <dt>Destination IP</dt><dd class="mono">${show(d.dest)}</dd><dt>Username</dt><dd>${d.user}</dd>
    <dt>Event ID</dt><dd class="mono">${d.ev}</dd><dt>Alert ID</dt><dd class="mono">${show(d.alert)}</dd><dt>Timestamp</dt><dd class="mono">${d.time}</dd></dl>
    <h3 style="font-size:14px;margin:0 0 6px">Rule description</h3><p class="note">${r.desc}</p>
    <h3 style="font-size:14px;margin:0 0 6px">Detection reason</h3><p class="note">${d.why}</p>
    <h3 style="font-size:14px;margin:0 0 6px">Recommended action</h3><p class="note">${d.act}</p>
    <p class="msg">Sample record. The backend does not store detection IDs or "No Threat" results yet.</p>`);
  renderTable();
}

function openRule(name) {
  const r = ruleOf(name);
  openDrawer(`${badge(r.sev)}<h2>${r.name}</h2><dl><dt>Status</dt><dd>${r.enabled ? "Enabled" : "Disabled"} (local only)</dd>
    <dt>Alert severity</dt><dd>${r.sev}</dd><dt>Triggers</dt><dd>${hits(name).length} (sample)</dd></dl>
    <h3 style="font-size:14px;margin:0 0 6px">Description</h3><p class="note">${r.desc}</p>
    <h3 style="font-size:14px;margin:0 0 6px">Detection logic</h3><code>${r.logic}</code>
    <p class="msg" style="margin-top:14px">Read from detection.py. Thresholds: 5 failed logins, 5 minute window.</p>
    <div class="acts"><button class="pri" id="goTest">Test Rule</button></div>`);
  $("goTest").onclick = () => openTest(name);
}

// ---------- simulated rule test ----------
const TEST_FIELDS = {
  known_malicious_ip: `<label for="t1">Event source IP</label><input id="t1" value="45.83.64.1"><p class="msg">Sample malicious IPs: ${SAMPLE_IOCS.join(", ")}</p>`,
  brute_force_login:  `<label for="t1">Failed logins for one user</label><input id="t1" type="number" min="0" value="6"><label for="t2">Within how many minutes</label><input id="t2" type="number" min="1" value="4">`,
  large_data_export:  `<label for="t1">Data export event severity</label><select id="t1"><option>critical</option><option selected>high</option><option>medium</option><option>low</option></select>`
};

function openTest(name) {
  openDrawer(`<h2>Test Rule</h2>
    <div class="sim"><b>SIMULATED.</b> This runs a copy of the rule logic in your browser. It does not call the Flask detection engine.</div>
    <label for="tr">Detection rule</label><select id="tr">${RULES.map(r => `<option ${r.name === name ? "selected" : ""}>${r.name}</option>`).join("")}</select>
    <div id="tf"></div><div class="acts" style="margin-top:16px"><button class="pri" id="run">Run test</button></div><div id="tout"></div>`);
  const fill = () => { $("tf").innerHTML = TEST_FIELDS[$("tr").value]; $("tout").innerHTML = ""; };
  $("tr").onchange = fill; fill();
  $("run").onclick = runTest;
}

function runTest() {
  const rule = $("tr").value, a = $("t1").value, b = $("t2") ? Number($("t2").value) : 0;
  let hit = false, why = "";
  if (rule === "known_malicious_ip") { hit = SAMPLE_IOCS.includes(a.trim()); why = hit ? "IP is on the sample malicious list." : "IP is not on the sample malicious list."; }
  if (rule === "brute_force_login")  { hit = Number(a) >= 5 && b <= 5; why = hit ? "5 or more failed logins within 5 minutes." : "Needs 5 or more failed logins within 5 minutes."; }
  if (rule === "large_data_export")  { hit = a === "high" || a === "critical"; why = hit ? "Export severity is high or critical." : "Export severity is below high."; }
  const sev = ruleOf(rule).sev;
  $("tout").innerHTML = hit
    ? `<div class="out hit"><b>Threat detected (simulated)</b><br>Alert severity: ${sev.toUpperCase()}<br>${why}</div>`
    : `<div class="out ok"><b>No threat (simulated)</b><br>${why}</div>`;
}

// ---------- events ----------
$("rows").onclick = e => { const r = e.target.closest("tr"); if (r) openDetection(r.dataset.id); };
$("rows").onkeydown = e => { if (e.key === "Enter") { const r = e.target.closest("tr"); if (r) openDetection(r.dataset.id); } };
$("rules").onclick = e => {
  if (e.target.dataset.rule) openRule(e.target.dataset.rule);
  if (e.target.dataset.test) openTest(e.target.dataset.test);
};
$("rules").onchange = e => { if (e.target.dataset.toggle) { ruleOf(e.target.dataset.toggle).enabled = e.target.checked; renderAll(); } };
document.onkeydown = e => { if (e.key === "Escape") closeDrawer(); };
["q","fs","fr","fres","fd"].forEach(id => $(id).oninput = renderTable);
$("clr").onclick = () => { ["q","fs","fr","fres","fd"].forEach(id => $(id).value = ""); renderTable(); };

setEngine("unknown");
renderAll();