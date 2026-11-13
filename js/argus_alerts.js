/* ARGUS Alerts page (frontend prototype).
   All data below is SAMPLE data. Button actions only change this page's
   local copy; nothing is saved to the backend (no alerts API exists yet). */

// The three real rules from detection.py
const RULES = {
  known_malicious_ip: "Detects an event matching a known malicious IP.",
  brute_force_login:  "Detects five or more failed login events within five minutes.",
  large_data_export:  "Detects a high or critical severity data export event."
};

// Sample alerts. Severity follows detection.py: two rules are high, one is medium.
// Later, replace this array with data fetched from a future GET /api/alerts.
const ALERTS = [
  { id:"AL-1009", name:"Large Data Export",          rule:"large_data_export",  sev:"medium", ip:"10.0.0.30",  dest:"203.0.113.50", user:"svc_backup", time:"2026-11-11 10:20", status:"open",         eventId:"EV-4120", incidentId:"INC-3",
    desc:"A data export event with critical event severity was recorded for this host.",
    act:"Confirm the export with the data owner and review what was sent." },
  { id:"AL-1008", name:"Brute Force Login Attempt",  rule:"brute_force_login",  sev:"high",   ip:"10.0.0.20",  dest:"10.0.0.5",     user:"admin",      time:"2026-11-11 10:00", status:"open",         eventId:"EV-4119", incidentId:"INC-3",
    desc:"Five or more failed logins for the same user within five minutes.",
    act:"Lock the account, reset the password and confirm no login succeeded." },
  { id:"AL-1007", name:"Brute Force Login Attempt",  rule:"brute_force_login",  sev:"high",   ip:"45.83.64.1", dest:"10.0.0.5",     user:"root",       time:"2026-11-11 09:05", status:"acknowledged", eventId:"EV-4118", incidentId:null,
    desc:"Repeated failed logins for the root user from an external address.",
    act:"Block the source IP and check authentication logs for a success." },
  { id:"AL-1006", name:"Known Malicious IP Detected", rule:"known_malicious_ip", sev:"high",   ip:"45.83.64.1", dest:null,           user:"admin",      time:"2026-11-10 22:41", status:"resolved",     eventId:"EV-4110", incidentId:"INC-2",
    desc:"An event matched an IP address on the threat-intelligence list.",
    act:"Source was blocked at the firewall. No further action needed." },
  { id:"AL-1005", name:"Large Data Export",          rule:"large_data_export",  sev:"medium", ip:"10.0.0.31",  dest:"198.51.100.7", user:"analyst1",   time:"2026-11-10 16:12", status:"acknowledged", eventId:"EV-4104", incidentId:null,
    desc:"A high severity data export event was recorded.",
    act:"Verify the export was approved and check the destination." },
  { id:"AL-1004", name:"Known Malicious IP Detected", rule:"known_malicious_ip", sev:"high",   ip:"185.220.101.4", dest:"10.0.0.8",  user:"unknown",    time:"2026-11-09 13:30", status:"open",         eventId:"EV-4091", incidentId:"INC-1",
    desc:"Inbound traffic matched a known malicious IP.",
    act:"Isolate the targeted host and review its recent connections." },
  { id:"AL-1003", name:"Brute Force Login Attempt",  rule:"brute_force_login",  sev:"high",   ip:"10.0.0.22",  dest:"10.0.0.5",     user:"dev_user",   time:"2026-11-08 18:55", status:"resolved",     eventId:"EV-4080", incidentId:null,
    desc:"Five failed logins in a short window, caused by a forgotten password.",
    act:"Confirmed with the user. No action needed." }
];

const $ = id => document.getElementById(id);
const PAGE_SIZE = 8;
let page = 1, selected = null;

const cap = s => s[0].toUpperCase() + s.slice(1);
const show = v => v ? v : "N/A";

// ---------- filtering ----------
function getFiltered() {
  const q = $("q").value.toLowerCase(), sev = $("fs").value, st = $("fst").value, day = $("fd").value;
  return ALERTS.filter(a =>
    (!sev || a.sev === sev) &&
    (!st || a.status === st) &&
    (!day || a.time.startsWith(day)) &&
    (!q || [a.id, a.name, a.rule, a.ip, a.user].join(" ").toLowerCase().includes(q))
  ).sort((a, b) => b.time.localeCompare(a.time));
}

// ---------- rendering ----------
function renderStats() {
  const count = fn => ALERTS.filter(fn).length;
  const cards = [
    [ALERTS.length, "Total Alerts", ""],
    [count(a => a.sev === "critical"), "Critical Alerts", "c-critical"],
    [count(a => a.sev === "high"), "High Severity Alerts", "c-high"],
    [count(a => a.status === "acknowledged"), "Acknowledged Alerts", ""]
  ];
  $("stats").innerHTML = cards.map(c => `<div class="stat"><b class="${c[2]}">${c[0]}</b><span>${c[1]}</span></div>`).join("");
}

function render() {
  const list = getFiltered();
  const pages = Math.max(1, Math.ceil(list.length / PAGE_SIZE));
  page = Math.min(page, pages);
  const rows = list.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  $("rows").innerHTML = rows.map(a => `
    <tr tabindex="0" data-id="${a.id}" class="${selected === a.id ? "sel" : ""}">
      <td class="mono">${a.id}</td>
      <td class="ev">${a.name}</td>
      <td class="rule">${a.rule}</td>
      <td><span class="badge ${a.sev}">${a.sev.toUpperCase()}</span></td>
      <td class="mono">${a.ip}</td>
      <td>${a.user}</td>
      <td class="mono">${a.time}</td>
      <td class="st-${a.status}">${a.status.toUpperCase()}</td>
      <td><button class="view-btn" data-id="${a.id}">View</button></td>
    </tr>`).join("");

  $("none").hidden = list.length > 0;
  $("cnt").textContent = list.length + " alerts";
  $("pn").textContent = page + " / " + pages;
  $("prev").disabled = page <= 1;
  $("next").disabled = page >= pages;
  renderStats();
}

// ---------- details drawer ----------
function openDrawer(id, message) {
  const a = ALERTS.find(x => x.id === id);
  selected = id;
  $("dr").innerHTML = `
    <button class="x" id="cl" aria-label="Close details">✕</button>
    <span class="badge ${a.sev}">${a.sev.toUpperCase()}</span>
    <h2>${a.name}</h2>
    <div class="mono" style="color:var(--mute)">${a.id} · ${a.time}</div>
    <dl>
      <dt>Detection rule</dt><dd class="mono">${a.rule}</dd>
      <dt>Status</dt><dd class="st-${a.status}">${cap(a.status)}</dd>
      <dt>Source IP</dt><dd class="mono">${a.ip}</dd>
      <dt>Destination IP</dt><dd class="mono">${show(a.dest)}</dd>
      <dt>Username</dt><dd>${a.user}</dd>
      <dt>Event ID</dt><dd class="mono">${a.eventId}</dd>
      <dt>Incident ID</dt><dd class="mono">${show(a.incidentId)}</dd>
      <dt>Timestamp</dt><dd class="mono">${a.time}</dd>
    </dl>
    <h3 style="font-size:14px;margin:0 0 6px">Description</h3>
    <p class="note">${a.desc}<br><small>Rule: ${RULES[a.rule]}</small></p>
    <h3 style="font-size:14px;margin:0 0 6px">Recommended action</h3>
    <p class="note">${a.act}</p>
    <p class="msg">${message || "Prototype: actions change sample data on this page only."}</p>
    <div class="acts">
      <button id="ack" ${a.status !== "open" ? "disabled" : ""}>Acknowledge</button>
      <button id="inv" class="pri" ${a.status === "resolved" ? "disabled" : ""}>Investigate</button>
      <button id="res" ${a.status === "resolved" ? "disabled" : ""}>Resolve</button>
    </div>`;
  $("dr").classList.add("open");
  $("dr").setAttribute("aria-hidden", "false");
  $("cl").onclick = closeDrawer;
  $("ack").onclick = () => setStatus(id, "acknowledged");
  $("res").onclick = () => setStatus(id, "resolved");
  $("inv").onclick = () => investigate(id);
  render();
}

function closeDrawer() {
  selected = null;
  $("dr").classList.remove("open");
  $("dr").setAttribute("aria-hidden", "true");
  render();
}

// ---------- sample actions (local only) ----------
function setStatus(id, status) {
  ALERTS.find(x => x.id === id).status = status;
  openDrawer(id, "Status set to " + status + " (sample data only, not saved).");
}

function investigate(id) {
  const a = ALERTS.find(x => x.id === id);
  if (a.status === "open") a.status = "acknowledged";
  openDrawer(id, "Investigations page is not built yet. Alert marked as acknowledged for now.");
}

// ---------- events ----------
$("rows").onclick = e => {
  const row = e.target.closest("tr");
  if (row) openDrawer(row.dataset.id);
};
$("rows").onkeydown = e => {
  if (e.key === "Enter") { const row = e.target.closest("tr"); if (row) openDrawer(row.dataset.id); }
};
document.onkeydown = e => { if (e.key === "Escape") closeDrawer(); };

["q", "fs", "fst", "fd"].forEach(id => $(id).oninput = () => { page = 1; render(); });
$("clr").onclick = () => { ["q", "fs", "fst", "fd"].forEach(id => $(id).value = ""); page = 1; render(); };
$("prev").onclick = () => { page--; render(); };
$("next").onclick = () => { page++; render(); };

render();