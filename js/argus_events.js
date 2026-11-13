const E=[
["14:32","Port Scan Detected","Port Scan","192.168.217.128","Firewall","high","open","Sequential connection attempts across 1,024 ports in under 40 seconds.","Block the source at the firewall and check the target hosts for exposed services."],
["14:28","Malicious IP Match","IOC Match","10.0.0.4","Threat Intel","critical","open","Outbound connection matched an IP on the malicious watchlist.","Isolate the host, capture traffic, and review what was sent."],
["14:21","Brute Force Attempt","Brute Force","192.168.217.1","Auth Logs","high","investigating","47 failed logins against the admin account within 5 minutes.","Lock the account, force a password reset, and confirm no login succeeded."],
["13:57","Suspicious Outbound Traffic","Outbound Traffic","10.0.1.44","Proxy","medium","open","Repeated uploads to an unfamiliar domain outside business hours.","Review the destination domain and the user's recent activity."],
["13:46","Privilege Escalation Signal","Privilege Escalation","server-03","Endpoint","medium","open","A standard user process started with elevated rights.","Check the process tree and recent changes to local groups."],
["13:12","Successful Login","Login","192.168.217.30","Auth Logs","low","closed","Normal login from a known workstation.","No action needed."],
["12:40","Rare Domain Lookup","DNS","10.0.1.61","DNS","low","closed","First lookup of this domain from the network in 30 days.","Reviewed and found benign."],
["12:05","Port Scan Detected","Port Scan","203.0.113.4","Firewall","high","closed","External scan of the public web tier, blocked at the edge.","Source added to the blocklist."],
["11:20","Large Data Transfer","Outbound Traffic","10.0.1.44","Proxy","high","investigating","2.3 GB sent to an external host in one session.","Confirm the transfer with the host's owner."],
["10:54","New Admin Account","Privilege Escalation","server-01","Endpoint","medium","open","A local administrator account was created outside change windows.","Verify who created it and disable it if unplanned."],
["10:31","Unusual DNS Volume","DNS","10.0.1.61","DNS","medium","closed","DNS queries ran 6x above the host's normal rate.","Traced to a software update; closed."],
["09:58","Scheduled Task Login","Login","192.168.217.30","Auth Logs","low","closed","Service account login from a known workstation.","No action needed."]
].map((r,i)=>({id:"EV-"+(4120-i),time:r[0],name:r[1],type:r[2],ip:r[3],src:r[4],sev:r[5],st:r[6],desc:r[7],act:r[8]}));
E.sort((a,b)=>b.time.localeCompare(a.time));
const $=id=>document.getElementById(id),PS=8;let page=1,desc=true,sel=null;
[...new Set(E.map(e=>e.type))].forEach(t=>$("ft").add(new Option(t,t)));
const cap=s=>s[0].toUpperCase()+s.slice(1);
function list(){
  const q=$("q").value.toLowerCase(),s=$("fs").value,t=$("ft").value,st=$("fst").value;
  return E.filter(e=>(!s||e.sev===s)&&(!t||e.type===t)&&(!st||e.st===st)&&(!q||[e.name,e.type,e.ip,e.src,e.id].join(" ").toLowerCase().includes(q)))
    .sort((a,b)=>desc?b.time.localeCompare(a.time):a.time.localeCompare(b.time));
}
function render(){
  const L=list(),pages=Math.max(1,Math.ceil(L.length/PS));page=Math.min(page,pages);
  const c=k=>L.filter(e=>e.sev===k).length;
  $("stats").innerHTML=[[L.length,"Shown events",""],[c("critical"),"Critical","c-critical"],[c("high"),"High","c-high"],[c("medium"),"Medium","c-medium"],[c("low"),"Low","c-low"]]
    .map(x=>`<div class="stat"><b class="${x[2]}">${x[0]}</b><span>${x[1]}</span></div>`).join("");
  const P=L.slice((page-1)*PS,page*PS);
  $("rows").innerHTML=P.map(e=>`<tr tabindex="0" data-id="${e.id}" class="${sel===e.id?"sel":""}"><td class="mono">${e.time}</td><td class="ev">${e.name}</td><td>${e.type}</td><td class="mono">${e.ip}</td><td>${e.src}</td><td><span class="badge ${e.sev}">${e.sev.toUpperCase()}</span></td><td class="st-${e.st}">${e.st.toUpperCase()}</td></tr>`).join("");
  $("none").hidden=L.length>0;
  $("cnt").textContent=L.length+" events";$("pn").textContent=page+" / "+pages;
  $("prev").disabled=page<=1;$("next").disabled=page>=pages;$("arr").textContent=desc?"▼":"▲";
}
function open(id){
  const e=E.find(x=>x.id===id);sel=id;
  $("dr").innerHTML=`<button class="x" id="cl" aria-label="Close details">✕</button><span class="badge ${e.sev}">${e.sev.toUpperCase()}</span><h2>${e.name}</h2><div class="mono" style="color:var(--mute)">${e.id} · ${e.time}</div>
  <dl><dt>Type</dt><dd>${e.type}</dd><dt>Source IP</dt><dd class="mono">${e.ip}</dd><dt>Log source</dt><dd>${e.src}</dd><dt>Status</dt><dd class="st-${e.st}">${cap(e.st)}</dd></dl>
  <h3 style="font-size:14px;margin:0 0 6px">What happened</h3><p class="note">${e.desc}</p>
  <h3 style="font-size:14px;margin:0 0 6px">Suggested next step</h3><p class="note">${e.act}</p>
  <div class="acts"><button class="pri">Investigate</button><button>Create alert</button></div>`;
  $("dr").classList.add("open");$("dr").setAttribute("aria-hidden","false");$("cl").onclick=close;$("cl").focus();render();
}
function close(){sel=null;$("dr").classList.remove("open");$("dr").setAttribute("aria-hidden","true");render()}
$("rows").onclick=e=>{const r=e.target.closest("tr");if(r)open(r.dataset.id)};
$("rows").onkeydown=e=>{if(e.key==="Enter"){const r=e.target.closest("tr");if(r)open(r.dataset.id)}};
document.onkeydown=e=>{if(e.key==="Escape")close()};
["q","fs","ft","fst"].forEach(i=>$(i).oninput=()=>{page=1;render()});
$("clr").onclick=()=>{["q","fs","ft","fst"].forEach(i=>$(i).value="");page=1;render()};
$("sortT").onclick=()=>{desc=!desc;render()};
$("prev").onclick=()=>{page--;render()};$("next").onclick=()=>{page++;render()};
$("csv").onclick=()=>{
  const h=["Time","Event","Type","Source IP","Log source","Severity","Status"];
  const t=[h,...list().map(e=>[e.time,e.name,e.type,e.ip,e.src,e.sev,e.st])].map(r=>r.map(v=>'"'+v+'"').join(",")).join("\n");
  $("csv").textContent="Copied to clipboard";try{navigator.clipboard.writeText(t)}catch(_){$("csv").textContent="Copy blocked"}
  setTimeout(()=>$("csv").textContent="Export CSV",1800);
};
render();