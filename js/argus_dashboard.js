 let currentScanId =
  sessionStorage.getItem('argus_current_scan_id') || null;

  let lastUploadedFile =
    sessionStorage.getItem('argus_last_uploaded_file') || '';

  function updateCurrentScanDisplay() {
    const display = document.getElementById('currentScanDisplay');

    if (!display) return;

    const count = Number(
        sessionStorage.getItem('argus_current_scan_count') || '0'
    );

    display.textContent = `Scan: ${count}`;
}


async function createNewScan() {
  try {
    const token = localStorage.getItem('argus_token');

    const response = await fetch('http://127.0.0.1:5000/api/scans', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    const result = await response.json();

    if (!response.ok) {
      throw new Error(result.error || 'Could not create scan');
    }

    currentScanId = result.scan_id;

    sessionStorage.setItem(
      'argus_current_scan_id',
      currentScanId
    );
    // Reset the current scan counter
sessionStorage.setItem('argus_current_scan_count', '0');

updateCurrentScanDisplay();
sessionStorage.removeItem('argus_last_uploaded_file');
lastUploadedFile = '';

    console.log('ARGUS CURRENT SCAN:', currentScanId);

    return currentScanId;

  } catch (error) {
    console.error('Failed to create scan:', error);
    showToast('Could not start new scan ✕');
    return null;
  }
}
 
 const API_BASE = 'http://127.0.0.1:5000';

const token = localStorage.getItem('argus_token');

if (!token) {
  alert('You are not logged in. Please login again.');
  window.location.href = 'argus_login.html';
}

async function apiFetch(endpoint) {
  const response = await fetch(API_BASE + endpoint, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });

  if (response.status === 401) {
    localStorage.removeItem('argus_token');
    localStorage.removeItem('argus_role');
    alert('Your session has expired. Please login again.');
    window.location.href = 'argus_login.html';
    return null;
  }

  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }

  return await response.json();
}

 const css = getComputedStyle(document.documentElement);
  const tok = n => css.getPropertyValue(n).trim();

  const toastEl = document.getElementById('toast');
  let toastTimer = null;
  function showToast(msg){
    toastEl.textContent = msg;
    toastEl.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toastEl.classList.remove('show'), 2600);
  }

  document.getElementById('nav').addEventListener('click', (e) => {
    const a = e.target.closest('a');
    if (!a) return;
    e.preventDefault();
    document.querySelectorAll('.side-nav a').forEach(x => x.classList.remove('on'));
    a.classList.add('on');
    if (a.dataset.p !== 'Dashboard') showToast(a.dataset.p + ' — not wired up in this preview yet.');
  });
  document.getElementById('bellBtn').addEventListener('click', () => showToast('5 critical, 18 high — see Recent Alerts below.'));
  document.getElementById('rangeBtn').addEventListener('click', () => showToast('Front-end preview — connect a real time-range picker to your API.'));
  document.getElementById('newScanBtn').addEventListener('click', async () => {

    const scanId = await createNewScan();

    if (scanId) {
        showToast(`New Scan #${scanId} started ✓`);
        console.log('ARGUS NEW SCAN STARTED:', scanId);
    }

});


document.getElementById('scanHistoryBtn').addEventListener('click', async () => {

    console.log('ARGUS SCAN HISTORY BUTTON CLICKED');

    try {

        const scans = await apiFetch('/api/scans');

        console.log('ARGUS SCAN HISTORY FROM BACKEND:', scans);

        if (!scans || scans.length === 0) {
            alert('No scan history found.');
            return;
        }

        let message = 'ARGUS SCAN HISTORY\n\n';

        scans.forEach(scan => {

            message +=
                `Scan #${scan.id}\n` +
                `Events: ${scan.total_events}\n` +
                `Threats: ${scan.threats_found}\n` +
                `Status: ${scan.status}\n\n`;

        });

        alert(message);

    } catch (error) {

        console.error('Scan history error:', error);

        alert('Could not load scan history.');

    }

});
   

  document.getElementById('q').addEventListener('input', (e) => {
    const query = e.target.value.trim().toLowerCase();
    let shown = 0;
    document.querySelectorAll('#alertList .alertrow').forEach(row => {
      const match = !query || row.dataset.s.includes(query);
      row.classList.toggle('hide', !match);
      if (match) shown++;
    });
    document.getElementById('alertCount').textContent = shown + ' shown';
    document.querySelectorAll('#iocTable tbody tr').forEach(row => {
      row.classList.toggle('hide', !(!query || row.dataset.s.includes(query)));
    });
  });

  const askBox = document.getElementById('askBox');
  const canned = {
    explain: `<strong>Explain this alert</strong>The Critical IOC match on <b>10.0.0.4</b> fired because that address is on a known malicious-IP watchlist. It landed within minutes of the brute-force pattern on <b>192.168.217.1</b>, which is why Argus grouped them in the same window.`,
    summarize: `<strong>Summarize recent threats</strong>Last 24h: 5 critical and 18 high-severity alerts, led by IOC detections (32%) and port scans (21%). Most of the source volume traces back to the 192.168.217.0/24 range — that segment is worth a closer look.`,
    steps: `<strong>Investigation steps</strong>1) Pull the full session log for 192.168.217.1. 2) Confirm whether 10.0.0.4 reached any internal host. 3) Check for successful logins between 14:21 and 14:32. 4) If confirmed, isolate the host and rotate exposed credentials.`,
    ask: q => `<strong>Re: "${q}"</strong>This is a front-end preview — connect this box to the Argus AI API to get an answer grounded in your real event data.`
  };
  document.querySelectorAll('.askrow button').forEach(btn => {
    btn.addEventListener('click', () => { askBox.innerHTML = canned[btn.dataset.ask]; });
  });
  const askInput = document.getElementById('askInput');
  document.getElementById('askBtn').addEventListener('click', () => {
    const q = askInput.value.trim();
    if (!q) return;
    askBox.innerHTML = canned.ask(q);
    askInput.value = '';
  });
  askInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') document.getElementById('askBtn').click(); });

  Chart.defaults.font.family = "'JetBrains Mono', monospace";
  Chart.defaults.font.size = 11;
  Chart.defaults.color = tok('--muted');

  const eventsChart = new Chart(document.getElementById('eventsChart'), {
    type: 'line',
    data: {
      labels: ['00','02','04','06','08','10','12','14','16','18','20','22'],
      datasets: [{
        data: [320,260,210,180,240,520,610,860,940,720,580,410],
        borderColor: tok('--accent'), backgroundColor: tok('--accent-soft'),
        fill: true, tension: .35, pointRadius: 0, borderWidth: 2
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, border: { color: tok('--line') } },
        y: { grid: { color: tok('--hairline') }, border: { display: false } }
      }
    }
  });

  const severityChart = new Chart(document.getElementById('sevChart'), {
    type: 'doughnut',
    data: {
      labels: ['Critical','High','Medium','Low'],
      datasets: [{ data: [5, 18, 61, 42], backgroundColor: [tok('--danger'), tok('--warn'), tok('--amber'), tok('--success')], borderWidth: 0 }]
    },
    options: { responsive: true, maintainAspectRatio: false, cutout: '72%', plugins: { legend: { display: false } } }
  });

  const riskChart = new Chart(document.getElementById('riskChart'), {
    type: 'line',
    data: {
      labels: ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'],
      datasets: [{ data: [0,0,0,0,0,0,0], borderColor: tok('--warn'), backgroundColor: 'transparent',
        tension: .35, pointRadius: 3, pointBackgroundColor: tok('--warn'), borderWidth: 2 }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, border: { color: tok('--line') } },
        y: { min: 0, max: 100, grid: { color: tok('--hairline') }, border: { display: false } }
      }
    }
  });
  async function testBackendConnection() {
  try {
    const data = await apiFetch('/api/events');
    const incidents = await apiFetch('/api/incidents');

    if (incidents && incidents.length > 0) {
  const latestRisk = Number(incidents[0].risk_score || 0);

  riskChart.data.datasets[0].data =
    [latestRisk, latestRisk, latestRisk, latestRisk, latestRisk, latestRisk, latestRisk];

  riskChart.update();
}

    console.log('ARGUS INCIDENTS FROM BACKEND:', incidents);

    console.log('ARGUS EVENTS FROM BACKEND:', data);

    document.getElementById('totalEvents').textContent = data.length;
    document.getElementById('totalEvents').textContent = data.length;

const critical = data.filter(e =>
  String(e.severity).toLowerCase() === 'critical'
).length;

const high = data.filter(e =>
  String(e.severity).toLowerCase() === 'high'
).length;

const medium = data.filter(e =>
  String(e.severity).toLowerCase() === 'medium'
).length;

const low = data.filter(e =>
  String(e.severity).toLowerCase() === 'low'
).length;

document.getElementById('criticalCount').textContent = critical;
document.getElementById('highCount').textContent = high;
document.getElementById('mediumCount').textContent = medium;
document.getElementById('lowCount').textContent = low;
// Count events by hour
const hourlyCounts = Array(12).fill(0);

data.forEach(event => {
  if (!event.timestamp) return;

  const hour = new Date(event.timestamp).getHours();

  // Chart uses 00, 02, 04 ... 22
  const index = Math.floor(hour / 2);

  if (index >= 0 && index < 12) {
    hourlyCounts[index]++;
  }
});

eventsChart.data.datasets[0].data = hourlyCounts;
eventsChart.update();
document.getElementById('severityTotal').textContent =
  critical + high + medium + low;

document.getElementById('severityCritical').textContent = critical;
document.getElementById('severityHigh').textContent = high;
document.getElementById('severityMedium').textContent = medium;
document.getElementById('severityLow').textContent = low;

severityChart.data.datasets[0].data = [critical, high, medium, low];
severityChart.update();
const alertsRaised = data.filter(e =>
  Number(e.ioc_match) === 1
).length;

document.getElementById('alertsRaised').textContent = alertsRaised;

// Update Top Source IPs from real backend events
const sourceCounts = {};

data.forEach(event => {
  const ip = event.source_ip || event.dest_ip;

  if (!ip) return;

  sourceCounts[ip] = (sourceCounts[ip] || 0) + 1;
});

const topSources = Object.entries(sourceCounts)
  .sort((a, b) => b[1] - a[1])
  .slice(0, 4);

const sourceTable = document.querySelector('.grid3 table:not(#iocTable) tbody');

if (sourceTable) {
  sourceTable.innerHTML = '';

  topSources.forEach(([ip, count]) => {
    const row = document.createElement('tr');

    row.innerHTML = `
      <td class="ink mono">${ip}</td>
      <td class="mono">${count}</td>
    `;

    sourceTable.appendChild(row);
  });
}

// Update Overall Risk from backend
if (incidents && incidents.length > 0) {
  const incident = incidents[0];

  const score = Number(incident.risk_score || 0);
  const level = String(incident.risk_level || 'low').toLowerCase();

  document.getElementById('riskScore').textContent = score;

  const riskLevelText =
    level.charAt(0).toUpperCase() + level.slice(1) + ' Risk';

  document.getElementById('riskLevel').textContent = riskLevelText;

  document.getElementById('riskDescription').textContent =
    incident.title || `Current Argus risk level is ${level}.`;
} else {
  document.getElementById('riskScore').textContent = '0';
  document.getElementById('riskLevel').textContent = 'Low Risk';
  document.getElementById('riskDescription').textContent =
    'No active security incidents.';
}

showToast('Backend connected successfully ✓');
updateCurrentScanDisplay();

// Display real recent events
const alertList = document.getElementById('alertList');

alertList.innerHTML = '';

data.slice(0, 5).forEach(event => {
  const row = document.createElement('div');

  const severity = String(event.severity || 'low').toLowerCase();

  let severityClass = 'low';

  if (severity === 'critical') {
    severityClass = 'critical';
  } else if (severity === 'high') {
    severityClass = 'high';
  } else if (severity === 'medium') {
    severityClass = 'medium';
  }

  const time = event.timestamp
    ? new Date(event.timestamp).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit'
      })
    : '--:--';

  const ip = event.source_ip || event.dest_ip || 'Unknown source';

  row.className = 'alertrow';

  row.dataset.s =
    `${event.event_type || ''} ${ip} ${severity} ${event.details || ''}`
      .toLowerCase();

  row.innerHTML = `
    <i class="adot"></i>

    <div class="amain">
      <strong>${event.event_type || 'Security Event'}</strong>
      <small>${ip} · ${time}</small>
    </div>

    <span class="tag ${severityClass}">
      ${severity.toUpperCase()}
    </span>
  `;

  alertList.appendChild(row);
});

document.getElementById('alertCount').textContent =
  `${Math.min(data.length, 5)} shown`;

  // Update Attack / Threat Types from real backend events
const threatCounts = {};

data.forEach(event => {
  let type = String(event.event_type || 'Other').toLowerCase();

  if (Number(event.ioc_match) === 1) {
    type = 'IOC Detection';
  } else if (type.includes('scan')) {
    type = 'Port Scan';
  } else if (type.includes('brute') || type.includes('failed_login')) {
  type = 'Brute Force';
  } else if (
  type.includes('suspicious') ||
  type.includes('outbound') ||
  type.includes('data_export')
) {
  type = 'Suspicious Traffic';
} else {
    type = 'Other';
  }

  threatCounts[type] = (threatCounts[type] || 0) + 1;
});

const totalThreatEvents = data.length || 1;

const threatRows = document.querySelectorAll('.grid3 .brow');

const threatTypes = [
  'IOC Detection',
  'Port Scan',
  'Brute Force',
  'Suspicious Traffic',
  'Other'
];

threatRows.forEach((row, index) => {
  const type = threatTypes[index];
  const count = threatCounts[type] || 0;
  const percentage = Math.round(
    (count / totalThreatEvents) * 100
  );

  const value = row.querySelector('.bmeta b');
  const bar = row.querySelector('.bfill');

  if (value) value.textContent = percentage + '%';
  if (bar) bar.style.width = percentage + '%';
});

  // Update IOC / Threat Intel from real backend events
const iocTable = document.querySelector('#iocTable tbody');

if (iocTable) {
  iocTable.innerHTML = '';

  const iocEvents = data.filter(event => Number(event.ioc_match) === 1);

  iocEvents.forEach(event => {
    const row = document.createElement('tr');

    const indicator =
      event.source_ip ||
      event.dest_ip ||
      'Unknown';

    const severity =
      String(event.severity || 'unknown').toUpperCase();

    row.innerHTML = `
      <td class="ink">IP</td>
      <td class="mono">${indicator}</td>
      <td>
        <span class="tag ${severity.toLowerCase()}">
          ${severity}
        </span>
      </td>
    `;

    iocTable.appendChild(row);
  });

  if (iocEvents.length === 0) {
    iocTable.innerHTML = `
      <tr>
        <td colspan="3" class="muted">
          No IOC matches detected
        </td>
      </tr>
    `;
  }
}

  } catch (error) {
    console.error('Backend connection failed:', error);
    showToast('Backend connection failed ✕');
  }
}

testBackendConnection();
const logFileInput = document.getElementById('logFileInput');


logFileInput.addEventListener('change', async (event) => {
    const file = event.target.files[0];

if (!file) return;

const fileKey = `${file.name}-${file.size}-${file.lastModified}`;

if (fileKey === lastUploadedFile) {
    showToast('This log file was already scanned.');
    logFileInput.value = '';
    return;
}

lastUploadedFile = fileKey;
sessionStorage.setItem('argus_last_uploaded_file', fileKey);

    try {
        console.log('Log file selected:', file.name);

        const text = await file.text();
        const log = JSON.parse(text);

        // Convert uploaded log format into Argus event format
        let argusEvent = {
            type: log.event_type || log.type || 'unknown',
            src_ip: log.source_ip || log.src_ip || '',
            user: log.username || log.user || '',
            severity: log.severity || 'low',
            timestamp: log.timestamp || new Date().toISOString()
        };

        // Failed login detection
        if (
            argusEvent.type === 'login' &&
            String(log.status).toLowerCase() === 'failed'
        ) {
            argusEvent.type = 'failed_login';
        }

        console.log('Event sent to Argus:', argusEvent);

        // Make sure a scan exists
if (!currentScanId) {
    currentScanId = await createNewScan();
}

if (!currentScanId) {
    throw new Error('No active scan. Please click New Scan.');
}

const response = await fetch('http://127.0.0.1:5000/api/events', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
        'X-Scan-ID': String(currentScanId)
    },
    body: JSON.stringify(argusEvent)
});

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Backend rejected the event');
        }

        console.log('ARGUS SCAN RESULT:', result);
        // Show Argus Scan Result
const scanResult = document.getElementById('scanResult');

if (scanResult) {
    scanResult.style.display = 'block';

    document.getElementById('scanFileName').textContent =
        `File: ${file.name}`;

    document.getElementById('scanEventType').textContent =
        log.event_type || log.type || 'Unknown';

    document.getElementById('scanSourceIp').textContent =
        log.source_ip || log.src_ip || 'Unknown';

    document.getElementById('scanEventSeverity').textContent =
        String(log.severity || 'low').toUpperCase();

    const alert = result.alerts && result.alerts.length > 0
        ? result.alerts[0]
        : null;

    document.getElementById('scanDetection').textContent =
    result.alerts && result.alerts.length > 0
        ? result.alerts.map(a => a.rule.replaceAll('_', ' ')).join(', ')
        : 'No threat detected';

    document.getElementById('scanDetectionSeverity').textContent =
        alert ? String(alert.severity).toUpperCase() : 'NONE';

    document.getElementById('scanRiskScore').textContent =
        result.risk_score !== undefined
            ? `${result.risk_score} / 100`
            : 'N/A';

    document.getElementById('scanRiskLevel').textContent =
        result.risk_level
            ? String(result.risk_level).toUpperCase()
            : 'LOW';
}

        showToast('Log scanned successfully ✓');

        let currentScanCount = Number(
    sessionStorage.getItem('argus_current_scan_count') || '0'
);

currentScanCount++;

sessionStorage.setItem(
    'argus_current_scan_count',
    String(currentScanCount)
);

updateCurrentScanDisplay();




// Refresh dashboard with latest backend data
await testBackendConnection();

    } catch (error) {
        console.error('Log scanning failed:', error);
        showToast('Log scanning failed ✕');
    }

    // Allow selecting the same file again
    logFileInput.value = '';
});
// Display the currently logged-in user
const username = localStorage.getItem('argus_username') || 'User';
const role = localStorage.getItem('argus_role') || 'analyst';

const displayUsername = document.getElementById('displayUsername');
const displayRole = document.getElementById('displayRole');
const userInitials = document.getElementById('userInitials');
const topUserInitials = document.getElementById('topUserInitials');



if (displayUsername) {
  displayUsername.textContent = username;
}

if (displayRole) {
  displayRole.textContent = role.toUpperCase();
}

if (userInitials) {
  const initials = username
    .trim()
    .split(/\s+/)
    .map(word => word[0])
    .join('')
    .slice(0, 2)
    .toUpperCase();

  userInitials.textContent = initials || 'U';
}

if (topUserInitials) {
  const initials = username
    .trim()
    .split(/\s+/)
    .map(word => word[0])
    .join('')
    .slice(0, 2)
    .toUpperCase();

  topUserInitials.textContent = initials || 'U';
}