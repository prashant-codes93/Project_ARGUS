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

  new Chart(document.getElementById('eventsChart'), {
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

  new Chart(document.getElementById('sevChart'), {
    type: 'doughnut',
    data: {
      labels: ['Critical','High','Medium','Low'],
      datasets: [{ data: [5,18,61,42], backgroundColor: [tok('--danger'), tok('--warn'), tok('--amber'), tok('--success')], borderWidth: 0 }]
    },
    options: { responsive: true, maintainAspectRatio: false, cutout: '72%', plugins: { legend: { display: false } } }
  });

  new Chart(document.getElementById('riskChart'), {
    type: 'line',
    data: {
      labels: ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'],
      datasets: [{ data: [58,61,55,64,70,66,72], borderColor: tok('--warn'), backgroundColor: 'transparent',
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