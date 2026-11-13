/* ============================================================
   ARGUS SECURITY DASHBOARD
   Complete live-backend dashboard JavaScript
   ============================================================ */


/* ============================================================
   1. CONFIGURATION
   ============================================================ */

const API_BASE = 'http://127.0.0.1:5000';

let currentScanId =
    sessionStorage.getItem('argus_current_scan_id') || null;

let lastUploadedFile =
    sessionStorage.getItem('argus_last_uploaded_file') || '';


/* ============================================================
   2. AUTHENTICATION
   ============================================================ */

const initialToken =
    localStorage.getItem('argus_token');

if (!initialToken) {
    alert('You are not logged in. Please login again.');
    window.location.href = 'argus_login.html';
}


/* ============================================================
   3. CURRENT SCAN DISPLAY
   ============================================================ */

function updateCurrentScanDisplay() {

    const display =
        document.getElementById('currentScanDisplay');

    if (!display) return;

    const count = Number(
        sessionStorage.getItem(
            'argus_current_scan_count'
        ) || '0'
    );

    display.textContent = `Scan: ${count}`;
}


/* ============================================================
   4. TOAST
   ============================================================ */

const toastEl =
    document.getElementById('toast');

let toastTimer = null;

function showToast(message) {

    if (!toastEl) return;

    toastEl.textContent = message;

    toastEl.classList.add('show');

    clearTimeout(toastTimer);

    toastTimer = setTimeout(() => {

        toastEl.classList.remove('show');

    }, 2600);
}


/* ============================================================
   5. API GET
   ============================================================ */

async function apiFetch(endpoint) {

    const token =
        localStorage.getItem('argus_token');

    const response = await fetch(
        API_BASE + endpoint,
        {
            method: 'GET',

            headers: {
                'Authorization':
                    `Bearer ${token}`,

                'Content-Type':
                    'application/json'
            }
        }
    );


    if (response.status === 401) {

        localStorage.removeItem('argus_token');
        localStorage.removeItem('argus_role');

        alert(
            'Your session has expired. Please login again.'
        );

        window.location.href =
            'argus_login.html';

        return null;
    }


    if (!response.ok) {

        throw new Error(
            `API error: ${response.status}`
        );
    }


    return await response.json();
}


/* ============================================================
   6. CREATE NEW SCAN
   ============================================================ */

async function createNewScan() {

    try {

        const token =
            localStorage.getItem('argus_token');

        const response =
            await fetch(
                `${API_BASE}/api/scans`,
                {
                    method: 'POST',

                    headers: {
                        'Authorization':
                            `Bearer ${token}`
                    }
                }
            );


        const result =
            await response.json();


        if (!response.ok) {

            throw new Error(
                result.error ||
                'Could not create scan'
            );
        }


        currentScanId =
            result.scan_id;


        sessionStorage.setItem(
            'argus_current_scan_id',
            String(currentScanId)
        );


        sessionStorage.setItem(
            'argus_current_scan_count',
            '0'
        );


        sessionStorage.removeItem(
            'argus_last_uploaded_file'
        );


        lastUploadedFile = '';


        updateCurrentScanDisplay();


        console.log(
            '[ARGUS] New scan created:',
            currentScanId
        );


        return currentScanId;


    } catch (error) {

        console.error(
            '[ARGUS] Failed to create scan:',
            error
        );

        showToast(
            'Could not start new scan ✕'
        );

        return null;
    }
}


/* ============================================================
   7. NAVIGATION
   ============================================================ */

const nav =
    document.getElementById('nav');

if (nav) {

    nav.addEventListener(
        'click',
        (event) => {

            const link =
                event.target.closest('a');

            if (!link) return;

            const page =
                link.dataset.p;

            if (
                page === 'Alerts' &&
                link.getAttribute('href') &&
                link.getAttribute('href') !== '#'
            ) {
                return;
            }

            event.preventDefault();

            document
                .querySelectorAll('.side-nav a')
                .forEach(item => {
                    item.classList.remove('on');
                });

            link.classList.add('on');

            if (page !== 'Dashboard') {

                showToast(
                    `${page} — not wired up yet.`
                );
            }
        }
    );
}


/* ============================================================
   8. BELL
   ============================================================ */

const bellBtn =
    document.getElementById('bellBtn');

if (bellBtn) {

    bellBtn.addEventListener(
        'click',
        async () => {

            try {

                const incidents =
                    await apiFetch(
                        '/api/incidents'
                    );

                const count =
                    Array.isArray(incidents)
                        ? incidents.length
                        : 0;

                showToast(
                    `${count} alert(s) currently detected.`
                );

            } catch (error) {

                console.error(
                    '[ARGUS] Alert loading failed:',
                    error
                );

                showToast(
                    'Could not load alerts ✕'
                );
            }
        }
    );
}


/* ============================================================
   9. RANGE BUTTON
   ============================================================ */

const rangeBtn =
    document.getElementById('rangeBtn');

if (rangeBtn) {

    rangeBtn.addEventListener(
        'click',
        () => {

            showToast(
                'Dashboard is displaying live backend data.'
            );
        }
    );
}


/* ============================================================
   10. NEW SCAN BUTTON
   ============================================================ */

const newScanBtn =
    document.getElementById('newScanBtn');

if (newScanBtn) {

    newScanBtn.addEventListener(
        'click',
        async () => {

            const scanId =
                await createNewScan();

            if (scanId) {

                showToast(
                    `New Scan #${scanId} started ✓`
                );
            }
        }
    );
}


/* ============================================================
   11. SCAN HISTORY
   ============================================================ */

const scanHistoryBtn =
    document.getElementById(
        'scanHistoryBtn'
    );

if (scanHistoryBtn) {

    scanHistoryBtn.addEventListener(
        'click',
        async () => {

            try {

                console.log(
                    '[ARGUS] Loading scan history...'
                );

                const scans =
                    await apiFetch(
                        '/api/scans'
                    );


                if (
                    !Array.isArray(scans) ||
                    scans.length === 0
                ) {

                    alert(
                        'No scan history found.'
                    );

                    return;
                }


                let message =
                    'ARGUS SCAN HISTORY\n\n';


                scans.forEach(scan => {

                    message +=
                        `Scan #${scan.id}\n` +
                        `Events: ${scan.total_events}\n` +
                        `Threats: ${scan.threats_found}\n` +
                        `Status: ${scan.status}\n\n`;

                });


                alert(message);


            } catch (error) {

                console.error(
                    '[ARGUS] Scan history error:',
                    error
                );

                alert(
                    'Could not load scan history.'
                );
            }
        }
    );
}


/* ============================================================
   12. SEARCH
   ============================================================ */

const searchBox =
    document.getElementById('q');

if (searchBox) {

    searchBox.addEventListener(
        'input',
        event => {

            const query =
                event.target.value
                    .trim()
                    .toLowerCase();


            let shown = 0;


            document
                .querySelectorAll(
                    '#alertList .alertrow'
                )
                .forEach(row => {

                    const text =
                        row.dataset.s || '';

                    const match =
                        !query ||
                        text.includes(query);

                    row.classList.toggle(
                        'hide',
                        !match
                    );

                    if (match) {
                        shown++;
                    }
                });


            const alertCount =
                document.getElementById(
                    'alertCount'
                );


            if (alertCount) {

                alertCount.textContent =
                    `${shown} shown`;
            }


            document
                .querySelectorAll(
                    '#iocTable tbody tr'
                )
                .forEach(row => {

                    const text =
                        row.dataset.s || '';

                    const match =
                        !query ||
                        text.includes(query);

                    row.classList.toggle(
                        'hide',
                        !match
                    );
                });
        }
    );
}


/* ============================================================
   13. AI PREVIEW
   ============================================================ */

const askBox =
    document.getElementById('askBox');

const cannedResponses = {

    explain:
        `<strong>Explain this alert</strong>
        <br><br>
        Review the event type, source IP, severity,
        detection rule and risk score shown by Argus.`,

    summarize:
        `<strong>Summarize recent threats</strong>
        <br><br>
        This dashboard summary is based on the
        current events and incidents returned
        by the Argus backend.`,

    steps:
        `<strong>Investigation steps</strong>
        <br><br>
        Review the affected source IP, event type,
        severity, detection rule and risk score.`,

    ask: question =>
        `<strong>Re: "${question}"</strong>
        <br><br>
        AI investigation is not connected yet.
        The dashboard currently uses live Argus
        event and incident data.`
};


document
    .querySelectorAll('.askrow button')
    .forEach(button => {

        button.addEventListener(
            'click',
            () => {

                const key =
                    button.dataset.ask;

                if (
                    askBox &&
                    cannedResponses[key]
                ) {

                    askBox.innerHTML =
                        cannedResponses[key];
                }
            }
        );
    });


const askInput =
    document.getElementById(
        'askInput'
    );

const askBtn =
    document.getElementById(
        'askBtn'
    );


if (askBtn) {

    askBtn.addEventListener(
        'click',
        () => {

            const question =
                askInput
                    ? askInput.value.trim()
                    : '';

            if (!question) return;


            if (askBox) {

                askBox.innerHTML =
                    cannedResponses.ask(
                        question
                    );
            }


            if (askInput) {

                askInput.value = '';
            }
        }
    );
}


if (askInput) {

    askInput.addEventListener(
        'keydown',
        event => {

            if (event.key === 'Enter') {

                askBtn?.click();
            }
        }
    );
}


/* ============================================================
   14. CHART CONFIGURATION
   ============================================================ */

function cssValue(name) {

    return getComputedStyle(
        document.documentElement
    )
        .getPropertyValue(name)
        .trim();
}


if (typeof Chart !== 'undefined') {

    Chart.defaults.font.family =
        "'JetBrains Mono', monospace";

    Chart.defaults.font.size = 11;

    Chart.defaults.color =
        cssValue('--muted');
}


/* ============================================================
   15. EVENTS CHART
   ============================================================ */

const eventsCanvas =
    document.getElementById(
        'eventsChart'
    );

let eventsChart = null;


if (
    eventsCanvas &&
    typeof Chart !== 'undefined'
) {

    eventsChart =
        new Chart(
            eventsCanvas,
            {
                type: 'line',

                data: {

                    labels: [
                        '00',
                        '02',
                        '04',
                        '06',
                        '08',
                        '10',
                        '12',
                        '14',
                        '16',
                        '18',
                        '20',
                        '22'
                    ],

                    datasets: [
                        {
                            data:
                                Array(12).fill(0),

                            borderColor:
                                cssValue('--accent'),

                            backgroundColor:
                                cssValue('--accent-soft'),

                            fill: true,

                            tension: 0.35,

                            pointRadius: 0,

                            borderWidth: 2
                        }
                    ]
                },

                options: {

                    responsive: true,

                    maintainAspectRatio: false,

                    plugins: {
                        legend: {
                            display: false
                        }
                    },

                    scales: {

                        x: {
                            grid: {
                                display: false
                            }
                        },

                        y: {
                            beginAtZero: true
                        }
                    }
                }
            }
        );
}


/* ============================================================
   16. SEVERITY CHART
   ============================================================ */

const severityCanvas =
    document.getElementById(
        'sevChart'
    );

let severityChart = null;


if (
    severityCanvas &&
    typeof Chart !== 'undefined'
) {

    severityChart =
        new Chart(
            severityCanvas,
            {
                type: 'doughnut',

                data: {

                    labels: [
                        'Critical',
                        'High',
                        'Medium',
                        'Low'
                    ],

                    datasets: [
                        {
                            data: [
                                0,
                                0,
                                0,
                                0
                            ],

                            backgroundColor: [
                                cssValue('--danger'),
                                cssValue('--warn'),
                                cssValue('--amber'),
                                cssValue('--success')
                            ],

                            borderWidth: 0
                        }
                    ]
                },

                options: {

                    responsive: true,

                    maintainAspectRatio: false,

                    cutout: '72%',

                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            }
        );
}


/* ============================================================
   17. RISK CHART
   ============================================================ */

const riskCanvas =
    document.getElementById(
        'riskChart'
    );

let riskChart = null;


if (
    riskCanvas &&
    typeof Chart !== 'undefined'
) {

    riskChart =
        new Chart(
            riskCanvas,
            {
                type: 'line',

                data: {

                    labels: [
                        'No data'
                    ],

                    datasets: [
                        {
                            data: [0],

                            borderColor:
                                cssValue('--warn'),

                            backgroundColor:
                                'transparent',

                            tension: 0.35,

                            pointRadius: 3,

                            borderWidth: 2
                        }
                    ]
                },

                options: {

                    responsive: true,

                    maintainAspectRatio: false,

                    plugins: {
                        legend: {
                            display: false
                        }
                    },

                    scales: {

                        x: {
                            grid: {
                                display: false
                            }
                        },

                        y: {
                            min: 0,
                            max: 100,
                            beginAtZero: true
                        }
                    }
                }
            }
        );
}


/* ============================================================
   18. KPI STATUS HELPER
   ============================================================ */

function updateKpiStatus(
    valueElementId,
    text
) {

    const valueElement =
        document.getElementById(
            valueElementId
        );


    if (!valueElement) return;


    const card =
        valueElement.closest('.kpi');


    if (!card) return;


    const statusElement =
        card.querySelector(
            '.kh span:last-child'
        );


    if (statusElement) {

        statusElement.textContent =
            text;
    }
}


/* ============================================================
   19. UPDATE KPI CARDS
   ============================================================ */

function updateKpis(
    events,
    incidents
) {

    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;


    events.forEach(event => {

        const severity =
            String(
                event.severity || ''
            )
                .toLowerCase()
                .trim();


        if (severity === 'critical') {

            critical++;

        } else if (severity === 'high') {

            high++;

        } else if (severity === 'medium') {

            medium++;

        } else if (severity === 'low') {

            low++;
        }
    });


    const totalEvents =
        events.length;

    const totalAlerts =
        incidents.length;


    /* --------------------------------------------------------
       BIG NUMBERS
       -------------------------------------------------------- */

    const totalEventsElement =
        document.getElementById(
            'totalEvents'
        );

    const alertsRaisedElement =
        document.getElementById(
            'alertsRaised'
        );

    const criticalElement =
        document.getElementById(
            'criticalCount'
        );

    const highElement =
        document.getElementById(
            'highCount'
        );

    const mediumElement =
        document.getElementById(
            'mediumCount'
        );

    const lowElement =
        document.getElementById(
            'lowCount'
        );


    if (totalEventsElement) {

        totalEventsElement.textContent =
            totalEvents;
    }


    if (alertsRaisedElement) {

        alertsRaisedElement.textContent =
            totalAlerts;
    }


    if (criticalElement) {

        criticalElement.textContent =
            critical;
    }


    if (highElement) {

        highElement.textContent =
            high;
    }


    if (mediumElement) {

        mediumElement.textContent =
            medium;
    }


    if (lowElement) {

        lowElement.textContent =
            low;
    }


    /* --------------------------------------------------------
       SMALL TEXT — DYNAMIC, NOT HARDCODED
       -------------------------------------------------------- */

    updateKpiStatus(
        'totalEvents',
        `${totalEvents} total`
    );


    updateKpiStatus(
        'alertsRaised',
        `${totalAlerts} detected`
    );


    updateKpiStatus(
        'criticalCount',
        `${critical} detected`
    );


    updateKpiStatus(
        'highCount',
        `${high} detected`
    );


    updateKpiStatus(
        'mediumCount',
        `${medium} detected`
    );


    updateKpiStatus(
        'lowCount',
        `${low} detected`
    );


    /* --------------------------------------------------------
       SEVERITY TOTAL
       -------------------------------------------------------- */

    const severityTotal =
        document.getElementById(
            'severityTotal'
        );


    if (severityTotal) {

        severityTotal.textContent =
            critical +
            high +
            medium +
            low;
    }


    const severityCritical =
        document.getElementById(
            'severityCritical'
        );

    const severityHigh =
        document.getElementById(
            'severityHigh'
        );

    const severityMedium =
        document.getElementById(
            'severityMedium'
        );

    const severityLow =
        document.getElementById(
            'severityLow'
        );


    if (severityCritical) {

        severityCritical.textContent =
            critical;
    }


    if (severityHigh) {

        severityHigh.textContent =
            high;
    }


    if (severityMedium) {

        severityMedium.textContent =
            medium;
    }


    if (severityLow) {

        severityLow.textContent =
            low;
    }


    /* --------------------------------------------------------
       UPDATE SEVERITY CHART
       -------------------------------------------------------- */

    if (severityChart) {

        severityChart.data.datasets[0].data = [
            critical,
            high,
            medium,
            low
        ];

        severityChart.update();
    }


    return {
        critical,
        high,
        medium,
        low,
        totalEvents,
        totalAlerts
    };
}


/* ============================================================
   20. EVENTS OVER TIME
   ============================================================ */

function updateEventsChart(events) {

    if (!eventsChart) return;


    const buckets =
        Array(12).fill(0);


    events.forEach(event => {

        const rawTimestamp =
            event.timestamp ||
            event.created_at ||
            event.time;


        if (!rawTimestamp) return;


        const date =
            new Date(rawTimestamp);


        if (Number.isNaN(date.getTime())) {
            return;
        }


        const hour =
            date.getHours();


        const bucket =
            Math.floor(hour / 2);


        if (
            bucket >= 0 &&
            bucket < 12
        ) {

            buckets[bucket]++;
        }
    });


    eventsChart.data.labels = [
        '00',
        '02',
        '04',
        '06',
        '08',
        '10',
        '12',
        '14',
        '16',
        '18',
        '20',
        '22'
    ];


    eventsChart.data.datasets[0].data =
        buckets;


    eventsChart.update();
}


/* ============================================================
   21. RISK SCORE
   ============================================================ */

function updateRisk(incidents) {

    const riskScoreElement =
        document.getElementById(
            'riskScore'
        );

    const riskLevelElement =
        document.getElementById(
            'riskLevel'
        );

    const riskDescriptionElement =
        document.getElementById(
            'riskDescription'
        );


    if (
        !incidents ||
        incidents.length === 0
    ) {

        if (riskScoreElement) {

            riskScoreElement.textContent =
                '0';
        }


        if (riskLevelElement) {

            riskLevelElement.textContent =
                'No Risk';
        }


        if (riskDescriptionElement) {

            riskDescriptionElement.textContent =
                'No incidents detected.';
        }


        if (riskChart) {

            riskChart.data.labels = [
                'No data'
            ];

            riskChart.data.datasets[0].data =
                [0];

            riskChart.update();
        }


        return;
    }


    const sorted =
        [...incidents].sort(
            (a, b) => {

                const dateA =
                    new Date(
                        a.created_at ||
                        a.timestamp ||
                        0
                    );

                const dateB =
                    new Date(
                        b.created_at ||
                        b.timestamp ||
                        0
                    );

                return dateB - dateA;
            }
        );


    const latest =
        sorted[0];


    const score =
        Number(
            latest.risk_score ??
            latest.score ??
            0
        );


    const level =
        String(
            latest.risk_level ||
            latest.level ||
            'Unknown'
        );


    if (riskScoreElement) {

        riskScoreElement.textContent =
            score;
    }


    if (riskLevelElement) {

        riskLevelElement.textContent =
            `${level} Risk`;
    }


    if (riskDescriptionElement) {

        riskDescriptionElement.textContent =
            latest.description ||
            latest.rule ||
            latest.reason ||
            'Security incident detected.';
    }


    /* --------------------------------------------------------
       RISK HISTORY
       -------------------------------------------------------- */

    const history =
        sorted
            .slice(0, 7)
            .reverse();


    const riskValues =
        history.map(incident => {

            return Number(
                incident.risk_score ??
                incident.score ??
                0
            );

        });


    const riskLabels =
        history.map(
            (incident, index) => {

                const date =
                    new Date(
                        incident.created_at ||
                        incident.timestamp ||
                        0
                    );


                if (
                    Number.isNaN(
                        date.getTime()
                    )
                ) {

                    return `#${index + 1}`;
                }


                return date.toLocaleDateString(
                    [],
                    {
                        day: '2-digit',
                        month: 'short'
                    }
                );
            }
        );


    if (riskChart) {

        riskChart.data.labels =
            riskLabels;

        riskChart.data.datasets[0].data =
            riskValues;

        riskChart.update();
    }
}


/* ============================================================
   22. RECENT EVENTS
   ============================================================ */

function updateRecentEvents(events) {

    const alertList =
        document.getElementById(
            'alertList'
        );


    if (!alertList) return;


    alertList.innerHTML = '';


    const recentEvents =
        [...events]
            .sort(
                (a, b) => {

                    const dateA =
                        new Date(
                            a.timestamp ||
                            a.created_at ||
                            a.time ||
                            0
                        );

                    const dateB =
                        new Date(
                            b.timestamp ||
                            b.created_at ||
                            b.time ||
                            0
                        );

                    return dateB - dateA;
                }
            )
            .slice(0, 10);


    if (recentEvents.length === 0) {

        alertList.innerHTML =
            `
            <div class="muted">
                No events available
            </div>
            `;

        return;
    }


    recentEvents.forEach(event => {

        const row =
            document.createElement(
                'div'
            );


        const severity =
            String(
                event.severity ||
                'low'
            ).toLowerCase();


        const eventType =
            event.event_type ||
            event.type ||
            event.action ||
            'Security Event';


        const sourceIp =
            event.source_ip ||
            event.src_ip ||
            event.sourceIp ||
            event.dest_ip ||
            event.dst_ip ||
            'Unknown source';


        const timestamp =
            event.timestamp ||
            event.created_at ||
            event.time;


        let time = '--:--';


        if (timestamp) {

            const date =
                new Date(timestamp);


            if (
                !Number.isNaN(
                    date.getTime()
                )
            ) {

                time =
                    date.toLocaleTimeString(
                        [],
                        {
                            hour: '2-digit',
                            minute: '2-digit'
                        }
                    );
            }
        }


        let severityClass =
            'low';


        if (severity === 'critical') {

            severityClass =
                'critical';

        } else if (severity === 'high') {

            severityClass =
                'high';

        } else if (severity === 'medium') {

            severityClass =
                'medium';
        }


        row.className =
            'alertrow';


        row.dataset.s =
            `${eventType} ${sourceIp} ${severity}`
                .toLowerCase();


        row.innerHTML =
            `
            <i class="adot"></i>

            <div class="amain">

                <strong>
                    ${eventType}
                </strong>

                <small>
                    ${sourceIp} · ${time}
                </small>

            </div>

            <span class="tag ${severityClass}">
                ${severity.toUpperCase()}
            </span>
            `;


        alertList.appendChild(row);
    });


    const alertCount =
        document.getElementById(
            'alertCount'
        );


    if (alertCount) {

        alertCount.textContent =
            `${recentEvents.length} shown`;
    }
}


/* ============================================================
   23. TOP SOURCE IPS
   ============================================================ */

function updateTopSourceIps(events) {

    const tables =
        document.querySelectorAll(
            '.grid3 table'
        );


    let sourceTable = null;


    tables.forEach(table => {

        if (
            table.id !== 'iocTable' &&
            !sourceTable
        ) {

            sourceTable =
                table;
        }
    });


    if (!sourceTable) return;


    const tbody =
        sourceTable.querySelector(
            'tbody'
        );


    if (!tbody) return;


    const counts = {};


    events.forEach(event => {

        const source =
            event.source_ip ||
            event.src_ip ||
            event.sourceIp ||
            event.dest_ip ||
            event.dst_ip ||
            'Unknown';


        counts[source] =
            (counts[source] || 0) + 1;
    });


    const rows =
        Object.entries(counts)
            .sort(
                (a, b) => b[1] - a[1]
            )
            .slice(0, 10);


    tbody.innerHTML = '';


    if (rows.length === 0) {

        tbody.innerHTML =
            `
            <tr>
                <td colspan="2" class="muted">
                    No source IP data
                </td>
            </tr>
            `;

        return;
    }


    rows.forEach(
        ([ip, count]) => {

            const tr =
                document.createElement(
                    'tr'
                );


            tr.innerHTML =
                `
                <td class="mono">
                    ${ip}
                </td>

                <td>
                    ${count}
                </td>
                `;


            tbody.appendChild(tr);
        }
    );
}


/* ============================================================
   24. THREAT TYPES
   ============================================================ */

function updateThreatTypes(events) {

    const threatCounts = {};


    events.forEach(event => {

        let type =
            String(
                event.event_type ||
                event.type ||
                event.threat_type ||
                event.action ||
                'Other'
            ).toLowerCase();


        if (
            Number(event.ioc_match) === 1 ||
            event.ioc_match === true ||
            event.ioc_match === '1'
        ) {

            type =
                'IOC Detection';

        } else if (
            type.includes('scan')
        ) {

            type =
                'Port Scan';

        } else if (
            type.includes('brute') ||
            type.includes('failed_login') ||
            type.includes('failed login')
        ) {

            type =
                'Brute Force';

        } else if (
            type.includes('suspicious') ||
            type.includes('outbound') ||
            type.includes('data_export')
        ) {

            type =
                'Suspicious Traffic';

        } else {

            type =
                'Other';
        }


        threatCounts[type] =
            (threatCounts[type] || 0) + 1;
    });


    const total =
        events.length;


    const rows =
        document.querySelectorAll(
            '.grid3 .brow'
        );


    const threatTypes = [
        'IOC Detection',
        'Port Scan',
        'Brute Force',
        'Suspicious Traffic',
        'Other'
    ];


    rows.forEach(
        (row, index) => {

            const type =
                threatTypes[index];


            if (!type) return;


            const count =
                threatCounts[type] || 0;


            const percentage =
                total > 0
                    ? Math.round(
                        (count / total) * 100
                    )
                    : 0;


            const value =
                row.querySelector(
                    '.bmeta b'
                );


            const bar =
                row.querySelector(
                    '.bfill'
                );


            if (value) {

                value.textContent =
                    `${percentage}%`;
            }


            if (bar) {

                bar.style.width =
                    `${percentage}%`;
            }
        }
    );
}


/* ============================================================
   25. IOC TABLE
   ============================================================ */

function updateIocTable(events) {

    const iocTable =
        document.querySelector(
            '#iocTable tbody'
        );


    if (!iocTable) return;


    iocTable.innerHTML = '';


    const iocEvents =
        events.filter(
            event =>
                Number(event.ioc_match) === 1 ||
                event.ioc_match === true ||
                event.ioc_match === '1'
        );


    if (iocEvents.length === 0) {

        iocTable.innerHTML =
            `
            <tr>
                <td
                    colspan="3"
                    class="muted">
                    No IOC matches detected
                </td>
            </tr>
            `;

        return;
    }


    iocEvents
        .slice(0, 10)
        .forEach(event => {

            const row =
                document.createElement(
                    'tr'
                );


            const indicator =
                event.source_ip ||
                event.src_ip ||
                event.dest_ip ||
                event.dst_ip ||
                'Unknown';


            const severity =
                String(
                    event.severity ||
                    'unknown'
                ).toUpperCase();


            row.dataset.s =
                `${indicator} ${severity}`
                    .toLowerCase();


            row.innerHTML =
                `
                <td class="ink">
                    IP
                </td>

                <td class="mono">
                    ${indicator}
                </td>

                <td>
                    <span class="tag ${severity.toLowerCase()}">
                        ${severity}
                    </span>
                </td>
                `;


            iocTable.appendChild(row);
        });
}


/* ============================================================
   26. MAIN LIVE DASHBOARD FUNCTION
   ============================================================ */

async function testBackendConnection() {

    try {

        console.log(
            '[ARGUS] Loading live dashboard data...'
        );


        const events =
            await apiFetch(
                '/api/events'
            );


        const incidents =
            await apiFetch(
                '/api/incidents'
            );


        if (!Array.isArray(events)) {

            throw new Error(
                'Events API did not return an array'
            );
        }


        const incidentList =
            Array.isArray(incidents)
                ? incidents
                : [];


        console.log(
            'ARGUS EVENTS FROM BACKEND:',
            events
        );


        console.log(
            'ARGUS INCIDENTS FROM BACKEND:',
            incidentList
        );


        /* ----------------------------------------------------
           KPI
           ---------------------------------------------------- */

        updateKpis(
            events,
            incidentList
        );


        /* ----------------------------------------------------
           EVENTS GRAPH
           ---------------------------------------------------- */

        updateEventsChart(
            events
        );


        /* ----------------------------------------------------
           RISK
           ---------------------------------------------------- */

        updateRisk(
            incidentList
        );


        /* ----------------------------------------------------
           RECENT EVENTS
           ---------------------------------------------------- */

        updateRecentEvents(
            events
        );


        /* ----------------------------------------------------
           SOURCE IPs
           ---------------------------------------------------- */

        updateTopSourceIps(
            events
        );


        /* ----------------------------------------------------
           THREAT TYPES
           ---------------------------------------------------- */

        updateThreatTypes(
            events
        );


        /* ----------------------------------------------------
           IOC
           ---------------------------------------------------- */

        updateIocTable(
            events
        );


        /* ----------------------------------------------------
           SCAN COUNTER
           ---------------------------------------------------- */

        updateCurrentScanDisplay();


        console.log(
            '[ARGUS] Dashboard updated from live backend data.'
        );


    } catch (error) {

        console.error(
            '[ARGUS] Backend connection failed:',
            error
        );

        showToast(
            'Backend connection failed ✕'
        );
    }
}


/* ============================================================
   27. FILE UPLOAD / LOG SCANNING
   ============================================================ */

const logFileInput =
    document.getElementById(
        'logFileInput'
    );


if (logFileInput) {

    logFileInput.addEventListener(
        'change',
        async event => {

            const file =
                event.target.files[0];


            if (!file) return;


            const fileKey =
                `${file.name}-${file.size}-${file.lastModified}`;


            if (
                fileKey ===
                lastUploadedFile
            ) {

                showToast(
                    'This log file was already scanned.'
                );

                logFileInput.value = '';

                return;
            }


            lastUploadedFile =
                fileKey;


            sessionStorage.setItem(
                'argus_last_uploaded_file',
                fileKey
            );


            try {

                console.log(
                    '[ARGUS] Log file selected:',
                    file.name
                );


                const text =
                    await file.text();


                const log =
                    JSON.parse(text);


                /* ------------------------------------------------
                   CONVERT LOG TO ARGUS EVENT
                   ------------------------------------------------ */

                let argusEvent = {

                    type:
                        log.event_type ||
                        log.type ||
                        'unknown',

                    src_ip:
                        log.source_ip ||
                        log.src_ip ||
                        '',

                    user:
                        log.username ||
                        log.user ||
                        '',

                    severity:
                        log.severity ||
                        'low',

                    timestamp:
                        log.timestamp ||
                        new Date().toISOString()
                };


                if (
                    argusEvent.type === 'login' &&
                    String(
                        log.status
                    ).toLowerCase() === 'failed'
                ) {

                    argusEvent.type =
                        'failed_login';
                }


                console.log(
                    '[ARGUS] Event sent to backend:',
                    argusEvent
                );


                /* ------------------------------------------------
                   CREATE SCAN IF NEEDED
                   ------------------------------------------------ */

                if (!currentScanId) {

                    currentScanId =
                        await createNewScan();
                }


                if (!currentScanId) {

                    throw new Error(
                        'No active scan. Please click New Scan.'
                    );
                }


                const currentToken =
                    localStorage.getItem(
                        'argus_token'
                    );


                /* ------------------------------------------------
                   SEND EVENT TO BACKEND
                   ------------------------------------------------ */

                const response =
                    await fetch(
                        `${API_BASE}/api/events`,
                        {
                            method: 'POST',

                            headers: {

                                'Content-Type':
                                    'application/json',

                                'Authorization':
                                    `Bearer ${currentToken}`,

                                'X-Scan-ID':
                                    String(
                                        currentScanId
                                    )
                            },

                            body:
                                JSON.stringify(
                                    argusEvent
                                )
                        }
                    );


                const result =
                    await response.json();


                if (!response.ok) {

                    throw new Error(
                        result.error ||
                        'Backend rejected the event'
                    );
                }


                console.log(
                    '[ARGUS] Scan result:',
                    result
                );


                /* ------------------------------------------------
                   SHOW SCAN RESULT
                   ------------------------------------------------ */

                const scanResult =
                    document.getElementById(
                        'scanResult'
                    );


                if (scanResult) {

                    scanResult.style.display =
                        'block';


                    const fileName =
                        document.getElementById(
                            'scanFileName'
                        );


                    const eventType =
                        document.getElementById(
                            'scanEventType'
                        );


                    const sourceIp =
                        document.getElementById(
                            'scanSourceIp'
                        );


                    const eventSeverity =
                        document.getElementById(
                            'scanEventSeverity'
                        );


                    const detection =
                        document.getElementById(
                            'scanDetection'
                        );


                    const detectionSeverity =
                        document.getElementById(
                            'scanDetectionSeverity'
                        );


                    const riskScore =
                        document.getElementById(
                            'scanRiskScore'
                        );


                    const riskLevel =
                        document.getElementById(
                            'scanRiskLevel'
                        );


                    if (fileName) {

                        fileName.textContent =
                            `File: ${file.name}`;
                    }


                    if (eventType) {

                        eventType.textContent =
                            log.event_type ||
                            log.type ||
                            'Unknown';
                    }


                    if (sourceIp) {

                        sourceIp.textContent =
                            log.source_ip ||
                            log.src_ip ||
                            'Unknown';
                    }


                    if (eventSeverity) {

                        eventSeverity.textContent =
                            String(
                                log.severity ||
                                'low'
                            ).toUpperCase();
                    }


                    const alerts =
                        Array.isArray(
                            result.alerts
                        )
                            ? result.alerts
                            : [];


                    if (detection) {

                        if (
                            alerts.length > 0
                        ) {

                            detection.textContent =
                                alerts
                                    .map(
                                        alert =>
                                            String(
                                                alert.rule ||
                                                'Detection'
                                            ).replaceAll(
                                                '_',
                                                ' '
                                            )
                                    )
                                    .join(', ');

                        } else {

                            detection.textContent =
                                'No threat detected';
                        }
                    }


                    if (detectionSeverity) {

                        detectionSeverity.textContent =
                            alerts.length > 0
                                ? String(
                                    alerts[0].severity ||
                                    'unknown'
                                ).toUpperCase()
                                : 'NONE';
                    }


                    if (riskScore) {

                        riskScore.textContent =
                            result.risk_score !==
                            undefined
                                ? `${result.risk_score} / 100`
                                : 'N/A';
                    }


                    if (riskLevel) {

                        riskLevel.textContent =
                            result.risk_level
                                ? String(
                                    result.risk_level
                                ).toUpperCase()
                                : 'LOW';
                    }
                }


                /* ------------------------------------------------
                   UPDATE CURRENT SCAN EVENT COUNT
                   ------------------------------------------------ */

                let scanCount =
                    Number(
                        sessionStorage.getItem(
                            'argus_current_scan_count'
                        ) || '0'
                    );


                scanCount++;


                sessionStorage.setItem(
                    'argus_current_scan_count',
                    String(scanCount)
                );


                updateCurrentScanDisplay();


                showToast(
                    'Log scanned successfully ✓'
                );


                /* ------------------------------------------------
                   REFRESH LIVE DASHBOARD
                   ------------------------------------------------ */

                await testBackendConnection();


            } catch (error) {

                console.error(
                    '[ARGUS] Log scanning failed:',
                    error
                );


                showToast(
                    'Log scanning failed ✕'
                );


            } finally {

                /*
                 * Allows selecting the same file again.
                 */

                logFileInput.value = '';
            }
        }
    );
}


/* ============================================================
   28. USER INFORMATION
   ============================================================ */

const username =
    localStorage.getItem(
        'argus_username'
    ) || 'User';


const role =
    localStorage.getItem(
        'argus_role'
    ) || 'analyst';


const displayUsername =
    document.getElementById(
        'displayUsername'
    );


const displayRole =
    document.getElementById(
        'displayRole'
    );


const userInitials =
    document.getElementById(
        'userInitials'
    );


const topUserInitials =
    document.getElementById(
        'topUserInitials'
    );


if (displayUsername) {

    displayUsername.textContent =
        username;
}


if (displayRole) {

    displayRole.textContent =
        role.toUpperCase();
}


function getInitials(name) {

    return name
        .trim()
        .split(/\s+/)
        .map(word => word[0])
        .join('')
        .slice(0, 2)
        .toUpperCase();
}


if (userInitials) {

    userInitials.textContent =
        getInitials(username) || 'U';
}


if (topUserInitials) {

    topUserInitials.textContent =
        getInitials(username) || 'U';
}


/* ============================================================
   29. INITIALIZATION
   ============================================================ */

updateCurrentScanDisplay();

testBackendConnection();


console.log(
    '[ARGUS] Dashboard JavaScript loaded successfully.'
);