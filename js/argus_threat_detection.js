const element = id => document.getElementById(id);
const filters = ["q", "fs", "fr", "fres", "fd"];

let detections = [];
let statusMessage = "Loading detections…";

function ruleName(rule) {
  return rule
    .split("_")
    .map(word => word === "ip" ? "IP" : word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

function updateRuleFilter() {
  const ruleIds = [...new Set(detections.map(detection => detection.rule))];
  const options = ruleIds.map(rule => new Option(ruleName(rule), rule));

  element("fr").replaceChildren(new Option("Rule: All", ""), ...options);
}

function render() {
  const [search, severity, rule, result, day] = filters.map(id => element(id).value);
  const query = search.trim().toLowerCase();

  const rows = detections.filter(detection =>
    (!severity || detection.severity === severity) &&
    (!rule || detection.rule === rule) &&
    (!result || result === "detected") &&
    (!day || detection.detected_at.startsWith(day)) &&
    [
      detection.rule,
      ruleName(detection.rule),
      detection.source_ip,
      detection.event_id,
      detection.user
    ].join(" ").toLowerCase().includes(query)
  );

  const fragment = document.createDocumentFragment();

  for (const detection of rows) {
    const row = document.createElement("tr");
    const values = [
      detection.id,
      ruleName(detection.rule),
      detection.event_id,
      detection.source_ip,
      detection.user,
      detection.severity,
      new Date(detection.detected_at).toLocaleString(),
      "Detected"
    ];

    for (const value of values) {
      row.insertCell().textContent = value ?? "N/A";
    }

    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "View";
    button.addEventListener("click", () => showDetails(values));
    row.insertCell().append(button);
    fragment.append(row);
  }

  element("rows").replaceChildren(fragment);
  element("cnt").textContent = `${rows.length} ${rows.length === 1 ? "match" : "matches"}`;
  element("none").hidden = rows.length > 0;
  element("none").textContent = statusMessage || "No detections match these filters.";
}

function closeDetails() {
  const drawer = element("dr");
  drawer.classList.remove("open");
  drawer.setAttribute("aria-hidden", "true");
}

function showDetails(values) {
  const drawer = element("dr");
  const close = document.createElement("button");
  close.type = "button";
  close.textContent = "Close";
  close.addEventListener("click", closeDetails);

  const title = document.createElement("h2");
  title.textContent = values[1];

  const details = document.createElement("dl");
  const labels = [
    "Detection ID", "Rule", "Event ID", "Source IP",
    "Username", "Severity", "Detected", "Result"
  ];

  labels.forEach((label, index) => {
    const term = document.createElement("dt");
    term.textContent = label;

    const value = document.createElement("dd");
    value.textContent = values[index] ?? "N/A";

    details.append(term, value);
  });

  drawer.replaceChildren(close, title, details);
  drawer.classList.add("open");
  drawer.setAttribute("aria-hidden", "false");
  close.focus();
}

async function loadDetections() {
  const token = localStorage.getItem("argus_token");

  if (!token) {
    location.href = "argus_login.html";
    return;
  }

  render();

  try {
    const response = await fetch("http://127.0.0.1:5000/api/detections", {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store"
    });

    if (response.status === 401) {
      localStorage.removeItem("argus_token");
      localStorage.removeItem("argus_role");
      location.href = "argus_login.html";
      return;
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    detections = await response.json();
    updateRuleFilter();

    statusMessage = detections.length ? "" : "No rule matches recorded yet.";
    element("eng").textContent = "Connected";
  } catch (error) {
    statusMessage = "Could not load detections. Check that the ARGUS backend is running.";
    element("eng").textContent = "Connection unavailable";
    console.error("ARGUS detections:", error);
  }

  render();
}

for (const id of filters) {
  element(id).addEventListener("input", render);
}

element("clr").addEventListener("click", () => {
  for (const id of filters) {
    element(id).value = "";
  }
  render();
});

document.addEventListener("keydown", event => {
  if (event.key === "Escape") closeDetails();
});

loadDetections();