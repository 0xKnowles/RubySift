const gate = document.getElementById("gate");
const dashboard = document.getElementById("dashboard");
const gateError = document.getElementById("gate-error");

document.getElementById("open-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  gateError.textContent = "";
  const path = document.getElementById("path").value;
  const secret = document.getElementById("secret").value;
  const body = /^[0-9a-fA-F]{64}$/.test(secret) ? { path, key: secret } : { path, passphrase: secret };

  const res = await fetch("/api/session/open", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) {
    gateError.textContent = data.error || "failed to open log";
    return;
  }
  document.getElementById("secret").value = "";
  gate.hidden = true;
  dashboard.hidden = false;
  await loadDashboard();
});

document.getElementById("close-session").addEventListener("click", async () => {
  await fetch("/api/session/close", { method: "POST" });
  dashboard.hidden = true;
  gate.hidden = false;
});

async function loadDashboard() {
  const [pulse, proximity] = await Promise.all([
    fetch("/api/pulse").then((r) => r.json()),
    fetch("/api/proximity").then((r) => r.json()),
  ]);
  renderPulseGrid(pulse);
  renderProximity(proximity);
  renderNodeTable(proximity);
}

function renderPulseGrid(buckets) {
  const max = Math.max(1, ...buckets.map((b) => b.count));
  const grid = document.getElementById("pulse-grid");
  grid.innerHTML = "";
  for (const b of buckets) {
    const cell = document.createElement("div");
    cell.className = "pulse-cell";
    cell.dataset.hour = b.hour;
    cell.title = `${b.hour}:00 — ${b.count} signals`;
    const intensity = b.count / max;
    cell.style.opacity = 0.15 + intensity * 0.85;
    grid.appendChild(cell);
  }
}

function renderProximity(clusters) {
  const canvas = document.getElementById("proximity-canvas");
  const ctx = canvas.getContext("2d");
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  if (clusters.length === 0) {
    ctx.fillStyle = "#8892a4";
    ctx.fillText("No nodes observed", 20, 30);
    return;
  }

  const minRSSI = -100;
  const maxRSSI = 0;
  const colors = {
    wifi_ap: "#e0405a",
    wifi_client: "#e0a040",
    wifi_handshake: "#e0405a",
    ble_device: "#4a90d9",
  };
  clusters.forEach((c, i) => {
    const x = 40 + (i * (canvas.width - 80)) / Math.max(1, clusters.length - 1);
    const norm = (c.avg_rssi - minRSSI) / (maxRSSI - minRSSI);
    const y = canvas.height - 20 - norm * (canvas.height - 40);
    const r = 4 + Math.min(20, c.sightings);
    ctx.beginPath();
    ctx.fillStyle = colors[c.type] || "#8892a4";
    ctx.globalAlpha = 0.75;
    ctx.arc(x, y, r, 0, Math.PI * 2);
    ctx.fill();
    ctx.globalAlpha = 1;
  });
}

function renderNodeTable(clusters) {
  const tbody = document.querySelector("#node-table tbody");
  tbody.innerHTML = "";
  for (const c of clusters) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${c.mac}</td><td>${c.type}</td><td>${c.label || ""}</td><td>${c.sightings}</td><td>${c.avg_rssi.toFixed(1)}</td><td>${c.max_rssi}</td>`;
    tbody.appendChild(tr);
  }
}
