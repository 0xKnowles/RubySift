const gate = document.getElementById("gate");
const usbGate = document.getElementById("usb-gate");
const dashboard = document.getElementById("dashboard");
const gateError = document.getElementById("gate-error");
const usbError = document.getElementById("usb-error");

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
  usbGate.hidden = true;
  dashboard.hidden = false;
  await loadDashboard();
});

document.getElementById("close-session").addEventListener("click", async () => {
  await fetch("/api/session/close", { method: "POST" });
  dashboard.hidden = true;
  gate.hidden = false;
  usbGate.hidden = false;
});

async function refreshUsbPorts() {
  usbError.textContent = "";
  const select = document.getElementById("usb-port");
  select.innerHTML = "";
  try {
    const ports = await fetch("/api/usb/ports").then((r) => r.json());
    for (const port of ports || []) {
      const opt = document.createElement("option");
      opt.value = port;
      opt.textContent = port;
      select.appendChild(opt);
    }
    if (!ports || ports.length === 0) {
      const opt = document.createElement("option");
      opt.textContent = "No serial ports found";
      select.appendChild(opt);
    }
  } catch {
    usbError.textContent = "Failed to list serial ports";
  }
}

document.getElementById("usb-refresh").addEventListener("click", refreshUsbPorts);
refreshUsbPorts();

document.getElementById("usb-browse").addEventListener("click", async () => {
  usbError.textContent = "";
  const port = document.getElementById("usb-port").value;
  const list = document.getElementById("usb-files");
  list.innerHTML = "";
  if (!port) {
    usbError.textContent = "Select a serial port first";
    return;
  }

  const res = await fetch("/api/usb/list", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ port }),
  });
  const files = await res.json();
  if (!res.ok) {
    usbError.textContent = files.error || "failed to list device files";
    return;
  }
  if (!files || files.length === 0) {
    list.innerHTML = "<li>No .pclog files on device.</li>";
    return;
  }
  for (const f of files) {
    const li = document.createElement("li");
    li.innerHTML = `<span>${f.name} (${f.size} bytes)</span>`;
    const pullBtn = document.createElement("button");
    pullBtn.type = "button";
    pullBtn.textContent = "Pull & Decrypt";
    pullBtn.addEventListener("click", () => pullUsbFile(port, f.name));
    li.appendChild(pullBtn);
    list.appendChild(li);
  }
});

async function pullUsbFile(port, name) {
  usbError.textContent = "";
  const res = await fetch("/api/usb/pull", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ port, name }),
  });
  const data = await res.json();
  if (!res.ok) {
    usbError.textContent = data.error || "failed to pull file";
    return;
  }
  gate.hidden = true;
  usbGate.hidden = true;
  dashboard.hidden = false;
  await loadDashboard();
}

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
