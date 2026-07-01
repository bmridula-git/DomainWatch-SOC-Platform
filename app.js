// app.js
// Entry point for Plesk Node.js hosting (Application Startup File = app.js).
// Serves the static dashboard frontend AND exposes the live alert feed.
console.log("APP.JS VERSION - UPDATED");
const express = require("express");
const http = require("http");
const path = require("path");
const WebSocket = require("ws");
const { DetectionEngine } = require("./detectionEngine");

const app = express();

// Plesk/Passenger assigns the port via process.env.PORT — never hardcode it.
const PORT = process.env.PORT || 3000;

// The host name shown on the dashboard as the "monitored" target.
// Set this in Plesk under Node.js > Custom environment variables (TARGET_HOST=demo-server.in)
const TARGET_HOST = process.env.TARGET_HOST || "demo-server.in";

// How often (ms) a new simulated alert is generated.
const TICK_INTERVAL_MS = parseInt(process.env.TICK_INTERVAL_MS, 10) || 4000;

const engine = new DetectionEngine({ targetHost: TARGET_HOST });

// Serve the existing frontend (index.html, style.css, script.js) from /public
app.use(express.static(__dirname));

// REST fallback: returns the current alert buffer + summary counts.
// Useful for initial page load and as a fallback if WebSocket fails.
app.get("/api/alerts", (req, res) => {
  res.json({
    target: TARGET_HOST,
    alerts: engine.getSnapshot(50),
    summary: engine.getSummary()
  });
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", target: TARGET_HOST, uptime: process.uptime() });
});

const server = http.createServer(app);

// --- WebSocket: push new alerts to all connected dashboards in real time ---
const wss = new WebSocket.Server({ server, path: "/ws" });

function broadcast(payload) {
  const data = JSON.stringify(payload);
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(data);
    }
  });
}

wss.on("connection", (ws) => {
  // On connect, send the current snapshot so the table isn't empty
  ws.send(
    JSON.stringify({
      type: "snapshot",
      target: TARGET_HOST,
      alerts: engine.getSnapshot(50),
      summary: engine.getSummary()
    })
  );
});

// --- Simulated live feed loop ---
setInterval(() => {
  const alert = engine.generateAlert();
  broadcast({
    type: "alert",
    target: TARGET_HOST,
    alert,
    summary: engine.getSummary()
  });
}, TICK_INTERVAL_MS);

server.listen(PORT, () => {
  console.log(`SOC-XDR Lite backend running on port ${PORT}`);
  console.log(`Monitoring target (simulated): ${TARGET_HOST}`);
});
