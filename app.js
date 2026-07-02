console.log("APP.JS VERSION - UPDATED");
const express = require("express");
const http = require("http");
const path = require("path");
const WebSocket = require("ws");
const { DetectionEngine } = require("./detectionEngine");

const app = express();

const PORT = process.env.PORT || 3000;

const TARGET_HOST = process.env.TARGET_HOST || "// ANY DOMAIN YOU OWN ENTER HERE";

const TICK_INTERVAL_MS = parseInt(process.env.TICK_INTERVAL_MS, 10) || 4000;

const engine = new DetectionEngine({ targetHost: TARGET_HOST });

app.use(express.static(__dirname));

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
