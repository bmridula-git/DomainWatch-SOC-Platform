// detectionEngine.js
// Simulates realistic security telemetry and applies detection logic on top of it,
// similar in spirit to how a SIEM correlates raw events into alerts.

const ATTACK_PROFILES = [
  {
    type: "Brute Force Attack",
    mitre: "T1110",
    severityRange: [70, 90],
    descTemplate: (ctx) =>
      `${ctx.failCount} failed login attempts from ${ctx.ip} on ${ctx.target} within ${ctx.window}s.`
  },
  {
    type: "PowerShell Abuse",
    mitre: "T1059.001",
    severityRange: [65, 85],
    descTemplate: (ctx) =>
      `Encoded PowerShell command executed on host ${ctx.target}, initiated from ${ctx.ip}.`
  },
  {
    type: "Phishing Attempt",
    mitre: "T1566",
    severityRange: [40, 65],
    descTemplate: (ctx) =>
      `User on ${ctx.target} interacted with a flagged link delivered via email from ${ctx.ip}.`
  },
  {
    type: "Port Scanning",
    mitre: "T1046",
    severityRange: [30, 55],
    descTemplate: (ctx) =>
      `${ctx.portCount} ports probed on ${ctx.target} from external host ${ctx.ip}.`
  },
  {
    type: "Malware Detection",
    mitre: "T1204",
    severityRange: [85, 99],
    descTemplate: (ctx) =>
      `Signature match for known malware family on ${ctx.target}, originating connection ${ctx.ip}.`
  },
  {
    type: "Suspicious Login",
    mitre: "T1078",
    severityRange: [45, 65],
    descTemplate: (ctx) =>
      `Login on ${ctx.target} from ${ctx.ip} flagged for anomalous geolocation/time pattern.`
  },
  {
    type: "Data Exfiltration Attempt",
    mitre: "T1041",
    severityRange: [85, 97],
    descTemplate: (ctx) =>
      `Outbound transfer of ${ctx.dataSize}MB from ${ctx.target} to ${ctx.ip} flagged as anomalous.`
  },
  {
    type: "DNS Tunneling",
    mitre: "T1071.004",
    severityRange: [60, 80],
    descTemplate: (ctx) =>
      `Abnormal DNS query volume/entropy from ${ctx.target} resolving via ${ctx.ip}.`
  },
  {
    type: "Privilege Escalation",
    mitre: "T1068",
    severityRange: [75, 92],
    descTemplate: (ctx) =>
      `Unauthorized privilege elevation attempt detected on ${ctx.target} (origin ${ctx.ip}).`
  }
];

// Pool of "monitored" hosts. The configured TARGET_HOST (e.g. demo-server.in)
// is always included so the dashboard can visibly point at your own domain.
function buildHostPool(primaryTarget) {
  const pool = [
    primaryTarget,
    "web-01.internal",
    "db-prod-03",
    "mail-gateway",
    "10.0.0.5",
    "192.168.1.20"
  ];
  return [...new Set(pool.filter(Boolean))];
}

function randomIp() {
  // Bias toward "external-looking" IPs for realism, occasionally internal RFC1918
  const internal = Math.random() < 0.3;
  if (internal) {
    return `192.168.1.${randInt(2, 254)}`;
  }
  return `${randInt(1, 223)}.${randInt(0, 255)}.${randInt(0, 255)}.${randInt(1, 254)}`;
}

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function severityFromRisk(risk) {
  if (risk >= 85) return "CRITICAL";
  if (risk >= 65) return "HIGH";
  if (risk >= 40) return "MEDIUM";
  return "LOW";
}

class DetectionEngine {
  constructor({ targetHost }) {
    this.targetHost = targetHost || "demo-server.in";
    this.hostPool = buildHostPool(this.targetHost);
    this.nextId = 1;
    this.alerts = [];       // rolling buffer of generated alerts
    this.maxBuffer = 200;   // cap memory usage
    this.ipFailCounts = new Map(); // naive correlation state for brute-force detection
  }

  // Generates one raw "event" and runs it through detection logic.
  // Returns an alert object, or null if the event didn't trip any rule
  // (kept low-probability so most ticks DO produce an alert for demo purposes).
  generateAlert() {
    const profile = ATTACK_PROFILES[randInt(0, ATTACK_PROFILES.length - 1)];
    const ip = randomIp();
    const target = this.hostPool[randInt(0, this.hostPool.length - 1)];
    const risk = randInt(profile.severityRange[0], profile.severityRange[1]);

    // crude correlation: track repeated source IPs to bump brute-force confidence,
    // mirroring how real SIEMs raise severity on repeated source behavior
    const failCount = this._bumpAndGetCount(ip);

    const ctx = {
      ip,
      target,
      window: randInt(30, 120),
      failCount: Math.max(failCount, randInt(4, 12)),
      portCount: randInt(15, 400),
      dataSize: randInt(50, 800)
    };

    const alert = {
      id: this.nextId++,
      timestamp: new Date().toISOString(),
      type: profile.type,
      ip,
      target,
      risk,
      severity: severityFromRisk(risk),
      mitre: profile.mitre,
      description: profile.descTemplate(ctx),
      recommendedActions: this._recommendActions(profile.type)
    };

    this.alerts.unshift(alert);
    if (this.alerts.length > this.maxBuffer) this.alerts.pop();

    return alert;
  }

  _bumpAndGetCount(ip) {
    const current = this.ipFailCounts.get(ip) || 0;
    const next = current + 1;
    this.ipFailCounts.set(ip, next);
    // Decay occasionally so the map doesn't grow forever and counts stay "live"
    if (this.ipFailCounts.size > 500) this.ipFailCounts.clear();
    return next;
  }

  _recommendActions(type) {
    const common = ["Investigate affected system", "Check logs for lateral movement"];
    const specific = {
      "Brute Force Attack": ["Block source IP at firewall", "Force password reset on targeted account", "Enable account lockout / MFA"],
      "PowerShell Abuse": ["Isolate host from network", "Review PowerShell script block logs", "Check for persistence mechanisms"],
      "Phishing Attempt": ["Quarantine the email", "Notify affected user", "Block sender domain"],
      "Port Scanning": ["Block source IP at perimeter firewall", "Review exposed services"],
      "Malware Detection": ["Isolate host immediately", "Run full AV/EDR scan", "Identify patient zero"],
      "Suspicious Login": ["Verify with the account owner", "Force re-authentication / MFA challenge"],
      "Data Exfiltration Attempt": ["Block outbound connection", "Identify data accessed", "Notify data owner / compliance"],
      "DNS Tunneling": ["Block resolving domain", "Inspect DNS logs for related hosts"],
      "Privilege Escalation": ["Revoke elevated session", "Audit recent permission changes"]
    };
    return [...(specific[type] || []), ...common];
  }

  getSnapshot(limit = 50) {
    return this.alerts.slice(0, limit);
  }

  getSummary() {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const a of this.alerts) {
      counts[a.severity] = (counts[a.severity] || 0) + 1;
    }
    return counts;
  }
}

module.exports = { DetectionEngine };
