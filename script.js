let alertsData = [];
let summaryCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
const MAX_ROWS = 50;

const connectionStatusEl = document.getElementById("connectionStatus");
const targetHostEl = document.getElementById("targetHost");

function setConnectionStatus(online) {
    if (online) {
        connectionStatusEl.textContent = "● Live";
        connectionStatusEl.className = "status-pill online";
    } else {
        connectionStatusEl.textContent = "● Reconnecting...";
        connectionStatusEl.className = "status-pill offline";
    }
}

function connectWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    const socket = new WebSocket(wsUrl);

    socket.addEventListener("open", () => {
        setConnectionStatus(true);
    });

    socket.addEventListener("message", (event) => {
        const payload = JSON.parse(event.data);

        if (payload.target) {
            targetHostEl.textContent = payload.target;
        }

        if (payload.type === "snapshot") {
            alertsData = payload.alerts;
            summaryCounts = payload.summary;
            renderAll();
        } else if (payload.type === "alert") {
            alertsData.unshift(payload.alert);
            if (alertsData.length > MAX_ROWS) alertsData.pop();
            summaryCounts = payload.summary;
            renderAll(payload.alert.id); 
        }
    });

    socket.addEventListener("close", () => {
        setConnectionStatus(false);
       
        setTimeout(connectWebSocket, 3000);
       
        pollViaRest();
    });

    socket.addEventListener("error", () => {
        socket.close();
    });
}

let restPollTimer = null;
function pollViaRest() {
    if (restPollTimer) return; 
    restPollTimer = setInterval(async () => {
        try {
           const res = await fetch("/api/alerts");
            const data = await res.json();
            alertsData = data.alerts;
            summaryCounts = data.summary;
            targetHostEl.textContent = data.target;
            renderAll();
           
            if (connectionStatusEl.classList.contains("online")) {
                clearInterval(restPollTimer);
                restPollTimer = null;
            }
        } catch (err) {
            console.error("REST fallback fetch failed:", err);
        }
    }, 5000);
}

function renderAll(newAlertId = null) {
    updateSummaryCards();
    populateTable(newAlertId);
}

function updateSummaryCards() {
    setCardValue("criticalCount", summaryCounts.CRITICAL || 0);
    setCardValue("highCount", summaryCounts.HIGH || 0);
    setCardValue("mediumCount", summaryCounts.MEDIUM || 0);
    setCardValue("lowCount", summaryCounts.LOW || 0);
}

function setCardValue(id, value) {
    const el = document.getElementById(id);
    if (el.innerText !== String(value)) {
        el.innerText = value;
        const card = el.closest(".card");
        card.classList.add("pulse");
        setTimeout(() => card.classList.remove("pulse"), 200);
    }
}

function populateTable(newAlertId) {
    const table = document.getElementById("alertTable");
    table.innerHTML = "";
    alertsData.forEach(alert => {
        let row = document.createElement("tr");
        if (alert.id === newAlertId) row.classList.add("new-row");

        const time = alert.timestamp
            ? new Date(alert.timestamp).toLocaleTimeString()
            : "-";

        row.innerHTML = `
            <td>${time}</td>
            <td>${alert.id}</td>
            <td>${alert.type}<span class="badge ${alert.severity}">${alert.severity}</span></td>
            <td>${alert.ip}</td>
            <td>${alert.target || "-"}</td>
            <td>${alert.risk}</td>
            <td>${alert.mitre}</td>
        `;
        row.addEventListener("click", () => showIncident(alert));
        table.appendChild(row);
    });
}

function showIncident(alert) {
    const box = document.getElementById("incidentBox");
    const actions = alert.recommendedActions && alert.recommendedActions.length
        ? alert.recommendedActions
        : ["Block suspicious IP", "Investigate affected system", "Reset credentials if needed", "Check logs for lateral movement"];

    box.innerHTML = `
        <h3>${alert.type} <span class="badge ${alert.severity}">${alert.severity}</span></h3>
        <p><strong>Source IP:</strong> ${alert.ip}</p>
        <p><strong>Target Host:</strong> ${alert.target || "-"}</p>
        <p><strong>Risk Score:</strong> ${alert.risk}/100</p>
        <p><strong>MITRE Technique:</strong> ${alert.mitre}</p>
        <p><strong>Description:</strong> ${alert.description}</p>
        <hr>
        <h4>Recommended Actions:</h4>
        <ul>
        
            ${actions.map(a => `<li>${a}</li>`).join("")}
        </ul>
    `;
}

connectWebSocket();
