# DomainWatch: Real-Time Security Monitoring Platform

## Overview

DomainWatch is a simulated Security Operations Center (SOC) monitoring platform designed to provide real-time visibility into security events, threat alerts, and incident investigation activities for monitored web infrastructure environments.

The platform simulates SOC operations by collecting security events, assigning risk levels, mapping threats to MITRE ATT&CK techniques, and presenting actionable security insights through an interactive monitoring interface.

## Key Features

- Real-time security alert monitoring
- Threat event visualization
- Risk-based alert classification
- Incident investigation workflow
- Source IP and target host analysis
- MITRE ATT&CK technique mapping
- Security event tracking
- SOC-style monitoring dashboard

## Security Monitoring Capabilities

The platform provides visibility into simulated security incidents including:

- Malware detection
- Brute-force attacks
- DNS tunneling activity
- PowerShell abuse
- Data exfiltration attempts

## Dashboard Highlights

- Critical / High / Medium / Low severity classification
- Risk score analysis
- Attack technique identification
- Security event timeline
- Incident response recommendations

## Technology Stack

- HTML5
- CSS3
- JavaScript
- Node.js
- Express.js
- WebSocket
- JSON-based security event simulation


## Project Architecture

```
│
├── Frontend
│   ├── index.html
│   ├── style.css
│   └── script.js
│
├── Backend
│   └── app.js
│
├── Detection Engine
│   └── detectionEngine.js
│
├── Configuration
│   └── package.json
│
└── README.md
```
## Component Description

### Frontend Layer
Provides the interactive SOC dashboard interface for visualizing security alerts, risk levels, attack information, and incident details.

### Backend Layer (app.js)
Handles application startup, server communication, and real-time event delivery between the backend and dashboard.

### Detection Engine (detectionEngine.js)
Processes simulated security events, evaluates threat conditions, assigns severity levels, calculates risk scores, and maps detected activities to MITRE ATT&CK techniques.

### Package Configuration (package.json)
Defines project dependencies, scripts, and Node.js application configuration.

## Use Case

## Use Case

DomainWatch demonstrates how modern Security Operations Centers (SOC) monitor, analyze, and prioritize security events in real time.

It helps simulate how analysts investigate threats, assess severity, correlate suspicious behavior, and make incident response decisions using structured security intelligence.
