# 🛡️ UZYNTRA API Firewall — Rust Security Engine

<p align="center">
  <img src="docs/assets/UZYNTRA-logo-mark.png" width="120"/>
</p>

<p align="center">
  <b>High-Performance API Security Engine for Modern SaaS Systems</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Backend-Rust-orange?style=for-the-badge&logo=rust"/>
  <img src="https://img.shields.io/badge/UI-Next.js-black?style=for-the-badge&logo=next.js"/>
  <img src="https://img.shields.io/badge/Status-Production Ready-success?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Security-API Firewall-blue?style=for-the-badge"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/contributions-welcome-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/PRs-welcome-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/open--source-yes-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/CI-passing-brightgreen?style=for-the-badge" />
</p>

---

## 🚀 Overview

**UZYNTRA API Firewall** is a high-performance API security engine that inspects, detects, and mitigates threats in real time through a programmable reverse proxy architecture.

It enables:

* 🔍 Deep request inspection
* 🧠 Intelligent threat detection
* 🛡️ Real-time mitigation
* 📊 Full observability via control plane

---

## 🚀 Why UZYNTRA?

UZYNTRA is a SaaS-ready API security platform combining a Rust-based security engine with a modern control plane.

Built for:

* Real-time threat detection
* Scalable API protection
* DevSecOps integration
* Cloud-native deployment

---

## 🏗️ Architecture Overview

```
Client → UZYNTRA Firewall (Rust)
              ↓
       Detection Engine
              ↓
       Mitigation System
              ↓
         Admin API
              ↓
        UZYNTRA UI (Next.js)
```

---

## 🔗 UI Control Plane

👉 https://github.com/UsamaMatrix/uzyntra-ui

---

## ⚡ Core Capabilities

* 🔍 Deep Request Inspection (headers, body, query)
* 🧠 Attack Detection Engine (pattern + heuristic)
* 🛡️ Active Mitigation (IP block, TTL bans)
* 📊 Security Telemetry (events, metrics, logs)
* ⚙️ Policy Control (rules, rate limiting)
* ⚡ High Performance (async Rust, low latency)

---

## 📡 Structured Logging (SIEM Ready)

* JSON-formatted logs
* Includes IP, route, severity, attack type
* Compatible with ELK, Splunk, Datadog

```json
{
  "ip": "192.168.1.1",
  "route": "/api/login",
  "attack": "SQL Injection",
  "severity": "critical",
  "action": "blocked"
}
```

---

## 🐳 Docker Support

```bash
docker build -t uzyntra-firewall .
docker run -p 8080:8080 -p 9090:9090 uzyntra-firewall
```

---

## ⚙️ CI/CD

Automated build & test pipeline using GitHub Actions.

---

## 🧰 Tech Stack

* Rust
* Tokio
* Axum
* Reqwest
* Serde

---

## 📦 Installation

```bash
git clone https://github.com/UsamaMatrix/uzyntra-api-firewall.git
cd uzyntra-api-firewall
cargo build
```

---

## ▶️ Running

```bash
cargo run
```

---

## 🌐 Endpoints

| Service   | URL                   |
| --------- | --------------------- |
| Proxy     | http://127.0.0.1:8080 |
| Admin API | http://127.0.0.1:9090 |

---

## 🔐 Authentication

```http
x-admin-token: dev-admin-token-1
```

---

## 🧠 Detection Model

* Pattern matching
* Request scoring
* Confidence levels
* Attack classification

---

## 🛡️ Mitigation Flow

```
Request → Inspection → Detection → Decision → Action
```

---

## 🧪 Testing

```bash
curl -X POST http://127.0.0.1:8080/proxy/test \
  -d "union select password from users"
```

---

## 🧭 Roadmap

* JWT Authentication
* ML-based detection
* Distributed architecture
* Multi-tenant SaaS
* Real-time alerts

---

## 🤝 Contributing

We welcome contributions!

* Check issues labeled `good first issue`
* Submit PRs
* Improve detection or performance

---

## 💼 Use Cases

* API Security Platforms
* Reverse Proxy Security
* DevSecOps Pipelines
* SaaS Backend Protection

---

## 👨‍💻 Author

Muhammad Usama
Cyber Security Analyst | Rust Engineer

---

## ⭐ Support

Give a ⭐ if you like the project

---

## 🛡️ UZYNTRA

> Observe. Detect. Control. Defend.
