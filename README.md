# SENTINEL — Cyber Threat Intelligence Dashboard

SENTINEL is a full-stack, real-time Security Operations Center (SOC) analyst simulation platform. It is designed to model the analytical tools, log auditing streams, and incident response playbooks used by entry-level threat analysts at a corporate command center ("NovaCorp Ltd").

The system consists of a cinematic frontend dashboard connected to a Python Flask API to retrieve real-world threat telemetry.

---

## System Architecture

* **Frontend:** Single-file HTML5, CSS3, and ES6 JavaScript. Uses HTML5 Canvas for animations, inline SVGs for threat mapping, and CSS CRT-scanline filters.
* **Backend:** Python Flask API incorporating real OSINT libraries, DNS resolvers, and public threat intelligence feeds.

---

## Core Capabilities & Modules

### 1. Active Threat Intelligence Map
* Coordinates global attack vectors using an animated, responsive inline SVG map converging on NovaCorp’s headquarters in Nairobi, Kenya.
* Highlights real-time telemetry details, including origin city, country, vector class, and severity levels.

### 2. SIEM Event Logger & Detail Panel
* Streams live mock telemetry logs mimicking an active SIEM environment.
* Clicking any individual log item parses its metadata, displaying standard MITRE ATT&CK technique mappings, impact analysis, and remediation steps.

### 3. Incident Response Playbook Console
* Triggers visual red alerts on critical threats (e.g., Ransomware execution or port scanning), initiating a 60-second response countdown timer.
* Logs analyst decisions (Isolate Host, Block IP, Escalate, Ignore), tracking outcomes, Mean Time to Detect (MTTD), and Mean Time to Respond (MTTR).

### 4. Interactive Analyst Workstation (Real APIs)
* **IP Reputation Checker:** Queries the [AbuseIPDB API](https://www.abuseipdb.com/) to analyze external addresses for malicious scoring, ISP operators, and geolocation parameters.
* **Hash Analyzer:** Verifies cryptographic signatures (MD5/SHA256) against known malicious binaries.
* **Phishing Sandbox:** Analyzes raw mail header blocks for SPF mismatches, sender spoofing, and social engineering patterns.
* **Vulnerability Port Scanner:** Audits target domains to map open ports, service versions, matched CVE numbers, and patch guidelines.

---

## Backend API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/ip/<ip_address>` | Performs WHOIS lookups, reverse DNS, and queries AbuseIPDB for reputation scores. |
| `GET` | `/api/dns/<domain>` | Resolves DNS records (A, MX, NS, TXT, CNAME) and flags configuration risks. |
| `POST` | `/api/analyze/headers` | Parses raw email headers to validate SPF/DKIM/DMARC alignment. |
| `GET` | `/api/threats/feed` | Pulls live malicious indicators from the AlienVault OTX API. |

---

## Local Installation & Setup

### Prerequisites
Before starting the backend, ensure your operating system has the system-level `whois` binaries installed:
* **macOS:** `brew install whois`
* **Linux (Ubuntu/Debian):** `sudo apt-get install whois`
* **Windows:** (No action required; managed automatically by library wrappers).

### Installation Steps

1. Clone this repository and navigate to the backend folder:
   ```bash
   git clone https://github.com/your-username/your-repo-name.git
   cd sentinel-backend
