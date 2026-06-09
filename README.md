# SENTINEL — Cyber Threat Intelligence Dashboard

SENTINEL is an interactive, browser-based Security Operations Center (SOC) simulation dashboard. Designed as a practical educational tool, it simulates the workflow, tools, and threat-remediation decisions of a Junior SOC Analyst at a fictional corporation ("NovaCorp Ltd"). 

This application is built entirely as a single-file, serverless web app using native HTML5, CSS3, and vanilla JavaScript—requiring no build pipelines or frameworks.

## Core Modules

### 1. Live Threat Map (SVG)
* Animates simulated attack lines converging from global coordinates (e.g., Moscow, Beijing, Lagos, São Paulo) onto NovaCorp's target headquarters in Nairobi, Kenya.
* Color-coded indicator arcs visualize threat types (DDoS, Ransomware, Zero-day, Phishing, Brute Force).

### 2. SIEM Event Logger & Detail Drawer
* Provides a real-time scrolling terminal-style log feed of mock network telemetry.
* Includes a CRT-scanline visual filter overlay.
* Clicking any individual log item pauses telemetry and opens an Incident Detail Panel displaying standard MITRE ATT&CK technique mapping, affected asset metadata, and defensive recommendations.

### 3. Interactive Analyst Workstation (Tabs)
* **IP Reputation Checker:** Simulates an OSINT lookup returning geolocation, threat risk scoring (0–100), malware family association, and blacklist statuses.
* **Hash Analyzer:** Simulates binary database comparisons (resembling VirusTotal) to return threat classifications and detection ratios.
* **Phishing Email Sandbox:** Analyzes incoming message strings for suspicious keywords, urgent language, and technical mismatches.
* **Vulnerability Scanner:** Simulates a port audit against designated domains, outputting open ports, service versions, matched CVE numbers, and patch guidelines.

### 4. Incident Response Playbook Panel
* Fires active alert overrides on critical events, giving the user 60 seconds to select a playbook remediation step (e.g., Isolate Host, Firewall IP Block, Escalate to Tier-2, or Ignore).
* Implements a state-machine that logs success or failure metrics based on whether the chosen action is appropriate for the threat vector.

### 5. Threat Intelligence & Dark Web Monitoring
* Features active threat actor monitor feeds (APT profiles), global DEFCON status dials, and mock dark web scanners detailing credential leaks, API exposures, and forum mentions.

---

## Gamification & Educational Layer

* **Performance Scorecard:** Tracks real-time operations metrics: *Threats Neutralized, Breaches, Mean Time to Detect (MTTD),* and *Mean Time to Respond (MTTR)*.
* **XP & Tier Ranks:** Triage decisions yield Experience Points (XP) allowing progression through analyst ranks: *Junior Analyst ➔ Analyst ➔ Senior Analyst ➔ Threat Hunter ➔ SOC Lead*.
* **Achievement Engine:** Pop-up banners reward defensive milestones (e.g., *First Blood, Speed Demon*).
* **Learn Mode Sidebar:** A collapsible glossary defining cybersecurity vocabulary directly referenced in the simulation (such as SIEM, IOCs, CVE, CVSS, and MTTD/MTTR).

---

## Technical Design Specifications

* **Color Palette:** Deep background values (`#05080c`), cyan highlight accents (`#00d4ff`), and standard alert indicators (amber for warnings, red for critical actions).
* **Matrix Rain Background:** Animated via a low-opacity, high-performance HTML5 Canvas script to preserve CPU headroom.
* **Responsive Layout:** Designed to scale dynamically across laptop and desktop monitor screen dimensions.
* **External Integration:** Handled natively with the browser's DOM; optionally pulls Chart.js from a CDN if you decide to extend the reporting graph elements.

---

## Getting Started / Deployment

Because the application is completely self-contained within a single HTML file and uses mocked database responses, deployment is simple:

1. Clone or download the repository:
   ```bash
   git clone https://github.com/yourusername/sentinel-dashboard.git
