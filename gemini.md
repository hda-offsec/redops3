# REDOPS3 — DEVELOPMENT MANIFESTO & TECHNICAL GUIDELINES

## 1. PROJECT IDENTITY & PURPOSE

**Name:** RedOps3  
**Type:** Offensive Security Orchestration Framework (Red Team / Pentest)  
**Scope:** PTES 9-step methodology (Recon → Enumeration → Vulnerability Mapping → Initial Access → Priv Esc → Lateral → Post-Ex → Reporting → Lessons Learned)  
**Philosophy:** *Assist the operator, never replace human judgment.*

### Mission
Provide a **centralized, structured, and auditable Red Team framework** that orchestrates best-in-class offensive tools while preserving:
- Analyst control
- Operational transparency
- OSCP / real-world pentest constraints

RedOps3 is **not** an auto-exploitation engine.  
It is a **decision-support system for professional attackers**.

### Target Audience
- Red Team operators
- Offensive security consultants
- OSCP / OSEP / CRTO candidates
- Internal security teams performing adversary simulations

---

## 2. CORE PRINCIPLES (NON-NEGOTIABLE)

1. **No Black Box**
   - Every command executed must be visible
   - Every result must be traceable
2. **Human-in-the-Loop**
   - No automatic exploitation
   - Suggestions ≠ actions
3. **Modularity over Monolith**
   - Each phase is independent
   - Tools can be replaced without refactoring the core
4. **OSCP-Compatible Mindset**
   - No auto-exploitation
   - Focus on methodology, not magic
5. **Operational Realism**
   - What works in labs must work in production-like environments

---

## 3. TECHNOLOGY STACK (STRICT)

### Backend
- **Python 3.11+**
- **Flask** (lightweight, explicit routing, no hidden magic)
- Background execution via:
  - threading / subprocess
  - future Celery support (RedOps4)

### Configuration
- Environment variables (`.env`)
- No secrets in code
- 12-Factor App principles

### Storage
- **SQLite** (metadata index)
- **JSON results** per scan in `data/results/scan_<id>.json`
- Designed for:
  - scan history
  - targets
  - findings
  - timelines
  - results archive

### Frontend
- **Jinja2 server-side rendering**
- **Vue.js (lightweight, optional, no SPA)**  
  Used only for:
  - live stdout
  - progress bars
  - timelines
- **Bootstrap 5**
- No React
- No heavy frontend frameworks

### Core Tools (Orchestrated, Not Rewritten)
- Nmap (+ NSE)
- Nuclei
- Searchsploit
- ffuf / gobuster / dirsearch
- WhatWeb / Wappalyzer
- Custom API & WAF testers
- Future: BloodHound ingestion (no auto abuse)

---

## 4. UI / UX PHILOSOPHY (RED TEAM FIRST)

**Design Goal:** Tactical clarity over aesthetics.

### Layout
- Left sidebar: phases of the kill chain
- Main panel: results, logs, timelines
- Dark mode by default

### UX Rules
- Results first, logs second
- Every scan shows:
  - command executed
  - duration
  - stdout / stderr
  - tool version
- No hidden background activity
- No modal hell

### Operational Safety
- Explicit authorization confirmation required before scans
- No automatic exploitation or payloads
- Wordlists are configurable via `WORDLIST_PATH`

### Visual Conventions
- Badges for severity
- Timelines for scan phases
- Tables for raw findings
- Cards for synthesis only

---

## 5. ARCHITECTURE & FOLDER STRUCTURE

```text
redops3/
├── scan_engine/
│   ├── orchestrator.py
│   ├── step01_recon/
│   ├── step02_enum/
│   ├── step03_vuln/
│   ├── step04_customapi/
│   ├── step05_dirbusting/
│   ├── step06_priv_esc/
│   ├── step07_lateral/
│   ├── step08_postex/
│   ├── step09_report/
│   └── helpers/
│
├── core/
│   ├── models.py
│   ├── timeline.py
│   ├── suggestions.py
│   └── mapping.py
│
├── ui/
│   ├── web/
│   │   ├── views/
│   │   ├── templates/
│   │   └── static/
│   └── socketio/
│
├── data/
│   ├── results/
│   ├── reports/
│   └── wordlists/
│
└── app.py
```
