# 🛡️ ThreatLens

A lean, production-style Streamlit application for cybersecurity threat intelligence aggregation and AI-driven analysis.

ThreatLens checks whether an IP address, domain, or URL is safe or suspicious using **VirusTotal** and **WHOIS**, then generates a concise, human-readable assessment using **Google Gemini** tailored to the user's technical background.

---

## 🛠️ Features

- **Multi-Target Analysis:** Supports IPv4/IPv6 addresses, domains (with IDNA support), and URLs.
- **Concurrent Source Lookups:** Queries VirusTotal and WHOIS in parallel using thread pools for optimal speed.
- **Adaptive AI Insights:** Uses Google Gemini with structured outputs calibrated across 3 knowledge levels (Beginner, Intermediate, Expert).
- **Rule-Based Fallback:** Computes a deterministic baseline heuristic verdict if Gemini is unavailable or rate-limited.
- **Extensible Architecture:** Strict one-way module dependencies allowing easy addition of new threat intelligence sources.

---

## 🚀 Quickstart Guide

### 1. Prerequisites
Ensure you have Python 3.9+ installed on your system.

### 2. Set Up Environment Variables
Copy `.env.example` to create a local `.env` file:
```bash
cp .env.example .env