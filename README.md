# PhishLens v2 — Security Analyst Edition

A defensive `.eml` investigation platform with a clean analyst-oriented interface.

## Included
- Explainable risk scoring
- SPF/DKIM/DMARC analysis
- Header forensics
- Reply-To / Return-Path mismatch detection
- Received-chain evidence
- Content and social-engineering indicators
- HTML/link analysis
- URL classification: ACTION / NAVIGATION / RESOURCE / TRACKING
- URL Intelligence "Show more" modal with tabs
- DNS intelligence
- VirusTotal lookup support
- urlscan support
- IOC extraction
- Attachment hashing and dangerous-extension checks
- MITRE ATT&CK mapping
- Analyst notes and SQLite case IDs
- PDF report export
- Docker + Nginx + Flask

## Start
```bash
cp .env.example .env
docker compose up --build
```

Open:
http://localhost:8080

Health:
http://localhost:8080/api/health

## Optional reputation APIs
Set `VT_API_KEY` and/or `URLSCAN_API_KEY` in `.env`, then set the corresponding feature flag.

`ENABLE_VT=true` enables VirusTotal lookups.

`ENABLE_ACTIVE_URL_SCAN=true` enables urlscan submission. Keep this disabled for normal testing because submitting arbitrary email URLs causes external scanning.

## Important security design
Active redirect fetching is intentionally not implemented in this starter release. A production redirect worker should run in a separate network-isolated service with SSRF protections, DNS rebinding protection, egress allow/deny controls, timeouts and a redirect limit.

## Suggested next production additions
RDAP/WHOIS enrichment, ASN/GeoIP, certificate inspection, isolated redirect worker, QR decoding, sandbox attachment detonation, persistent scan history, authentication, RBAC, and SIEM/SOAR integrations.
