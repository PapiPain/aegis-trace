# 🛡️ AegisTrace — Zero-Knowledge API Dead-Code & Attack Surface Auditor

**AegisTrace** combines **Static AST Route Analysis** with **Zero-Knowledge Runtime Telemetry (HMAC-SHA256)** to detect and safely prune zombie API endpoints in Node.js & Express applications without ever exposing URLs, payloads, or PII.

## 🚀 Why AegisTrace?

- **Beyond Static Analysis:** Tools like `knip` or `ts-prune` cannot detect unused Express routes (`app.get`, `router.post`) because they are bound to the router object. AegisTrace crosses AST declarations with real runtime traffic.
- **Zero-Knowledge Privacy:** Routes are normalized and hashed locally via `HMAC-SHA256` before leaving your server. Only blind cryptographic hashes are stored.
- **Anti-Bot Noise Filter:** Automatically ignores `404` scanner noise and unregistered paths.
- **Safe Interactive Pruning & 1-Click Rollback:** Comment out or remove zombie routes with automatic `.aegis.bak` backups and instant restoration (`--restore`).

---

## 📦 Quick Start (Zero-Server Local Mode)

### 1. Install the Middleware SDK
```bash
npm install @aegistrace/node-sdk