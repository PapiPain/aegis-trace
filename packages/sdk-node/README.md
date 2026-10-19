# Maiestor Stelfid

> **An authority that guides with purpose and trust.**  
> *Connect your API code with real runtime traffic to identify unnecessary routes and retire them with verifiable evidence — without breaking production.*

---

## Core Purpose

Removing an unused API endpoint should never be a blind guess. An endpoint with `0 hits` in a short local test might be an annual billing webhook, a disaster-recovery trigger, or a partner integration. Conversely, an abandoned, unauthenticated debug route left in production is a high-risk entry point (**OWASP API9:2023 — Improper Inventory Management**).

**Maiestor Stelfid** bridges static code analysis with privacy-preserving runtime telemetry (`HMAC-SHA256`) so engineering and security teams can:
1. **Inventory what exists** across Express/Node.js route declarations and authentication middlewares.
2. **Measure what is actually used** without logging plaintext URLs, payloads, or PII.
3. **Retire routes safely with evidence**, respecting observation windows, environment coverage, test references, and explicit exemptions (`// @stelfid-keep`).

---

## Evidence-Based Retirement Model (Why Zero Hits != Instant Delete)

Maiestor Stelfid never turns a short absence of traffic into an automatic deletion order. Every route is evaluated across five evidence dimensions before recommending retirement:

| Evidence Dimension | How Maiestor Stelfid Evaluates It | Protection Against Breaking Production |
| :--- | :--- | :--- |
| **1. Observation Window** | Tracks `observationStartedAt` and total days observed. | Blocks automatic pruning if the observation window is shorter than your configured threshold (`--min-days 14`). |
| **2. Environment Context** | Distinguishes `local`, `staging`, and `production` telemetry. | Routes with 0 hits in `local` are labeled **Unobserved (Low Confidence)**, never falsely flagged as dead in production. |
| **3. Explicit Exemptions (`@stelfid-keep`)** | Reads inline code annotations (`// @stelfid-keep: annual-webhook`). | Permanently exempts emergency, seasonal, or external integration routes from pruning and warnings. |
| **4. Test & Static Reachability** | Cross-checks route paths against `*.test.ts` / `*.spec.ts` files. | Highlights whether an unobserved route is still actively covered by integration tests. |
| **5. Auth Surface Analysis** | Detects route-level and global `app.use` auth middlewares. | Prioritizes unauthenticated, unobserved routes for security review (**OWASP API9:2023**). |

---

## Product Maturity & Transparency Matrix

We believe in strict engineering candor. Below is the exact status of every capability in the Maiestor Stelfid ecosystem:

| Capability | Status | Scope & Current Limitations |
| :--- | :--- | :--- |
| **Static Route & Auth Scanner (Express.js)** | **Implemented & Verified** | Scans `.ts`/`.js` files, resolves `@stelfid-prefix`, detects common auth middleware patterns, and cross-checks test files. |
| **Zero-Knowledge Local Telemetry (`HMAC-SHA256`)** | **Implemented & Verified** | Hashes `METHOD:/normalized/route` locally with your secret key and records observation window metadata. |
| **Retirement Confidence & `@stelfid-keep` Guard** | **Implemented & Verified** | Prevents premature `--prune` execution when observation window or environment coverage is insufficient. |
| **VS Code Extension (CodeLens + 1-Click Keep/Prune)** | **Implemented & Verified** | Real-time inline status, 1-click `Safe Prune`, and 1-click `Keep Route (@stelfid-keep)` annotation. |
| **Centralized HTTP Ingestion API** | **Prototype (Local/Single-Node)** | Functional ingestion service in `apps/ingestion-api`; multi-node production cluster scaling is under validation. |
| **Dormant Route Reactivation Alerts (Observe-First)** | **Planned in Roadmap** | Contextual alerts when a long-dormant route receives traffic, defaulting to **Observe-Only** mode (never blocking legitimate legacy clients). |
| **Audit Evidence Exports & Multi-Framework Support** | **Planned in Roadmap** | Exportable inventory evidence reports to assist internal security reviews (note: reports provide technical evidence and do not constitute automatic SOC 2 or ISO 27001 certification). |

---

## Quick Start

```bash
# 1. Run an evidence-based audit on your workspace
npx @m_stelfid/cli --dir ./apps/test-service --secret sec_secretkey_test987

# 2. Mark an intentional low-frequency route in your code so it is never pruned
// @stelfid-keep: annual-tax-reconciliation-webhook
app.post('/api/v1/webhooks/annual-close', requireAuth, handler);

# 3. Safely comment out only verified retirement candidates
npx @m_stelfid/cli --dir ./apps/test-service --prune
```

---

*Built with purpose and engineering rigor by **Ezequiel Canales Moran** — **Maiestor Stelfid Labs**.*
