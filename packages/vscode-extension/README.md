# 🛡️ AegisTrace SecOps — VS Code Extension

**Zero-Knowledge API Dead-Code & OWASP API9:2023 Attack Surface Auditor for Node.js & Express.**

AegisTrace correlates static AST route declarations with blind runtime telemetry (`HMAC-SHA256`) directly inside Visual Studio Code:

- 🚨 **Unauthenticated Zombie Route Detection (CRITICAL):** Highlights dormant endpoints lacking authentication middleware (`JWT`, `Session`, `AuthGuard`).
- 🟢 **Real-Time Traffic CodeLens:** Displays observed production/staging hit counts directly above every `app.get()`, `router.post()`, `app.delete()` block.
- 🛡️ **1-Click Safe Pruning:** Comment out dead routes with audit timestamps directly from the editor.

## Plans & Cloud Telemetry
- **Local Mode (Free):** Uses local `.aegis-local.json` telemetry.
- **Pro ($49/mo) · Team ($149/mo) · Business ($399/mo):** Multi-node cloud telemetry, 90-365 day forensic retention, Slack/SIEM honeypot alerts, and automated PR pruning.
