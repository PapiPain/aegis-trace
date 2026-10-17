# 🛡️ AegisTrace — Zero-Knowledge API Dead-Code & Attack Surface Auditor

[![NPM SDK Version](https://img.shields.io/npm/v/@aegis-trace/node-sdk?label=%40aegis-trace%2Fnode-sdk&color=blue)](https://www.npmjs.com/package/@aegis-trace/node-sdk)
[![NPM CLI Version](https://img.shields.io/npm/v/@aegis-trace/cli?label=%40aegis-trace%2Fcli&color=brightgreen)](https://www.npmjs.com/package/@aegis-trace/cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**AegisTrace** is a security and code-hygiene ecosystem for **Node.js & Express** applications. It combines **Static AST (Abstract Syntax Tree) Route Analysis** with **Zero-Knowledge Runtime Telemetry (`HMAC-SHA256`)** to detect, document line-by-line, and safely prune unused ("zombie") API endpoints without ever exposing sensitive URLs, query parameters, payloads, or PII.

---

## 📖 Table of Contents / Tabla de Contenidos
1. [How AegisTrace Works Internally (5-Stage Architecture)](#-1-how-aegistrace-works-internally-5-stage-architecture)
2. [Complete Step-by-Step User Guide (From Setup to Rollback)](#-2-complete-step-by-step-user-guide-from-setup-to-rollback)
   - [Phase A: Installing & Recording Blind Traffic](#phase-a-installing--recording-blind-traffic)
   - [Phase B: Auditing in Read-Only Mode (No Code Modified)](#phase-b-auditing-in-read-only-mode-no-code-modified)
   - [Phase C: Generating the Explicit Line-by-Line Audit Document](#phase-c-generating-the-explicit-line-by-line-audit-document)
   - [Phase D: Deciding What to Do with Dead Code (Keep, Comment Out, or Delete)](#phase-d-deciding-what-to-do-with-dead-code-keep-comment-out-or-delete)
   - [Phase E: Instant Rollback / Undo (`--restore`)](#phase-e-instant-rollback--undo---restore)
3. [Complete CLI Flags Reference](#-3-complete-cli-flags-reference)
4. [Guía Completa Paso a Paso (Español)](#-4-guía-completa-paso-a-paso-español)

---

## ⚙️ 1. How AegisTrace Works Internally (5-Stage Architecture)

Traditional static analysis tools (`knip`, `ts-prune`, `eslint`) cannot detect unused Express routes (`app.get`, `router.post`) because route handlers are passed as anonymous callbacks bound to the router object—meaning they always appear "referenced" in memory even if nobody calls them in production. **AegisTrace solves this through 5 automated stages:**

1. **Non-Blocking Runtime Interception (`@aegis-trace/node-sdk`):**
   Hooks into Express's `res.on('finish')` event so it adds **0ms of latency** to your API responses.
2. **Anti-Bot Noise Filter & Dynamic Route Normalization:**
   - If a bot or scanner requests a non-existent path (`/wp-admin`, `/.env`) resulting in `req.route === undefined` (`404`), AegisTrace discards it immediately.
   - Dynamic parameters (`/api/users/94812` or UUIDs) are normalized back to their canonical Express declaration (`GET:/api/users/:id`).
3. **Zero-Knowledge `HMAC-SHA256` Blind Hashing:**
   The normalized string (`GET:/api/users/:id`) is hashed locally in memory using `HMAC-SHA256` and your secret key. Neither the endpoint name nor any request data ever leaves your server—only a blind 64-character cryptographic hash (`e.g., 4f8a9c...`) and its hit counter.
4. **AST Source Code Scanning & Router Prefix Resolution (`@aegis-trace/cli`):**
   The CLI parses all `.ts` and `.js` files in your project, detects both direct routes (`app.get`) and modular Express routers (`app.use('/api/legacy', legacyRouter)`), and records the **exact file name, start line (`startLine`), end line (`endLine`), and code block** of every route.
5. **Cryptographic Cross-Check & Confidence Scoring:**
   The CLI hashes every route found in your source code and compares it against the runtime telemetry hashes. Any route with `0 hits` is flagged as a **Zombie Endpoint**, and AegisTrace calculates the **Attack Surface Reduction %** and **Statistical Pruning Confidence** (`LOW`, `MEDIUM`, `HIGH`).

---

## 🚀 2. Complete Step-by-Step User Guide (From Setup to Rollback)

Below is the exact workflow a developer follows when integrating AegisTrace into any Express project:

### Phase A: Installing & Recording Blind Traffic

**Step 1:** Install the lightweight SDK middleware in your Express project:
```bash
npm install @aegis-trace/node-sdk


Step 2: Add the middleware to your main Express file (app.ts or server.ts) before declaring your routes:

import express from 'express';
import { aegisMiddleware } from '@aegis-trace/node-sdk';

const app = express();

// Option 1: Zero-Server Local Mode (saves blind hashes locally in .aegis-local.json)
app.use(aegisMiddleware({
  secret: process.env.AEGIS_SECRET || 'your-private-hmac-secret',
  localMode: true,
  localFilePath: './.aegis-local.json'
}));

// Option 2: Cloud / Centralized SQLite Server Mode (for multi-container deployments)
/*
app.use(aegisMiddleware({
  apiKey: process.env.AEGIS_API_KEY,
  secret: process.env.AEGIS_SECRET,
  ingestionUrl: 'http://localhost:4000/api/v1/ingest'
}));
*/

As your application runs in staging or production, .aegis-local.json (or the SQLite database) quietly accumulates hit counts per cryptographic hash.

Phase B: Auditing in Read-Only Mode (No Code Modified)
By default, AegisTrace NEVER modifies, comments out, or deletes your files. It runs in strict Read-Only (--dry-run) mode so you can inspect your project safely:

npx @aegis-trace/cli --dir=./src --local

What this step does:

Scans all files inside ./src.

Reads the blind hashes from .aegis-local.json.

Prints a complete terminal summary showing which routes are [ACTIVO] and which routes are [ZOMBI: 0 hits], along with their exact file and line number (e.g., app.ts:38).

Phase C: Generating the Explicit Line-by-Line Audit Document
If you want a formal, shareable document that explicitly states which exact lines of code are doing nothing, their isolated code snippet, their cryptographic hash, and the exact security metrics:

Option 1 — Generate a Detailed Markdown Report (SECURITY_AUDIT.md):

npx @aegis-trace/cli --dir=./src --local --output=SECURITY_AUDIT.md --format=markdown

Option 2 — Generate a Machine-Readable JSON Report (audit-report.json):

npx @aegis-trace/cli --dir=./src --local --output=audit-report.json --format=json

📄 What the Generated Document Explicitly Contains:
Executive Metrics: Total endpoints declared, active endpoints, zombie endpoints (0 hits), shadow endpoints, Attack Surface Reduction (%), and Statistical Confidence Level.

Line-by-Line Zombie Table: Lists every dead route with its HTTP Method, full normalized path, exact file path, exact line range (startLine – endLine, e.g., Lines 38–40), hit count (0), and HMAC-SHA256 signature.

Isolated Dead Code Snippets: Prints the exact block of code inside those lines so developers can review what the unused endpoint is doing without even opening the code editor.

Phase D: Deciding What to Do with Dead Code (Keep, Comment Out, or Delete)
Once you review the report, you have 100% control over whether to touch the code or not:

Choice 1: Do Nothing (Keep the Code Intact)
If you only wanted the audit document (SECURITY_AUDIT.md) for security compliance or manual review, simply stop here. None of your source files have been altered.

Choice 2: Interactive Safe Commenting (--prune) — Recommended
If you want AegisTrace to neutralize dead routes step-by-step without losing the code:

npx @aegis-trace/cli --dir=./src --local --prune

What happens step-by-step during --prune:

AegisTrace shows you each Zombie Endpoint one by one in the terminal (e.g., GET /api/legacy/export-v1 in src/app.ts [Lines 38-40]).

It asks for your confirmation: ¿Neutralizar este endpoint zombi? (s/N).

If you type n (or press Enter): AegisTrace skips that route and leaves those lines untouched.

If you type s:

AegisTrace first creates an exact backup copy of your original file (src/app.ts.aegis.bak).

It wraps the exact dead lines (startLine to endLine) in a clear [AEGIS-TRACE ZOMBIE PRUNED] comment block (//), disabling the route while keeping the code visible in your file.

Choice 3: Physical Line Deletion (--prune --delete)
If you want AegisTrace to physically remove the dead lines from the file instead of commenting them out:

npx @aegis-trace/cli --dir=./src --local --prune --delete

(Even when using --delete, AegisTrace still creates the .aegis.bak backup file first so you are protected against mistakes).

Phase E: Instant Rollback / Undo (--restore)
Changed your mind after pruning or deleting routes? Or did a test fail after disabling a legacy endpoint? You can undo all changes in 1 second with a single command:

npx @aegis-trace/cli --dir=./src --restore

What --restore does:Searches your directory for all .aegis.bak backup files created during pruning.Restores every modified .ts / .js file back to its exact byte-for-byte original state.Cleans up the .aegis.bak files automatically.🛠️ 3. Complete CLI Flags ReferenceFlag / OptionDescriptionDefault--dir=<path>Target source directory to scan for Express routes../src--localReads telemetry directly from .aegis-local.json without needing the SQLite server.false--local-file=<path>Custom path to the local JSON telemetry file../.aegis-local.json--output=<filename>Exports the explicit line-by-line audit report to a file (SECURITY_AUDIT.md or .json).None (Console only)--format=<type>Output document format: markdown (md) or json.json--pruneStarts the interactive prompt to neutralize zombie routes (creates .aegis.bak backups).false (Read-Only)--deleteUsed with --prune: physically deletes dead lines instead of commenting them out.false--yes / -ySkips interactive confirmation prompts and prunes all detected zombie routes automatically.false--restoreReverts all pruned/deleted files back to their original state using .aegis.bak backups.false🇪🇸 4. Guía Completa Paso a Paso (Español)¿Qué hace AegisTrace paso a paso y cómo se usa?Paso 1 — Recolección Ciega en Tiempo de Ejecución (@aegis-trace/node-sdk):Instalas el middleware en tu servidor Express. Cada vez que entra una petición real, AegisTrace filtra ataques de bots (404), normaliza los IDs dinámicos (/api/users/123 -> GET:/api/users/:id) y los convierte en un hash criptográfico ciego (HMAC-SHA256) que guarda en .aegis-local.json (Modo Local sin servidor) o en SQLite (Modo Cloud).Paso 2 — Escaneo del Código Fuente y Generación del Documento Detallado (@aegis-trace/cli):Al ejecutar el CLI, este analiza el árbol sintáctico (AST) de tus archivos .ts/.js, detecta los prefijos de Express.Router() y cruza tus rutas declaradas contra el tráfico real.Si ejecutas --output=SECURITY_AUDIT.md --format=markdown, genera un documento forense detallado que te indica explícitamente qué archivo, desde qué línea hasta qué línea (Línea 38 a 40) y qué bloque exacto de código no tiene actividad (0 hits), además del porcentaje de reducción de superficie de ataque y el nivel de confianza estadística.Paso 3 — Tú decides si deseas tocar el código o no:Si NO deseas borrar ni modificar nada: Simplemente usas el comando normal o generas el reporte .md/.json. Por defecto AegisTrace trabaja en modo Sólo Lectura (--dry-run) y jamás toca tus archivos.Si deseas neutralizar código muerto de forma interactiva (--prune): AegisTrace te pregunta ruta por ruta (s/N). Si respondes n, la ignora. Si respondes s, crea primero una copia de seguridad automática (.aegis.bak) y comenta (//) únicamente las líneas muertas.Si deseas borrar físicamente las líneas (--prune --delete): Elimina las líneas inactivas tras crear el respaldo .aegis.bak.Paso 4 — Cómo retroceder / deshacer cambios en 1 clic (--restore):Si después de podar o borrar rutas deseas arrepentirte y volver atrás, solo ejecutas npx @aegis-trace/cli --dir=./src --restore. AegisTrace restaurará instantáneamente todos tus archivos originales desde los respaldos .aegis.bak.📄 LicenseMIT © Ezequiel Canales
