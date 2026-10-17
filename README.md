# 🛡️ AegisTrace — Zero-Knowledge API Dead-Code & Attack Surface Auditor

[![NPM SDK Version](https://img.shields.io/npm/v/@aegis-trace/node-sdk?label=%40aegis-trace%2Fnode-sdk&color=blue)](https://www.npmjs.com/package/@aegis-trace/node-sdk)
[![NPM CLI Version](https://img.shields.io/npm/v/@aegis-trace/cli?label=%40aegis-trace%2Fcli&color=brightgreen)](https://www.npmjs.com/package/@aegis-trace/cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**AegisTrace** is a security and code-hygiene ecosystem for **Node.js & Express** applications. It combines **Static AST (Abstract Syntax Tree) Route Analysis** with **Zero-Knowledge Runtime Telemetry (`HMAC-SHA256`)** to detect, document line-by-line, and safely prune unused ("zombie") API endpoints without ever exposing sensitive URLs, query parameters, payloads, or PII.

---

## 📖 Table of Contents / Tabla de Contenidos

1. [How AegisTrace Works Internally (5-Stage Architecture)](#sec-1)
2. [Complete Step-by-Step User Guide (From Setup to Rollback)](#sec-2)
   - [Phase A: Installing & Recording Blind Traffic](#phase-a)
   - [Phase B: Auditing in Read-Only Mode (No Code Modified)](#phase-b)
   - [Phase C: Generating the Explicit Line-by-Line Audit Document](#phase-c)
   - [Phase D: Deciding What to Do with Dead Code (Keep, Comment Out, or Delete)](#phase-d)
   - [Phase E: Instant Rollback / Undo (`--restore`)](#phase-e)
3. [Complete CLI Flags Reference](#sec-3)
4. [Guía Completa Paso a Paso (Español)](#sec-4)

---

<a id="sec-1"></a>

## ⚙️ 1. How AegisTrace Works Internally (5-Stage Architecture)

Traditional static analysis tools (`knip`, `ts-prune`, `eslint`) cannot detect unused Express routes (`app.get`, `router.post`) because route handlers are passed as anonymous callbacks bound to the router object—meaning they always appear "referenced" in memory even if nobody calls them in production. **AegisTrace solves this through 5 automated stages:**

1. **Non-Blocking Runtime Interception (`@aegis-trace/node-sdk`):** Hooks into Express's `res.on('finish')` event so it adds **0ms of latency** to your API responses.
2. **Anti-Bot Noise Filter & Dynamic Route Normalization:**
   - If a bot or scanner requests a non-existent path (`/wp-admin`, `/.env`) resulting in `req.route === undefined` (`404`), AegisTrace discards it immediately.
   - Dynamic parameters (`/api/users/94812` or UUIDs) are normalized back to their canonical Express declaration (`GET:/api/users/:id`).
3. **Zero-Knowledge `HMAC-SHA256` Blind Hashing:** The normalized string (`GET:/api/users/:id`) is hashed locally in memory using `HMAC-SHA256` and your secret key. Neither the endpoint name nor any request data ever leaves your server—only a blind 64-character cryptographic hash (`e.g., 4f8a9c...`) and its hit counter.
4. **AST Source Code Scanning & Router Prefix Resolution (`@aegis-trace/cli`):** The CLI parses all `.ts` and `.js` files in your project, detects both direct routes (`app.get`) and modular Express routers (`app.use('/api/legacy', legacyRouter)`), and records the **exact file name, start line (`startLine`), end line (`endLine`), and code block** of every route.
5. **Cryptographic Cross-Check & Confidence Scoring:** The CLI hashes every route found in your source code and compares it against the runtime telemetry hashes. Any route with `0 hits` is flagged as a **Zombie Endpoint**, and AegisTrace calculates the **Attack Surface Reduction %** and **Statistical Pruning Confidence** (`LOW`, `MEDIUM`, `HIGH`).

---

<a id="sec-2"></a>

## 🚀 2. Complete Step-by-Step User Guide (From Setup to Rollback)

Below is the exact workflow a developer follows when integrating AegisTrace into any Express project:

<a id="phase-a"></a>

### Phase A: Installing & Recording Blind Traffic

1. **Step 1 — Install the lightweight SDK middleware in your Express project:**

        npm install @aegis-trace/node-sdk

2. **Step 2 — Register the middleware in your main Express file (`app.ts` or `server.ts`) before declaring your routes:**

        import express from 'express';
        import { aegisMiddleware } from '@aegis-trace/node-sdk';

        const app = express();

        // Zero-Server Local Mode: stores blind HMAC-SHA256 hashes locally in .aegis-local.json
        app.use(aegisMiddleware({
          secret: process.env.AEGIS_SECRET || 'your-private-hmac-secret',
          localMode: true,
          localFilePath: './.aegis-local.json'
        }));

   *As your application runs in staging or production, `.aegis-local.json` (or the SQLite server) quietly accumulates hit counts per cryptographic hash.*

<a id="phase-b"></a>

### Phase B: Auditing in Read-Only Mode (No Code Modified)

By default, **AegisTrace NEVER modifies, comments out, or deletes your files.** It runs in strict **Read-Only (`--dry-run`)** mode so you can inspect your project safely:

    npx @aegis-trace/cli --dir=./src --local

- **Scans all files inside `./src`** and reads the blind hashes from `.aegis-local.json`.
- **Prints a complete terminal summary** showing which routes are `[ACTIVE]` and which routes are `[ZOMBIE: 0 hits]`, along with their exact file and line range (`app.ts:38 (Lines 38-40)`).

<a id="phase-c"></a>

### Phase C: Generating the Explicit Line-by-Line Audit Document

If you need a formal, shareable document that explicitly states **which exact lines of code are doing nothing**, their isolated code snippet, their cryptographic hash, and the exact security metrics:

    # Option 1: Generate a Detailed Markdown Report (SECURITY_AUDIT.md)
    npx @aegis-trace/cli --dir=./src --local --output=SECURITY_AUDIT.md --format=markdown

    # Option 2: Generate a Machine-Readable JSON Report (audit-report.json)
    npx @aegis-trace/cli --dir=./src --local --output=audit-report.json --format=json

- **Executive Metrics:** Total declared endpoints, active endpoints, zombie endpoints (`0 hits`), shadow endpoints, **Attack Surface Reduction (%)**, and **Statistical Confidence Level**.
- **Line-by-Line Inventory Table:** Lists every route with its HTTP Method, normalized path, **exact file and line range (`startLine`–`endLine`)**, risk level (`HIGH (Mutation)` vs `Medium (Read)`), hit count, and `HMAC-SHA256` signature.
- **Isolated Dead Code Snippets:** Prints the exact block of code inside those lines so developers can verify what the unused endpoint does without opening the editor.

<a id="phase-d"></a>

### Phase D: Deciding What to Do with Dead Code (Keep, Comment Out, or Delete)

Once you review the report, **you have 100% control over whether to touch the code or not**:

1. **Choice 1 — Do Nothing (Keep the Code Intact):** If you only wanted the audit document (`SECURITY_AUDIT.md`) for security compliance or manual review, simply stop here. None of your source files have been altered.
2. **Choice 2 — Interactive Assistant (`--prune`):** Run the interactive assistant to decide route-by-route what to do:

        npx @aegis-trace/cli --dir=./src --local --prune

   For each detected Zombie Endpoint, AegisTrace displays the affected code lines (`startLine`–`endLine`) and presents **4 explicit options (`[c/d/s/q]`)**:
   - **`[c]` Comment out code block (Safe, reversible):** Asks for confirmation (`[y/n]`), creates an automatic backup (`<file>.aegis.bak`), and wraps the exact dead lines in a `/* [AegisTrace: Dead-Code Audit] ... */` comment block.
   - **`[d]` Delete code block permanently:** Displays a security warning and requires typing `"DELETE"` to confirm, creates an automatic backup (`<file>.aegis.bak`), and physically removes the dead lines from the file.
   - **`[s]` Skip / Keep unchanged:** Leaves that route untouched and moves to the next candidate.
   - **`[q]` Quit assistant:** Immediately exits the interactive process.

<a id="phase-e"></a>

### Phase E: Instant Rollback / Undo (`--restore`)

If you change your mind after commenting out or deleting routes, you can **undo all changes in 1 second** with a single command:

    npx @aegis-trace/cli --dir=./src --restore

- **Automatic File Restoration:** Searches your directory for all `.aegis.bak` backup files, restores every modified `.ts` / `.js` file back to its exact original state, and removes the temporary `.aegis.bak` files.

---

<a id="sec-3"></a>

## 🛠️ 3. Complete CLI Flags Reference

| Flag / Option | Description | Default |
| :--- | :--- | :--- |
| `--dir=<path>` | Target source directory to scan for Express routes. | `./src` |
| `--local` | Reads telemetry directly from `.aegis-local.json` without needing the SQLite server. | `false` |
| `--output=<filename>` | Exports the explicit line-by-line audit report to a file (`SECURITY_AUDIT.md` or `.json`). | Console only |
| `--format=<type>` | Output document format: `markdown` (`md`) or `json`. | `json` |
| `--days=<number>` | Filters runtime telemetry to the last `N` days. | Full history |
| `--prune` | Launches the interactive `[c/d/s/q]` assistant to comment out or delete zombie routes (creates `.aegis.bak`). | `false` (Read-Only) |
| `--restore` | Reverts all modified files back to their original state using `.aegis.bak` backups. | `false` |
| `--fail-on-zombies` | Exits with code `1` if zombie routes are found (ideal for strict CI/CD pipelines). | `false` |

---

<a id="sec-4"></a>

## 🇪🇸 4. Guía Completa Paso a Paso (Español)

1. **Paso 1 — Recolección Ciega en Tiempo de Ejecución (`@aegis-trace/node-sdk`):** Instalas el middleware en tu servidor Express. Cada petición legítima se normaliza (`/api/users/123` -> `GET:/api/users/:id`), ignora el ruido de bots (`404`) y se convierte localmente en un hash criptográfico ciego (`HMAC-SHA256`) guardado en `.aegis-local.json` (Modo Local) o en SQLite (Modo Cloud).
2. **Paso 2 — Auditoría en Modo Sólo Lectura y Generación del Documento Forense (`@aegis-trace/cli`):**
   - Al ejecutar `npx @aegis-trace/cli --dir=./src --local`, la herramienta analiza el árbol sintáctico (AST), resuelve prefijos de `Express.Router()` y muestra en consola qué rutas están activas y cuáles son zombis sin tocar ni una línea de tu código.
   - Al añadir `--output=SECURITY_AUDIT.md --format=markdown`, genera un **documento detallado** que especifica el **archivo exacto, el rango de líneas (`startLine`–`endLine`), el nivel de riesgo, el bloque aislado de código que no hace nada en producción y el porcentaje de reducción de superficie de ataque**.
3. **Paso 3 — Decisión Interactiva sobre el Código Muerto (`--prune`):** Si deseas intervenir el código, ejecutas `npx @aegis-trace/cli --dir=./src --local --prune`. Por cada ruta zombi podrás elegir:
   - **`[c]` Comentar el bloque:** Pide confirmación `[y/n]`, crea un respaldo `.aegis.bak` y comenta las líneas muertas.
   - **`[d]` Eliminar el bloque:** Pide escribir `"DELETE"` por seguridad, crea el respaldo `.aegis.bak` y borra físicamente las líneas.
   - **`[s]` Omitir:** Deja ese bloque intacto sin cambios.
   - **`[q]` Salir:** Cancela el asistente inmediatamente.
4. **Paso 4 — Reversión Instantánea en 1 Clic (`--restore`):** Si deseas deshacer cualquier cambio (incluso si borraste líneas con `[d]`), ejecutas `npx @aegis-trace/cli --dir=./src --restore` y todos tus archivos volverán instantáneamente a su estado original gracias a los respaldos `.aegis.bak`.

---

## 📄 License

MIT © Ezequiel Canales