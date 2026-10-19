const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");
const { generateBlindHash } = require("../packages/sdk-node/dist/index");

// Compilar transactionalIngestor.ts a JS o cargarlo para generar el estado agregado real de los 3 nodos
const txTsPath = path.join(process.cwd(), "apps", "ingestion-api", "src", "transactionalIngestor.ts");

async function runAuditSemanticsVerification() {
  const secret = "sec_secretkey_test987";
  const baseTimeMs = Date.parse("2026-09-19T00:00:00.000Z"); // Inicio de ventana (hace 30 dias)
  const dayMs = 24 * 60 * 60 * 1000;
  const endWindowIso = new Date(baseTimeMs + 30 * dayMs).toISOString();

  const hUsersGet = generateBlindHash("GET", "/api/users", secret);
  const hUserById = generateBlindHash("GET", "/api/users/:id", secret);
  const hShadowMetrics = generateBlindHash("GET", "/internal/prometheus-hidden-metrics", secret);
  const hBot404 = generateBlindHash("GET", "/wp-login.php", secret);

  // Construir la telemetria agregada de 3 nodos reales en momentos distintos de la ventana de 30 dias:
  // - node-prod-1: observa la Shadow API entre el dia 2 y el dia 9 (7 hits HTTP 200)
  // - node-prod-2: observa la Shadow API entre el dia 11 y el dia 19 (5 hits HTTP 200)
  // - node-prod-3: observa la Shadow API entre el dia 21 y el dia 29.15 (7 hits HTTP 200) -> Total = 19 hits, Span = 27.15 dias
  const node1First = new Date(baseTimeMs + 2.0 * dayMs).toISOString();
  const node1Last  = new Date(baseTimeMs + 9.2 * dayMs).toISOString();
  const node2First = new Date(baseTimeMs + 11.1 * dayMs).toISOString();
  const node2Last  = new Date(baseTimeMs + 19.4 * dayMs).toISOString();
  const node3First = new Date(baseTimeMs + 21.0 * dayMs).toISOString();
  const node3Last  = new Date(baseTimeMs + 29.15 * dayMs).toISOString();

  const multiNodeTelemetry = {
    _meta: {
      vendor: "Maiestor Stelfid Cluster Aggregator",
      schemaVersion: "1.6.4",
      environment: "production",
      nodeCount: 3,
      activeNodes: ["node-prod-1", "node-prod-2", "node-prod-3"],
      observationStartedAt: new Date(baseTimeMs).toISOString(),
      lastFlushedAt: endWindowIso,
      uniqueBatchesProcessed: 9
    },
    routes: {
      [hUsersGet]: {
        calls: 420,
        firstSeenAt: new Date(baseTimeMs + 0.1 * dayMs).toISOString(),
        lastSeen: new Date(baseTimeMs + 29.9 * dayMs).toISOString(),
        statusCodes: { "200": 420 },
        nodeBreakdown: {
          "node-prod-1": { calls: 150, firstSeenAt: new Date(baseTimeMs + 0.1 * dayMs).toISOString(), lastSeenAt: new Date(baseTimeMs + 29.5 * dayMs).toISOString() },
          "node-prod-2": { calls: 140, firstSeenAt: new Date(baseTimeMs + 0.2 * dayMs).toISOString(), lastSeenAt: new Date(baseTimeMs + 29.8 * dayMs).toISOString() },
          "node-prod-3": { calls: 130, firstSeenAt: new Date(baseTimeMs + 0.3 * dayMs).toISOString(), lastSeenAt: new Date(baseTimeMs + 29.9 * dayMs).toISOString() }
        }
      },
      [hUserById]: {
        calls: 185,
        firstSeenAt: new Date(baseTimeMs + 0.5 * dayMs).toISOString(),
        lastSeen: new Date(baseTimeMs + 29.7 * dayMs).toISOString(),
        statusCodes: { "200": 185 },
        nodeBreakdown: {
          "node-prod-1": { calls: 65, firstSeenAt: new Date(baseTimeMs + 0.5 * dayMs).toISOString(), lastSeenAt: new Date(baseTimeMs + 29.1 * dayMs).toISOString() },
          "node-prod-2": { calls: 60, firstSeenAt: new Date(baseTimeMs + 1.0 * dayMs).toISOString(), lastSeenAt: new Date(baseTimeMs + 29.4 * dayMs).toISOString() },
          "node-prod-3": { calls: 60, firstSeenAt: new Date(baseTimeMs + 1.2 * dayMs).toISOString(), lastSeenAt: new Date(baseTimeMs + 29.7 * dayMs).toISOString() }
        }
      },
      // SHADOW API REAL: 19 hits HTTP 200 agregados de los 3 nodos a lo largo de 27.15 dias
      [hShadowMetrics]: {
        calls: 19,
        firstSeenAt: node1First,
        lastSeen: node3Last,
        statusCodes: { "200": 19 },
        nodeBreakdown: {
          "node-prod-1": { calls: 7, firstSeenAt: node1First, lastSeenAt: node1Last },
          "node-prod-2": { calls: 5, firstSeenAt: node2First, lastSeenAt: node2Last },
          "node-prod-3": { calls: 7, firstSeenAt: node3First, lastSeenAt: node3Last }
        }
      },
      // Ruido 404 (ignorado por el detector de Shadow APIs)
      [hBot404]: {
        calls: 950,
        firstSeenAt: node1First,
        lastSeen: node3Last,
        statusCodes: { "404": 950 }
      }
    }
  };

  const telemetryFile = path.join(process.cwd(), "apps", "test-service", ".stelfid-local.json");
  fs.writeFileSync(telemetryFile, JSON.stringify(multiNodeTelemetry, null, 2) + "\n", "utf8");

  // Ejecutar el CLI v1.7.0-rc.1 exportando los 4 formatos (--min-days 14 --min-nodes 3)
  execFileSync(
    process.execPath,
    [
      path.join(process.cwd(), "packages", "cli", "dist", "index.js"),
      "--dir", "apps/test-service",
      "--min-days", "14",
      "--min-nodes", "3",
      "--export-evidence", "all"
    ],
    { stdio: "inherit" }
  );

  // Leer los 4 archivos exportados para verificar consistencia matematica y semantica
  const jsonReport = JSON.parse(fs.readFileSync("STELFID_AUDIT_EVIDENCE.json", "utf8"));
  const sarifReport = JSON.parse(fs.readFileSync("STELFID_AUDIT_EVIDENCE.sarif.json", "utf8"));
  const csvLines = fs.readFileSync("STELFID_AUDIT_EVIDENCE.csv", "utf8").trim().split(/\r?\n/);
  const mdText = fs.readFileSync("STELFID_AUDIT_EVIDENCE.md", "utf8");

  // 1. Verificar Punto B: Separacion OWASP API9 (Inventario) vs API2 (Autenticacion)
  const publicActiveRoute = jsonReport.endpoints.find(e => e.fullRoute === "/api/users" && e.method === "GET");
  const candidateRoutes = jsonReport.endpoints.filter(e => e.state === "CANDIDATE_FOR_MANUAL_REVIEW");
  const checkB_OwaspSeparation =
    publicActiveRoute.owaspLifecycleTag === "INVENTORY_ACTIVE" &&
    publicActiveRoute.owaspAuthNote.includes("OWASP API2:2023") &&
    candidateRoutes.length === 2 &&
    candidateRoutes.every(r => r.owaspLifecycleTag === "OWASP_API9_RETIREMENT_CANDIDATE" && r.owaspAuthNote.includes("OWASP API2:2023"));

  // 2. Verificar Punto D: Evidencia temporal real de la Shadow API (19 hits HTTP 200 en 3 nodos, span > 27 dias, 0 rutas filtradas)
  const shadow = jsonReport.shadowApis[0];
  const shadowNodeCallsSum = Object.values(shadow.nodeBreakdown).reduce((a, b) => a + b.calls, 0);
  const checkD_ShadowTemporalEvidence =
    jsonReport.shadowApis.length === 1 &&
    shadow.calls === 19 &&
    shadowNodeCallsSum === 19 &&
    shadow.observedNodesCount === 3 &&
    shadow.firstSeenAt === node1First &&
    shadow.lastSeenAt === node3Last &&
    shadow.observedSpanDays >= 27.0 &&
    !JSON.stringify(shadow).includes("prometheus-hidden-metrics");

  // 3. Verificar seguridad de retiro: Observe-Only (@stelfid-deprecated) tiene canAutoPrune === false
  const observeOnlyRoute = jsonReport.endpoints.find(e => e.state === "STAGE_DEPRECATED");
  const keepExemptRoute = jsonReport.endpoints.find(e => e.state === "EXEMPT_KEEP");
  const checkSafety_ObserveOnlyProtected =
    observeOnlyRoute.canAutoPrune === false &&
    keepExemptRoute.canAutoPrune === false &&
    observeOnlyRoute.autoPruneBlockers.length > 0;

  // 4. Verificar consistencia de conteos en JSON, MD, CSV y SARIF + recalculo criptografico SHA-256
  const csvStaticCount = csvLines.slice(1).filter(l => l.startsWith("STATIC_ENDPOINT,")).length;
  const csvShadowCount = csvLines.slice(1).filter(l => l.startsWith("SHADOW_API,")).length;
  const sarifSummary = sarifReport.properties.summary;
  const recomputedSha256 = crypto
    .createHash("sha256")
    .update(JSON.stringify(jsonReport.canonicalIntegrityPayload), "utf8")
    .digest("hex");

  const checkConsistencyAndHash =
    jsonReport.summary.totalEndpointsScanned === 6 &&
    csvStaticCount === 6 &&
    csvShadowCount === 1 &&
    JSON.stringify(jsonReport.summary) === JSON.stringify(sarifSummary) &&
    recomputedSha256 === jsonReport.integritySha256 &&
    sarifReport.properties.integritySha256 === jsonReport.integritySha256 &&
    mdText.includes(jsonReport.integritySha256) &&
    jsonReport.integrityVerification.trustBoundaryNotice.includes("does NOT prove creator identity");

  // 5. Verificar ejecucion real de --prune sobre un sandbox temporal del codigo fuente:
  //    - Debe comentar POST /api/users y GET /api/legacy/export-v1 (Eligible for Safe-Prune)
  //    - NO debe tocar GET /api/users ni GET /api/users/:id (ACTIVE)
  //    - NO debe tocar POST /api/v2/billing/annual-tax-webhook (@stelfid-keep)
  //    - NO debe tocar GET /api/v2/billing/invoices-legacy-xml (Observe-Only @stelfid-deprecated)
  const sandboxDir = path.join(process.cwd(), '.stelfid-prune-sandbox');
  if (fs.existsSync(sandboxDir)) fs.rmSync(sandboxDir, { recursive: true, force: true });
  fs.cpSync(path.join(process.cwd(), 'apps', 'test-service'), sandboxDir, { recursive: true });

  execFileSync(
    process.execPath,
    [
      path.join(process.cwd(), 'packages', 'cli', 'dist', 'index.js'),
      '--dir', sandboxDir,
      '--min-days', '14',
      '--min-nodes', '3',
      '--prune'
    ],
    { stdio: 'pipe' }
  );

  const sandboxAppTs = fs.readFileSync(path.join(sandboxDir, 'src', 'app.ts'), 'utf8');
  const sandboxBillingTs = fs.readFileSync(path.join(sandboxDir, 'src', 'routes', 'billing.ts'), 'utf8');

  const prunedPostUsers = sandboxAppTs.includes('[Maiestor Stelfid Controlled-Retirement: POST /api/users');
  const prunedLegacyExport = sandboxAppTs.includes('[Maiestor Stelfid Controlled-Retirement: GET /api/legacy/export-v1');
  const untouchedActiveGetUsers = !sandboxAppTs.includes('[Maiestor Stelfid Controlled-Retirement: GET /api/users ');
  const untouchedBillingKeepAndObserveOnly = !sandboxBillingTs.includes('[Maiestor Stelfid Controlled-Retirement:');

  // Tambien probar que ni siquiera --force-prune toca @stelfid-keep ni @stelfid-deprecated (Observe-Only)
  execFileSync(
    process.execPath,
    [
      path.join(process.cwd(), 'packages', 'cli', 'dist', 'index.js'),
      '--dir', sandboxDir,
      '--force-prune'
    ],
    { stdio: 'pipe' }
  );
  const sandboxBillingAfterForce = fs.readFileSync(path.join(sandboxDir, 'src', 'routes', 'billing.ts'), 'utf8');
  const forcePruneStillProtectsObserveOnlyAndKeep = !sandboxBillingAfterForce.includes('[Maiestor Stelfid Controlled-Retirement:');

  fs.rmSync(sandboxDir, { recursive: true, force: true });

  const checkPruneExecution =
    prunedPostUsers &&
    prunedLegacyExport &&
    untouchedActiveGetUsers &&
    untouchedBillingKeepAndObserveOnly &&
    forcePruneStillProtectsObserveOnlyAndKeep;

  console.log("================================================================================");
  console.log(" VERIFICACION SEMANTICA DEL AUDITOR DE RETIRADAS (v1.7.0-rc.1)");
  console.log("================================================================================");
  console.log(" [PASS=" + checkB_OwaspSeparation + "] Punto B — Separacion OWASP API9 (Inventario) vs API2 (Auth Review)");
  console.log(" [PASS=" + checkD_ShadowTemporalEvidence + "] Punto D — Shadow API (19 hits en 3 nodos, Span=" + shadow.observedSpanDays + "d, First=" + shadow.firstSeenAt.slice(0,10) + " -> Last=" + shadow.lastSeenAt.slice(0,10) + ")");
  console.log(" [PASS=" + checkSafety_ObserveOnlyProtected + "] Retiro Seguro — Observe-Only (@deprecated) y @keep bloqueados ante Auto-Prune (canAutoPrune=false)");
  console.log(" [PASS=" + checkConsistencyAndHash + "] Consistencia 4 Formatos + SHA-256 Verificable (" + recomputedSha256.slice(0, 16) + "...)");
  console.log(" [PASS=" + checkPruneExecution + "] Ejecucion Real --prune / --force-prune en Sandbox (2 podadas, 0 falsos borrados en Observe-Only/@keep)");
  console.log("================================================================================\n");

  if (!checkB_OwaspSeparation || !checkD_ShadowTemporalEvidence || !checkSafety_ObserveOnlyProtected || !checkConsistencyAndHash || !checkPruneExecution) {
    process.exit(1);
  }
}

runAuditSemanticsVerification();