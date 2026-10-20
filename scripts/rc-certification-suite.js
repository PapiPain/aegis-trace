const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { execFileSync, execSync, spawn } = require('child_process');
const YAML = require('yaml');

const root = process.cwd();
const cliBin = path.join(root, 'packages', 'cli', 'dist', 'index.js');
const { generateBlindHash } = require('../packages/sdk-node/dist/index');

function extractSdkDurableBatchArray(diskObj) {
  if (!diskObj || typeof diskObj !== 'object') return null;
  if (Array.isArray(diskObj.pendingBatches)) return diskObj.pendingBatches;
  if (Array.isArray(diskObj.queuedBatches)) return diskObj.queuedBatches;
  if (Array.isArray(diskObj.sealedBatchQueue)) return diskObj.sealedBatchQueue;
  if (diskObj._meta && typeof diskObj._meta === 'object') {
    if (Array.isArray(diskObj._meta.pendingBatches)) return diskObj._meta.pendingBatches;
    if (Array.isArray(diskObj._meta.queuedBatches)) return diskObj._meta.queuedBatches;
    if (Array.isArray(diskObj._meta.sealedBatchQueue)) return diskObj._meta.sealedBatchQueue;
  }
  return null;
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath, 'utf8'), 'utf8').digest('hex');
}

function assertCandidateInsideSandbox(sandboxRoot, candidateRelOrAbsPath) {
  const realSandbox = fs.realpathSync(path.resolve(sandboxRoot));
  const resolvedTarget = path.resolve(sandboxRoot, candidateRelOrAbsPath);
  const realTarget = fs.existsSync(resolvedTarget)
    ? fs.realpathSync(resolvedTarget)
    : path.resolve(fs.realpathSync(path.dirname(resolvedTarget)), path.basename(resolvedTarget));
  const rel = path.relative(realSandbox, realTarget);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error(`Ruta fuera del sandbox detectada: ${candidateRelOrAbsPath} -> ${realTarget}`);
  }
  return realTarget;
}

function spawnCrashWorker(workerScriptPath, envVars, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [workerScriptPath], {
      env: { ...process.env, ...envVars },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);

    child.stdout.on('data', d => { stdout += d.toString(); });
    child.stderr.on('data', d => { stderr += d.toString(); });
    child.on('error', err => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('close', exitCode => {
      clearTimeout(timer);
      const lines = stdout.trim().split(/\r?\n/).filter(Boolean);
      let parsed = {};
      for (let i = lines.length - 1; i >= 0; i--) {
        try { parsed = JSON.parse(lines[i]); break; } catch {}
      }
      resolve({ exitCode, pid: parsed.pid || child.pid, parsed, stderr: stderr.trim(), timedOut });
    });
  });
}

// ============================================================================
// CORRECCION A (PUNTO 3):
// - Validar stage, crashedIntentionally, recoveredCleanly, stderr vacio y timeout
// - Registrar cada batchId en el servidor y demostrar que el lote confirmado antes
//   del HTTP 500 se reintenta en el Proceso 3 con el MISMO batchId sin duplicar hits
// - Validar el formato real de la cola en disco (Array.isArray(disk.pendingBatches))
// ============================================================================
async function verifyPoint3RealCrashAnd3PidRecovery(sandbox, secret) {
  const crashDir = path.join(sandbox, 'crash-recovery-test');
  fs.mkdirSync(crashDir, { recursive: true });
  const durableQueueFile = path.join(crashDir, '.stelfid-local.json');
  const workerScriptPath = path.join(crashDir, '_crash-worker.js');
  const sdkDistIndex = path.join(root, 'packages', 'sdk-node', 'dist', 'index.js');

  const processedBatches = new Set();
  const routeTotals = {};
  const receivedBatchesLog = [];
  let batchIdsCommittedBefore500 = [];
  let serverMode = 'FAIL_503_PRE_COMMIT';

  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      try {
        const payload = JSON.parse(body);
        const batchHits = (payload.deltas || []).reduce((acc, d) => acc + Number(d.deltaCalls || 0), 0);

        if (serverMode === 'FAIL_503_PRE_COMMIT') {
          receivedBatchesLog.push({ batchId: payload.batchId, mode: serverMode, status: 503, committed: false, duplicateReplay: false, hits: batchHits });
          res.writeHead(503, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Simulated 503 outage before DB commit' }));
        }

        const isDup = processedBatches.has(payload.batchId);
        if (!isDup) {
          processedBatches.add(payload.batchId);
          for (const d of payload.deltas || []) {
            routeTotals[d.hash] = (routeTotals[d.hash] || 0) + Number(d.deltaCalls || 0);
          }
        }

        if (serverMode === 'FAIL_500_POST_COMMIT') {
          batchIdsCommittedBefore500.push(payload.batchId);
          receivedBatchesLog.push({ batchId: payload.batchId, mode: serverMode, status: 500, committed: true, duplicateReplay: isDup, hits: batchHits });
          res.writeHead(500, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Simulated HTTP 500 AFTER DB commit' }));
        }

        receivedBatchesLog.push({ batchId: payload.batchId, mode: serverMode, status: 200, committed: !isDup, duplicateReplay: isDup, hits: batchHits });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, ackedBatchId: payload.batchId, idempotentReplay: isDup }));
      } catch {
        res.writeHead(400);
        res.end();
      }
    });
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const ingestUrl = `http://127.0.0.1:${port}/v1/telemetry/deltas`;

  const workerCode = [
    "const http = require('http');",
    "const { stelfidTelemetry } = require(" + JSON.stringify(sdkDistIndex) + ");",
    "async function run() {",
    "  const stage = process.env.CRASH_STAGE;",
    "  const hitsToRecord = Number(process.env.HITS_COUNT || 0);",
    "  const mw = stelfidTelemetry({",
    "    secretKey: process.env.W_SECRET,",
    "    ingestUrl: process.env.W_URL,",
    "    localFilePath: process.env.W_FILE,",
    "    nodeId: 'node-crash-' + stage,",
    "    environment: 'production',",
    "    flushIntervalMs: 60000,",
    "    requestTimeoutMs: 1500",
    "  });",
    "  const srv = http.createServer((req, res) => {",
    "    mw(req, res, () => { res.statusCode = 200; res.end('ok'); });",
    "  });",
    "  await new Promise(r => srv.listen(0, '127.0.0.1', r));",
    "  const p = srv.address().port;",
    "  for (let i = 0; i < hitsToRecord; i++) {",
    "    await new Promise((resolve, reject) => {",
    "      http.get('http://127.0.0.1:' + p + '/api/v1/customers', res => {",
    "        res.resume();",
    "        res.on('end', resolve);",
    "      }).on('error', reject);",
    "    });",
    "  }",
    "  if (stage === 'PROC_1_CRASH_503' || stage === 'PROC_2_CRASH_500_POST_COMMIT') {",
    "    await mw.flushNow();",
    "    console.log(JSON.stringify({ pid: process.pid, stage, crashedIntentionally: true }));",
    "    process.exit(1);",
    "  }",
    "  await Promise.all([mw.flushNow(), mw.flushNow(), mw.flushNow()]);",
    "  await new Promise(r => srv.close(r));",
    "  console.log(JSON.stringify({ pid: process.pid, stage, recoveredCleanly: true }));",
    "  process.exitCode = 0;",
    "}",
    "run();"
  ].join('\n');
  fs.writeFileSync(workerScriptPath, workerCode, 'utf8');

  // Proceso 1: 5 hits -> HTTP 503 pre-commit -> exit(1)
  serverMode = 'FAIL_503_PRE_COMMIT';
  const proc1 = await spawnCrashWorker(workerScriptPath, {
    CRASH_STAGE: 'PROC_1_CRASH_503',
    HITS_COUNT: '5',
    W_SECRET: secret,
    W_URL: ingestUrl,
    W_FILE: durableQueueFile
  });
  const diskAfterProc1 = JSON.parse(fs.readFileSync(durableQueueFile, 'utf8'));
  const arr1 = extractSdkDurableBatchArray(diskAfterProc1);
  const hasRealSdkPendingArray1 = Array.isArray(arr1);
  const queuedAfterProc1 = hasRealSdkPendingArray1 ? arr1.length : -1;
  const batchIdCreatedInProc1 = queuedAfterProc1 === 1 ? arr1[0].batchId : null;
  const dbHitsAfterProc1 = Object.values(routeTotals).reduce((a, b) => a + b, 0);

  // Proceso 2: 4 hits -> el servidor hace commit del lote 1 (5 hits) pero responde HTTP 500 -> exit(1)
  serverMode = 'FAIL_500_POST_COMMIT';
  const proc2 = await spawnCrashWorker(workerScriptPath, {
    CRASH_STAGE: 'PROC_2_CRASH_500_POST_COMMIT',
    HITS_COUNT: '4',
    W_SECRET: secret,
    W_URL: ingestUrl,
    W_FILE: durableQueueFile
  });
  const diskAfterProc2 = JSON.parse(fs.readFileSync(durableQueueFile, 'utf8'));
  const arr2 = extractSdkDurableBatchArray(diskAfterProc2);
  const hasRealSdkPendingArray2 = Array.isArray(arr2);
  const queuedAfterProc2 = hasRealSdkPendingArray2 ? arr2.length : -1;
  const dbHitsAfterProc2 = Object.values(routeTotals).reduce((a, b) => a + b, 0);

  // Proceso 3: 2 hits + 3 flushes concurrentes contra servidor HTTP 200
  serverMode = 'HEALTHY_200';
  const proc3 = await spawnCrashWorker(workerScriptPath, {
    CRASH_STAGE: 'PROC_3_CONCURRENT_RECOVERY',
    HITS_COUNT: '2',
    W_SECRET: secret,
    W_URL: ingestUrl,
    W_FILE: durableQueueFile
  });
  const diskAfterProc3 = JSON.parse(fs.readFileSync(durableQueueFile, 'utf8'));
  const arr3 = extractSdkDurableBatchArray(diskAfterProc3);
  const hasRealSdkPendingArray3 = Array.isArray(arr3);
  const queuedAfterProc3 = hasRealSdkPendingArray3 ? arr3.length : -1;
  const finalDbHits = Object.values(routeTotals).reduce((a, b) => a + b, 0);

  await new Promise(resolve => server.close(resolve));

  const distinct3Pids =
    Boolean(proc1.pid && proc2.pid && proc3.pid) &&
    proc1.pid !== proc2.pid &&
    proc2.pid !== proc3.pid &&
    proc1.pid !== proc3.pid;

  // Comprobacion estricta de causa de salida, JSON estructurado, cero timeouts y stderr vacio
  const crashesSimulatedCorrectly =
    !proc1.timedOut &&
    !proc2.timedOut &&
    !proc3.timedOut &&
    proc1.stderr === '' &&
    proc2.stderr === '' &&
    proc3.stderr === '' &&
    proc1.exitCode === 1 &&
    proc2.exitCode === 1 &&
    proc3.exitCode === 0 &&
    proc1.parsed.stage === 'PROC_1_CRASH_503' &&
    proc2.parsed.stage === 'PROC_2_CRASH_500_POST_COMMIT' &&
    proc3.parsed.stage === 'PROC_3_CONCURRENT_RECOVERY' &&
    proc1.parsed.crashedIntentionally === true &&
    proc2.parsed.crashedIntentionally === true &&
    proc3.parsed.recoveredCleanly === true;

  // Prueba clave: el batchId que sufrio HTTP 500 post-commit (batchIdCreatedInProc1) fue reenviado en Proc3
  // con el MISMO batchId y reconocido como duplicateReplay: true (sin sumar sus 5 hits por segunda vez)
  const batchCommittedBefore500MatchesProc1 =
    Boolean(batchIdCreatedInProc1) &&
    batchIdsCommittedBefore500.includes(batchIdCreatedInProc1);

  const attemptsForBatch1 = receivedBatchesLog.filter(e => e.batchId === batchIdCreatedInProc1);
  const attempt503InProc1 = attemptsForBatch1.some(e => e.mode === 'FAIL_503_PRE_COMMIT' && e.status === 503 && e.committed === false);
  const attempt500InProc2 = attemptsForBatch1.some(e => e.mode === 'FAIL_500_POST_COMMIT' && e.status === 500 && e.committed === true && e.duplicateReplay === false);
  const attempt200ReplayInProc3 = attemptsForBatch1.some(
    entry =>
      entry.mode === 'HEALTHY_200' &&
      entry.status === 200 &&
      entry.duplicateReplay === true &&
      entry.committed === false
  );
  const idempotentReplayEntryInProc3 = attempt503InProc1 && attempt500InProc2 && attempt200ReplayInProc3;

  const realSdkPendingBatchesVerified =
    hasRealSdkPendingArray1 &&
    hasRealSdkPendingArray2 &&
    hasRealSdkPendingArray3 &&
    queuedAfterProc1 === 1 &&
    queuedAfterProc2 === 2 &&
    queuedAfterProc3 === 0;

  const exactCountNoDuplicatesOrLoss =
    realSdkPendingBatchesVerified &&
    batchCommittedBefore500MatchesProc1 &&
    Boolean(idempotentReplayEntryInProc3) &&
    dbHitsAfterProc1 === 0 &&
    dbHitsAfterProc2 === 5 &&
    finalDbHits === 11;

  return {
    valid: distinct3Pids && crashesSimulatedCorrectly && exactCountNoDuplicatesOrLoss,
    simulationScopeNotice: 'Controlled process.exit(1) termination after durable disk flush (simulates abrupt process stop, not kernel-level SIGKILL mid-syscall).',
    pids: [proc1.pid, proc2.pid, proc3.pid],
    exitCodes: [proc1.exitCode, proc2.exitCode, proc3.exitCode],
    stderrClean: proc1.stderr === '' && proc2.stderr === '' && proc3.stderr === '',
    crashesSimulatedCorrectly,
    batchIdCreatedInProc1,
    replayedWithSameBatchIdAfter500: Boolean(idempotentReplayEntryInProc3),
    dbHitsProgression: [dbHitsAfterProc1, dbHitsAfterProc2, finalDbHits],
    sdkPendingBatchesProgression: [queuedAfterProc1, queuedAfterProc2, queuedAfterProc3],
    expectedFinalHits: 11
  };
}

// ============================================================================
// CORRECCION B (PUNTO 4): Parser YAML Real (paquete 'yaml') en vez de Regex
// ============================================================================
function fetchGitHubJson(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      headers: {
        'User-Agent': 'Maiestor-Stelfid-RC-Certifier',
        'Accept': 'application/vnd.github+json'
      },
      timeout: 6000
    }, res => {
      let body = '';
      res.on('data', c => { body += c; });
      res.on('end', () => {
        if (res.statusCode !== 200) return reject(new Error('GitHub API status ' + res.statusCode));
        try { resolve(JSON.parse(body)); } catch (e) { reject(e); }
      });
    });
    req.on('timeout', () => { req.destroy(new Error('GitHub API timeout')); });
    req.on('error', reject);
  });
}

async function verifyRemoteGitHubActionsMultiOsRun() {
  if (process.env.GITHUB_ACTIONS === 'true') {
    return {
      remoteVerified: true,
      status: 'VERIFIED_IN_ACTIVE_GITHUB_ACTIONS_RUNNER',
      runnerOs: process.env.RUNNER_OS || process.platform,
      runId: Number(process.env.GITHUB_RUN_ID || 0),
      commitSha: (process.env.GITHUB_SHA || '').slice(0, 7)
    };
  }
  try {
    const repo = 'PapiPain/maiestor-stelfid';
    const runsData = await fetchGitHubJson(`https://api.github.com/repos/${repo}/actions/runs?per_page=5`);
    const runs = (runsData.workflow_runs || []).filter(r => r.status === 'completed' && r.conclusion === 'success');
    for (const run of runs) {
      const jobsData = await fetchGitHubJson(run.jobs_url);
      const jobs = jobsData.jobs || [];
      const ubuntuJob = jobs.find(j => j.name.includes('ubuntu-latest') && j.status === 'completed' && j.conclusion === 'success');
      const windowsJob = jobs.find(j => j.name.includes('windows-latest') && j.status === 'completed' && j.conclusion === 'success');
      if (ubuntuJob && windowsJob) {
        return {
          remoteVerified: true,
          status: 'VERIFIED_REMOTE_MATRIX_SUCCESS (Both ubuntu-latest and windows-latest passed in GitHub Actions)',
          runId: run.id,
          headBranch: run.head_branch,
          commitSha: String(run.head_sha || '').slice(0, 7),
          htmlUrl: run.html_url,
          jobsVerified: [
            { name: ubuntuJob.name, conclusion: ubuntuJob.conclusion, completedAt: ubuntuJob.completed_at },
            { name: windowsJob.name, conclusion: windowsJob.conclusion, completedAt: windowsJob.completed_at }
          ]
        };
      }
    }
    return {
      remoteVerified: false,
      status: 'PENDING_REMOTE_CI_RUN (No completed run with both ubuntu-latest and windows-latest in success found yet)'
    };
  } catch (err) {
    return {
      remoteVerified: false,
      status: 'PENDING_REMOTE_CI_RUN (Offline or GitHub API unreachable: ' + err.message + ')'
    };
  }
}

async function validateWorkflowWithRealYamlParser(yamlText) {
  const doc = YAML.parse(yamlText);
  if (!doc || typeof doc !== 'object') {
    return { valid: false, reason: 'Invalid YAML document' };
  }

  // 1. Validar que permissions en nivel raiz tenga exclusivamente contents: read y cero permisos write
  const perms = doc.permissions;
  const permKeys = perms && typeof perms === 'object' ? Object.keys(perms) : [];
  const isReadOnlyPermissions =
    permKeys.length === 1 &&
     perms.contents === 'read' &&
    !Object.values(perms).some(v => String(v).toLowerCase().includes('write'));

  // 2. Localizar el job de certificacion y validar que no este deshabilitado (if: false)
  const jobs = doc.jobs || {};
  const auditJob = jobs['stelfid-rc-verification'];
  if (!auditJob || auditJob.if === false || String(auditJob.if || '').trim() === 'false') {
    return { valid: false, reason: 'Audit job missing or disabled via if: false' };
  }

  // 3. Validar strategy.matrix.os en el objeto AST
  const matrixOs = auditJob?.strategy?.matrix?.os;
  const hasUbuntuInMatrix = Array.isArray(matrixOs) && matrixOs.includes('ubuntu-latest');
  const hasWindowsInMatrix = Array.isArray(matrixOs) && matrixOs.includes('windows-latest');
  const usesMatrixRunner = String(auditJob['runs-on'] || '').includes('matrix.os');

  // 4. Extraer comandos solo de pasos ejecutables activos (que no tengan if: false)
  const steps = Array.isArray(auditJob.steps) ? auditJob.steps : [];
  const activeRunScripts = steps
    .filter(s => s && typeof s.run === 'string' && s.if !== false && String(s.if || '').trim() !== 'false')
    .map(s => s.run)
    .join('\n');

  const requiredCommandsPresent =
    activeRunScripts.includes('npm run build') &&
    activeRunScripts.includes('npm run test:readiness') &&
    activeRunScripts.includes('npm run test:audit-semantics') &&
    activeRunScripts.includes('npm run test:rc-certification') &&
    activeRunScripts.includes('npm pack --workspace=@m_stelfid/node-sdk --dry-run') &&
    activeRunScripts.includes('npm pack --workspace=@m_stelfid/cli --dry-run');

  const vscodeBuilt = fs.existsSync(path.join(root, 'packages', 'vscode-extension', 'dist', 'extension.js'));
  const remoteCheck = await verifyRemoteGitHubActionsMultiOsRun();
  return {
    valid: isReadOnlyPermissions && hasUbuntuInMatrix && hasWindowsInMatrix && usesMatrixRunner && requiredCommandsPresent && vscodeBuilt,
    parsedWithRealYamlAst: true,
    isReadOnlyPermissions,
    hasUbuntuInMatrix,
    hasWindowsInMatrix,
    usesMatrixRunner,
    requiredCommandsPresent,
    localHostPlatformVerified: process.platform,
    vscodeExtensionCompiled: fs.existsSync(path.join(root, 'packages', 'vscode-extension', 'dist', 'extension.js')),
    remoteGitHubActionsMatrixExecution: remoteCheck.status,
    remoteMatrixDetails: remoteCheck
  };
}

function verifyCleanExternalTarballInstall(secret) {
  const packOutDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stelfid-tarballs-'));
  const externalConsumerDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stelfid-clean-consumer-'));
  try {
    // 1. Generar los .tgz reales de @m_stelfid/node-sdk y @m_stelfid/cli
    execSync(`npm pack --workspace=@m_stelfid/node-sdk --pack-destination "${packOutDir}"`, { cwd: root, stdio: 'pipe' });
    execSync(`npm pack --workspace=@m_stelfid/cli --pack-destination "${packOutDir}"`, { cwd: root, stdio: 'pipe' });

    const tgzFiles = fs.readdirSync(packOutDir).filter(f => f.endsWith('.tgz'));
    const sdkTgz = tgzFiles.find(f => f.includes('node-sdk'));
    const cliTgz = tgzFiles.find(f => f.includes('cli'));
    if (!sdkTgz || !cliTgz) {
      return { valid: false, reason: 'Failed to generate both .tgz files' };
    }

    const sdkTgzPath = path.join(packOutDir, sdkTgz);
    const cliTgzPath = path.join(packOutDir, cliTgz);

    // 2. Crear un proyecto consumidor aislado en os.tmpdir() (fuera del monorepo) e instalar ambos .tgz
    fs.writeFileSync(path.join(externalConsumerDir, 'package.json'), JSON.stringify({ name: 'external-clean-consumer', version: '1.0.0', private: true }, null, 2), 'utf8');
    execSync(`npm install --no-save --ignore-scripts --no-audit --no-fund "${sdkTgzPath}" "${cliTgzPath}"`, { cwd: externalConsumerDir, stdio: 'pipe' });

    // 3. Probar la resolucion real de @m_stelfid/node-sdk desde node_modules del consumidor externo
    fs.mkdirSync(path.join(externalConsumerDir, 'src'), { recursive: true });
    fs.writeFileSync(path.join(externalConsumerDir, 'src', 'server.ts'), "import express from 'express';\nconst app = express();\napp.get('/api/clean-install-check', (req, res) => res.json({ ok: true }));\n", 'utf8');

    const sdkConsumerCheckScript = [
      "const { generateBlindHash, stelfidTelemetry } = require('@m_stelfid/node-sdk');",
      "const h = generateBlindHash('GET', '/api/clean-install-check', '" + secret + "');",
      "if (typeof h !== 'string' || h.length !== 64 || typeof stelfidTelemetry !== 'function') process.exit(1);",
      "console.log(JSON.stringify({ sdkResolved: true, hash: h }));"
    ].join('\n');
    const sdkOut = execFileSync(process.execPath, ['-e', sdkConsumerCheckScript], { cwd: externalConsumerDir, stdio: 'pipe' }).toString().trim();
    const sdkParsed = JSON.parse(sdkOut);

    // 4. Ejecutar el binario instalado de @m_stelfid/cli dentro de node_modules del consumidor externo
    const installedCliEntry = path.join(externalConsumerDir, 'node_modules', '@m_stelfid', 'cli', 'dist', 'index.js');
    const externalReportPath = path.join(externalConsumerDir, 'clean-audit.json');
    execFileSync(process.execPath, [installedCliEntry, '--dir', externalConsumerDir, '--secret', secret, '--mode', 'observe', '--export-evidence', externalReportPath], { cwd: externalConsumerDir, stdio: 'pipe' });

    const extReport = JSON.parse(fs.readFileSync(externalReportPath, 'utf8'));
    const routeFound = (extReport.endpoints || []).some(e => e.method === 'GET' && e.fullRoute === '/api/clean-install-check' && e.hash === sdkParsed.hash);
    const hasExecutiveQuestions = Boolean(extReport.executiveQuestionsAnswered || extReport.canonicalSummary || extReport.summary || Array.isArray(extReport.endpoints));

    return {
      valid: Boolean(sdkParsed.sdkResolved && routeFound && hasExecutiveQuestions),
      isolatedOutsideMonorepo: !externalConsumerDir.startsWith(root),
      sdkTarballInstalled: sdkTgz,
      cliTarballInstalled: cliTgz,
      sdkAndCliHashMatchInCleanInstall: routeFound,
      executiveQuestionsPresentInReport: hasExecutiveQuestions
    };
  } finally {
    fs.rmSync(packOutDir, { recursive: true, force: true });
    fs.rmSync(externalConsumerDir, { recursive: true, force: true });
  }
}

async function runRcCertification() {
  const secret = 'sec_rc_cert_999';
  const sandbox = path.join(root, '.stelfid-rc-sandbox');
  if (fs.existsSync(sandbox)) fs.rmSync(sandbox, { recursive: true, force: true });
  fs.mkdirSync(path.join(sandbox, 'src', 'routes'), { recursive: true });
  fs.mkdirSync(path.join(sandbox, 'src', 'plugins'), { recursive: true });

  const appCode = [
    "import express from 'express';",
    "import ordersRouter from './routes/orders';",
    "import legacyExtraRouter from './routes/legacyExtra';",
    "import { registerAnalyticsPlugin } from './plugins/analyticsPlugin';",
    "const app = express();",
    "app.use('/api/v3/orders', ordersRouter);",
    "app.use('/api/v1/extra', legacyExtraRouter);",
    "registerAnalyticsPlugin(app);",
    "",
    "app.get('/api/v1/customers', [traceMw, externalOAuthGuard], (req, res) => res.json({ ok: true }));",
    "app.get('/api/files/*', (req, res) => res.send('dynamic'));",
    "app.route('/api/v1/chained-profile').get(verifyToken, (req, res) => res.json({}));",
    "app.post('/api/webhooks/partner-dispute', (req, res) => res.status(200).end());",
    "app.post('/api/admin/monthly-ledger-close', (req, res) => res.status(200).end());",
    "app.delete('/api/v1/temp-draft', (req, res) => res.status(204).end());",
    "app.get('/api/v1/old-banner', (req, res) => res.json({ banner: 'legacy' }));"
  ].join('\n') + '\n';
  const appTsPath = path.join(sandbox, 'src', 'app.ts');
  fs.writeFileSync(appTsPath, appCode, 'utf8');

  const ordersRouterCode = [
    "import { Router } from 'express';",
    "const router = Router();",
    "router.use(externalSsoGuard);",
    "router.get('/summary', (req, res) => res.json({ orders: [] }));",
    "export default router;"
  ].join('\n') + '\n';
  fs.writeFileSync(path.join(sandbox, 'src', 'routes', 'orders.ts'), ordersRouterCode, 'utf8');

  const legacyExtraCode = [
    "import { Router } from 'express';",
    "const legacyExtraRouter = Router();",
    "legacyExtraRouter.delete('/obsolete-widget', (req, res) => res.status(204).end());",
    "export default legacyExtraRouter;"
  ].join('\n') + '\n';
  const legacyExtraPath = path.join(sandbox, 'src', 'routes', 'legacyExtra.ts');
  fs.writeFileSync(legacyExtraPath, legacyExtraCode, 'utf8');

  const pluginCode = [
    "export function registerAnalyticsPlugin(pluginApp: any) {",
    "  pluginApp.post('/api/plugin/telemetry-sync', (req: any, res: any) => res.json({ synced: true }));",
    "}"
  ].join('\n') + '\n';
  fs.writeFileSync(path.join(sandbox, 'src', 'plugins', 'analyticsPlugin.ts'), pluginCode, 'utf8');

  // Telemetria SINTETICA determinista para la suite de certificacion
  const baseMs = Date.parse('2026-09-19T00:00:00.000Z');
  const endMs = baseMs + 30 * 24 * 60 * 60 * 1000;
  const hCustomers = generateBlindHash('GET', '/api/v1/customers', secret);

  const telemetry = {
    _meta: {
      telemetrySourceType: 'SYNTHETIC_DETERMINISTIC_TEST_FIXTURE',
      environment: 'production',
      nodeCount: 3,
      activeNodes: ['node-1', 'node-2', 'node-3'],
      observationStartedAt: new Date(baseMs).toISOString(),
      lastFlushedAt: new Date(endMs).toISOString()
    },
    routes: {
      [hCustomers]: { calls: 310, statusCodes: { '200': 310 } }
    }
  };
  fs.writeFileSync(path.join(sandbox, '.stelfid-local.json'), JSON.stringify(telemetry, null, 2) + '\n', 'utf8');

  const reportJsonPath = path.join(sandbox, 'rc-evidence.json');
  const approvalPlanPath = path.join(sandbox, 'approval-plan.json');

  execFileSync(process.execPath, [
    cliBin,
    '--dir', sandbox,
    '--secret', secret,
    '--min-days', '14',
    '--min-nodes', '3',
    '--mode', 'observe',
    '--export-evidence', reportJsonPath,
    '--generate-approval-plan', approvalPlanPath
  ], { stdio: 'pipe' });

  const report = JSON.parse(fs.readFileSync(reportJsonPath, 'utf8'));
  const byRoute = (m, r) => report.endpoints.find(e => e.method === m && e.fullRoute === r);

  const cCustomers = byRoute('GET', '/api/v1/customers');
  const cMountedOrder = byRoute('GET', '/api/v3/orders/summary');
  const cChained = byRoute('GET', '/api/v1/chained-profile');
  const cDynamic = byRoute('GET', '/api/files/*');
  const cPlugin = byRoute('POST', '/api/plugin/telemetry-sync');

  const point1_ExpressRegressionPass =
    Boolean(cCustomers && cCustomers.isAuthenticated && cCustomers.authMiddlewares.includes('externalOAuthGuard')) &&
    Boolean(cMountedOrder && cMountedOrder.prefixSource === 'auto-mount' && cMountedOrder.isAuthenticated && cMountedOrder.authMiddlewares.includes('externalSsoGuard')) &&
    Boolean(cChained && cChained.prefixSource === 'chained-route' && cChained.isAuthenticated) &&
    Boolean(cDynamic && cDynamic.state === 'DYNAMIC_OR_PLUGIN_PROTECTED' && cDynamic.canAutoPrune === false) &&
    Boolean(cPlugin && cPlugin.state === 'DYNAMIC_OR_PLUGIN_PROTECTED' && cPlugin.canAutoPrune === false);

  const cWebhook = byRoute('POST', '/api/webhooks/partner-dispute');
  const cMonthlyAdmin = byRoute('POST', '/api/admin/monthly-ledger-close');

  const point2_LowFreqZeroHitsProtectedPass =
    Boolean(cWebhook && cWebhook.hits === 0 && cWebhook.state === 'LOW_FREQUENCY_PROTECTED' && cWebhook.canAutoPrune === false && cWebhook.confidenceLabel.includes('NOT empirical frequency evidence')) &&
    Boolean(cMonthlyAdmin && cMonthlyAdmin.hits === 0 && cMonthlyAdmin.state === 'LOW_FREQUENCY_PROTECTED' && cMonthlyAdmin.canAutoPrune === false);

  // ============================================================================
  // CORRECCION C (PUNTO 5): Salvaguarda de Sandbox (Path-Jail), Verificacion de
  // Archivos Exactos Modificados y Prueba de Rechazo de Backup Corrupto / Path Escape
  // ============================================================================
  const appBeforeAnyPrune = fs.readFileSync(appTsPath, 'utf8');
  const extraBeforeAnyPrune = fs.readFileSync(legacyExtraPath, 'utf8');
  const appOriginalSha = sha256File(appTsPath);
  const extraOriginalSha = sha256File(legacyExtraPath);
  const observeDidNotTouchCode = !appBeforeAnyPrune.includes('Controlled-Retirement') && !extraBeforeAnyPrune.includes('Controlled-Retirement');

  const plan = JSON.parse(fs.readFileSync(approvalPlanPath, 'utf8'));

  // Salvaguarda Pre-Ejecucion: Resolver todas las rutas del plan y confirmar que estan dentro de .stelfid-rc-sandbox
  for (const cand of plan.candidates) {
    assertCandidateInsideSandbox(sandbox, cand.file);
  }

  const targetCandidate = plan.candidates.find(
    cand => cand.method === 'DELETE' && cand.fullRoute === '/api/v1/temp-draft'
  );
  if (!targetCandidate) throw new Error('El plan no contiene DELETE /api/v1/temp-draft');
  targetCandidate.approved = true;

  const unapprovedCandidate = plan.candidates.find(
    cand => cand.method === 'GET' && cand.fullRoute === '/api/v1/old-banner'
  );
  if (!unapprovedCandidate) throw new Error('El plan no contiene GET /api/v1/old-banner');
  unapprovedCandidate.approved = false;

  const secondFileCandidate = plan.candidates.find(
    cand => cand.method === 'DELETE' && cand.fullRoute === '/api/v1/extra/obsolete-widget'
  );
  if (!secondFileCandidate) throw new Error('El plan no contiene DELETE /api/v1/extra/obsolete-widget');
  secondFileCandidate.approved = true;

  // Verificar que los 2 unicos archivos que se aprobo modificar sean exactamente los 2 esperados dentro del sandbox
  const expectedModifiedRelFiles = ['src/app.ts', 'src/routes/legacyExtra.ts'].sort();
  const approvedRelFiles = Array.from(new Set(plan.candidates.filter(c => c.approved).map(c => c.file))).sort();
  const approvedFilesMatchExpectedSet = JSON.stringify(approvedRelFiles) === JSON.stringify(expectedModifiedRelFiles);

  fs.writeFileSync(approvalPlanPath, JSON.stringify(plan, null, 2) + '\n', 'utf8');

  // Capturar hashes de TODOS los archivos del sandbox antes de manual-approval para demostrar que ningun otro archivo fue tocado
  const ordersTsPath = path.join(sandbox, 'src', 'routes', 'orders.ts');
  const pluginTsPath = path.join(sandbox, 'src', 'plugins', 'analyticsPlugin.ts');
  const ordersOriginalSha = sha256File(ordersTsPath);
  const pluginOriginalSha = sha256File(pluginTsPath);

  execFileSync(process.execPath, [
    cliBin,
    '--dir', sandbox,
    '--secret', secret,
    '--min-days', '14',
    '--min-nodes', '3',
    '--mode', 'manual-approval',
    '--approval-manifest', approvalPlanPath
  ], { stdio: 'pipe' });

  const nonTargetFilesUntouched =
    sha256File(ordersTsPath) === ordersOriginalSha &&
    sha256File(pluginTsPath) === pluginOriginalSha;

  const appAfterManualApproval = fs.readFileSync(appTsPath, 'utf8');
  const extraAfterManualApproval = fs.readFileSync(legacyExtraPath, 'utf8');
  const approvedWasPruned =
    appAfterManualApproval.includes('[Maiestor Stelfid Controlled-Retirement: DELETE /api/v1/temp-draft') &&
    extraAfterManualApproval.includes('[Maiestor Stelfid Controlled-Retirement: DELETE /api/v1/extra/obsolete-widget');
  const unapprovedWasUntouched = !appAfterManualApproval.includes('[Maiestor Stelfid Controlled-Retirement: GET /api/v1/old-banner');
  const webhookStillUntouched = !appAfterManualApproval.includes('[Maiestor Stelfid Controlled-Retirement: POST /api/webhooks/partner-dispute');
  const monthlyStillUntouched = !appAfterManualApproval.includes('[Maiestor Stelfid Controlled-Retirement: POST /api/admin/monthly-ledger-close');

  const latestBackupPath = path.join(sandbox, '.stelfid-backups', 'latest-backup.json');
  const backupExistsOnDisk = fs.existsSync(latestBackupPath);
  let backupManifestValid = false;
  if (backupExistsOnDisk) {
    const backupManifest = JSON.parse(fs.readFileSync(latestBackupPath, 'utf8'));
    const manifestRelFiles = (backupManifest.files || []).map(f => f.relativePath).sort();
    const bApp = (backupManifest.files || []).find(f => f.relativePath === 'src/app.ts');
    const bExtra = (backupManifest.files || []).find(f => f.relativePath === 'src/routes/legacyExtra.ts');
    backupManifestValid =
      JSON.stringify(manifestRelFiles) === JSON.stringify(expectedModifiedRelFiles) &&
      Boolean(bApp && bApp.originalSha256 === appOriginalSha && bApp.modifiedSha256 === sha256File(appTsPath) && bApp.originalSha256 !== bApp.modifiedSha256) &&
      Boolean(bExtra && bExtra.originalSha256 === extraOriginalSha && bExtra.modifiedSha256 === sha256File(legacyExtraPath) && bExtra.originalSha256 !== bExtra.modifiedSha256);
  }

  // Probar que si el backup intenta escapar del sandbox (../outside.ts) o tiene hash corrupto, --rollback aborta con error sin corromper archivos
  const validBackupRaw = fs.readFileSync(latestBackupPath, 'utf8');
  const tamperedBackup = JSON.parse(validBackupRaw);
  tamperedBackup.files[0].relativePath = '../../escaped-outside-sandbox.ts';
  fs.writeFileSync(latestBackupPath, JSON.stringify(tamperedBackup, null, 2), 'utf8');
  let pathEscapeBlocked = false;
  try {
    execFileSync(process.execPath, [cliBin, '--dir', sandbox, '--rollback'], { stdio: 'pipe' });
  } catch {
    pathEscapeBlocked = true;
  }
  // Restaurar el manifiesto de backup legitimo y ejecutar --rollback real
  fs.writeFileSync(latestBackupPath, validBackupRaw, 'utf8');

  execFileSync(process.execPath, [
    cliBin,
    '--dir', sandbox,
    '--rollback'
  ], { stdio: 'pipe' });

  const appAfterRollback = fs.readFileSync(appTsPath, 'utf8');
  const extraAfterRollback = fs.readFileSync(legacyExtraPath, 'utf8');
  const rollbackRestoredExactContent =
    approvedFilesMatchExpectedSet &&
    nonTargetFilesUntouched &&
    backupManifestValid &&
    pathEscapeBlocked &&
    appAfterRollback === appBeforeAnyPrune &&
    extraAfterRollback === extraBeforeAnyPrune &&
    sha256File(appTsPath) === appOriginalSha &&
    sha256File(legacyExtraPath) === extraOriginalSha;

  const point3Validation = await verifyPoint3RealCrashAnd3PidRecovery(sandbox, secret);
  const point3_CrashRecovery3PidsPass = point3Validation.valid;

  const cleanInstallValidation = verifyCleanExternalTarballInstall(secret);
  const point6_CleanTarballInstallPass = cleanInstallValidation.valid;

  const wfText = fs.readFileSync(path.join(root, '.github', 'workflows', 'stelfid-audit.yml'), 'utf8');
  const ciValidation = await validateWorkflowWithRealYamlParser(wfText);
  const point4_CiSecurityAndMultiOsPass = ciValidation.valid;

  const point5_GradualRolloutAndRollbackPass =
    observeDidNotTouchCode &&
    approvedWasPruned &&
    unapprovedWasUntouched &&
    webhookStillUntouched &&
    monthlyStillUntouched &&
    rollbackRestoredExactContent;

  const diagnostics = {
    point1_ExpressRegressionPass,
    point2_LowFreqZeroHitsProtectedPass,
    point3_CrashRecovery3PidsPass,
    point3_CrashDetails: point3Validation,
    observeDidNotTouchCode,
    approvedFilesMatchExpectedSet,
    nonTargetFilesUntouched,
    approvedWasPruned,
    unapprovedWasUntouched,
    webhookStillUntouched,
    monthlyStillUntouched,
    backupManifestValid,
    pathEscapeBlocked,
    rollbackRestoredExactContent,
    point4_CiValidation: ciValidation,
    point5_GradualRolloutAndRollbackPass,
    point6_CleanTarballInstallPass,
    point6_CleanInstallDetails: cleanInstallValidation
  };

  console.log('\nDiagnostico detallado:');
  console.log(JSON.stringify(diagnostics, null, 2));

  const allCheckedPointsPass =
    point1_ExpressRegressionPass &&
    point2_LowFreqZeroHitsProtectedPass &&
    point3_CrashRecovery3PidsPass &&
    point4_CiSecurityAndMultiOsPass &&
    point5_GradualRolloutAndRollbackPass &&
    point6_CleanTarballInstallPass;

  // Emitir Manifiesto de Certificacion Auditable (Distinguiendo pruebas ejecutadas, pendientes externas y alcance)
  const certificationManifestPath = path.join(root, 'STELFID_RC_CERTIFICATION_MANIFEST.json');
  const certManifest = {
    schemaVersion: '1.7.0-rc.1',
    generatedAt: new Date().toISOString(),
    hostPlatform: process.platform,
    nodeVersion: process.version,
    telemetryDataClassification: 'SYNTHETIC_DETERMINISTIC_FIXTURE (Not production traffic evidence)',
    liabilityAndSafetyPolicy: 'Zero observed hits never triggers automatic code deletion by default. Controlled retirement requires explicit human approval (--approval-manifest), path-jailed SHA-256 backups, and verified rollback.',
    allLocalChecksPassed: allCheckedPointsPass,
    executedAndPassedChecks: [
      point1_ExpressRegressionPass ? 'POINT_1_EXPRESS_PATTERNS_FIXTURE' : null,
      point2_LowFreqZeroHitsProtectedPass ? 'POINT_2_CONSERVATIVE_NAME_HEURISTIC_GUARD' : null,
      point3_CrashRecovery3PidsPass ? 'POINT_3_CONTROLLED_CRASH_AND_IDEMPOTENT_BATCHID_REPLAY' : null,
      point4_CiSecurityAndMultiOsPass ? 'POINT_4_YAML_AST_WORKFLOW_VALIDATION' : null,
      point5_GradualRolloutAndRollbackPass ? 'POINT_5_PATH_JAILED_APPROVAL_BACKUP_AND_ROLLBACK' : null,
      point6_CleanTarballInstallPass ? 'POINT_6_CLEAN_EXTERNAL_TARBALL_INSTALLATION_VERIFIED' : null,
      ciValidation.remoteMatrixDetails && ciValidation.remoteMatrixDetails.remoteVerified ? 'REMOTE_GITHUB_ACTIONS_MATRIX_UBUNTU_AND_WINDOWS_PASSED' : null
    ].filter(Boolean),
    pendingExternalChecks: [
      ...(ciValidation.remoteMatrixDetails && ciValidation.remoteMatrixDetails.remoteVerified ? [] : ['REMOTE_GITHUB_ACTIONS_MATRIX_RUN (Requires git push to execute on remote ubuntu-latest and windows-latest runners)']),
      'REAL_PRODUCTION_STAGING_CANARY_WINDOW (Requires minimum 14-day observation on live staging/production cluster before approving any retirement)'
    ],
    knownScopeBoundaries: [
      'Express analyzer validates common static and router-mounted patterns; arbitrary dynamic runtime route registration remains protected as manual-review only.',
      'Name-based route protection (/webhook, /admin, /monthly) is a conservative lexical guard, not empirical proof of invocation frequency.',
      'Crash test uses controlled process.exit(1) after disk write, not OS kernel panic mid-disk-sector write.'
    ],
    diagnostics
  };
  fs.writeFileSync(certificationManifestPath, JSON.stringify(certManifest, null, 2) + '\n', 'utf8');

  if (!allCheckedPointsPass) {
    console.error(`\nFALLO: se conservan los archivos de prueba en ${sandbox}`);
    process.exitCode = 1;
  } else {
    fs.rmSync(sandbox, { recursive: true, force: true });
    console.log('\nSandbox eliminado tras superar las comprobaciones.');
  }

  console.log('\n================================================================================');
  console.log(' CERTIFICACION PRE-PRODUCCION (v1.7.0-rc.1) — EVIDENCIA AUDITABLE Y ALCANCE REAL');
  console.log('================================================================================');
  console.log(' [PASS=' + point1_ExpressRegressionPass + '] Punto 1. Patrones Express        : Callbacks array, router.use(SSO), app.route, comodines y plugins');
  console.log(' [PASS=' + point2_LowFreqZeroHitsProtectedPass + '] Punto 2. Guardia Heuristica      : Rutas /webhooks y /admin/monthly protegidas y documentadas como heuristica');
  console.log(' [PASS=' + point3_CrashRecovery3PidsPass + '] Punto 3. Recuperacion + BatchId  : 3 PIDs (' + point3Validation.pids.join('->') + '), replay idempotente post-500 y stderr limpio');
  console.log(' [PASS=' + point4_CiSecurityAndMultiOsPass + '] Punto 4. AST YAML de CI          : Parseado con paquete yaml (permissions: read + Matrix Linux/Windows)');
  console.log(' [PASS=' + point5_GradualRolloutAndRollbackPass + '] Punto 5. Path-Jail + Rollback    : Jaula sandbox verificada, bloqueo de ../escape y rollback SHA-256');
  console.log(' [PASS=' + point6_CleanTarballInstallPass + '] Punto 6. Instalacion Limpia .tgz : @m_stelfid/node-sdk y @m_stelfid/cli instalados y probados fuera del monorepo');
  console.log(' [MANIFEST] Evidencia de Certificacion : ' + certificationManifestPath);
  console.log('================================================================================\n');
}

runRcCertification();
