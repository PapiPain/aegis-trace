#!/usr/bin/env node

import * as fs from 'fs';
import * as path from 'path';
import { createHash } from 'crypto';
import { scanDirectoryForRoutes, AnalyzedRoute } from './analyzer';
import {
  evaluateRoutesWithEvidence,
  printEvidenceReport,
  exportAuditEvidenceFile,
  TelemetryContext,
  EvaluatedRoute,
  ShadowApiEntry,
  NodeSlice
} from './reporter';

export interface BackupFileEntry {
  filePath: string;
  relativePath: string;
  originalSha256: string;
  modifiedSha256?: string;
  originalBytes: number;
  originalContent: string;
}

export interface BackupManifest {
  backupId: string;
  createdAt: string;
  targetDir: string;
  mode: string;
  prunedRoutes: Array<{ hash: string; method: string; fullRoute: string; file: string; line: number }>;
  files: BackupFileEntry[];
}

function sha256Text(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

export function assertPathInsideTargetDir(targetDir: string, candidatePath: string): string {
  const realRoot = fs.realpathSync(path.resolve(targetDir));
  const resolvedCandidate = path.resolve(targetDir, candidatePath);
  const targetToCheck = fs.existsSync(resolvedCandidate)
    ? fs.realpathSync(resolvedCandidate)
    : path.resolve(fs.realpathSync(path.dirname(resolvedCandidate)), path.basename(resolvedCandidate));

  const rel = path.relative(realRoot, targetToCheck);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error(
      `SECURITY PATH-JAIL VIOLATION: Refusing to access or modify '${candidatePath}' (resolved to '${targetToCheck}') because it escapes authorized targetDir '${realRoot}'.`
    );
  }
  return targetToCheck;
}

function loadTelemetryWithShadowDetection(
  targetDir: string,
  minRequiredDays: number,
  expectedMinNodes: number,
  scannedRoutes: AnalyzedRoute[]
): { map: Map<string, number>; context: TelemetryContext } {
  const candidates = [
    path.join(targetDir, '.stelfid-local.json'),
    path.join(targetDir, '.aegis-local.json'),
    path.join(process.cwd(), '.stelfid-local.json'),
    path.join(process.cwd(), 'apps', 'test-service', '.stelfid-local.json')
  ];
  const knownStaticHashes = new Set<string>(scannedRoutes.map(r => r.hash));
  const map = new Map<string, number>();
  const shadowApis: ShadowApiEntry[] = [];
  let environment = 'local';
  let nodeCount = 1;
  let observationStartedAt: string | null = null;
  let observationDays = 0;
  let reactivationEventsCount = 0;

  const found = candidates.find(p => fs.existsSync(p));
  if (found) {
    try {
      const raw = JSON.parse(fs.readFileSync(found, 'utf8').replace(/^\uFEFF/, ''));
      if (raw._meta) {
        environment = raw._meta.environment || 'local';
        nodeCount = Array.isArray(raw._meta.activeNodes) ? raw._meta.activeNodes.length : Number(raw._meta.nodeCount || 1);
        observationStartedAt = raw._meta.observationStartedAt || null;
        const endRefMs = raw._meta.lastFlushedAt ? new Date(raw._meta.lastFlushedAt).getTime() : Date.now();
        if (observationStartedAt) {
          observationDays = Math.max(0, (endRefMs - new Date(observationStartedAt).getTime()) / (1000 * 60 * 60 * 24));
        }
      }
      if (Array.isArray(raw.reactivationEvents)) reactivationEventsCount = raw.reactivationEvents.length;
      const entries = raw.routes || raw;
      for (const [hash, val] of Object.entries(entries as Record<string, any>)) {
        if (hash === '_meta' || hash === 'reactivationEvents' || hash === '_txState') continue;
        const calls = Number(val?.calls ?? 1);
        map.set(hash, calls);
        if (calls > 0 && !knownStaticHashes.has(hash)) {
          const statusCodes: Record<string, number> = val?.statusCodes || { '200': calls };
          if (Object.keys(statusCodes).some(code => Number(code) < 400)) {
            const breakdown: Record<string, NodeSlice> = val?.nodeBreakdown || {};
            const sliceValues = Object.values(breakdown);
            let firstSeenAt = val?.firstSeenAt || observationStartedAt || new Date().toISOString();
            let lastSeenAt = val?.lastSeen || val?.lastSeenAt || new Date().toISOString();
            if (sliceValues.length > 0) {
              firstSeenAt = sliceValues.map(s => s.firstSeenAt).sort()[0];
              lastSeenAt = sliceValues.map(s => s.lastSeenAt).sort().reverse()[0];
            }
            const spanMs = Math.max(0, new Date(lastSeenAt).getTime() - new Date(firstSeenAt).getTime());
            shadowApis.push({
              hash,
              calls,
              firstSeenAt,
              lastSeenAt,
              observedSpanDays: Number((spanMs / (1000 * 60 * 60 * 24)).toFixed(4)),
              observedNodesCount: sliceValues.length > 0 ? sliceValues.length : nodeCount,
              nodeBreakdown: breakdown,
              statusCodes,
              owaspMapping: 'OWASP_API9_UNDOCUMENTED_SHADOW_ENDPOINT'
            });
          }
        }
      }
    } catch {}
  }
  return {
    map,
    context: {
      environment,
      nodeCount,
      expectedMinNodes,
      nodeCoverageVerified: nodeCount >= expectedMinNodes,
      observationDays,
      minRequiredDays,
      observationWindowVerified: observationDays >= minRequiredDays,
      observationStartedAt,
      reactivationEventsCount,
      shadowApis
    }
  };
}

function createBackupBeforePrune(
  targetDir: string,
  routesToPrune: EvaluatedRoute[],
  mode: string
): { latestBackupPath: string; timestampedBackupPath: string; manifest: BackupManifest } {
  const backupRoot = path.join(targetDir, '.stelfid-backups');
  fs.mkdirSync(backupRoot, { recursive: true });
  const uniqueFiles = Array.from(new Set(routesToPrune.map(r => assertPathInsideTargetDir(targetDir, r.file))));
  const stamp = new Date().toISOString();
  const safeStamp = stamp.replace(/[:.]/g, '-');

  const manifest: BackupManifest = {
    backupId: 'stelfid-backup-' + safeStamp,
    createdAt: stamp,
    targetDir,
    mode,
    prunedRoutes: routesToPrune.map(r => ({
      hash: r.hash,
      method: r.method,
      fullRoute: r.fullRoute,
      file: path.relative(targetDir, r.file).replace(/\\/g, '/'),
      line: r.line
    })),
    files: uniqueFiles.map(f => {
      const raw = fs.readFileSync(f, 'utf8');
      return {
        filePath: f,
        relativePath: path.relative(targetDir, f).replace(/\\/g, '/'),
        originalSha256: sha256Text(raw),
        originalBytes: Buffer.byteLength(raw, 'utf8'),
        originalContent: raw
      };
    })
  };

  const timestampedBackupPath = path.join(backupRoot, 'backup-' + safeStamp + '.json');
  const latestBackupPath = path.join(backupRoot, 'latest-backup.json');
  const serialized = JSON.stringify(manifest, null, 2) + '\n';
  fs.writeFileSync(timestampedBackupPath, serialized, 'utf8');
  fs.writeFileSync(latestBackupPath, serialized, 'utf8');
  return { latestBackupPath, timestampedBackupPath, manifest };
}

function rollbackFromLatestBackup(targetDir: string): { restoredCount: number; restoredFiles: string[] } {
  const latestBackupPath = assertPathInsideTargetDir(targetDir, path.join(targetDir, '.stelfid-backups', 'latest-backup.json'));
  if (!fs.existsSync(latestBackupPath)) {
    throw new Error('No backup manifest found at ' + latestBackupPath);
  }
  const manifest: BackupManifest = JSON.parse(fs.readFileSync(latestBackupPath, 'utf8'));
  if (!Array.isArray(manifest.files) || manifest.files.length === 0) {
    throw new Error('Backup manifest contains zero file entries to restore.');
  }

  // Fase 1 (Pre-flight atomico): Validar jaula de rutas e integridad SHA-256 de TODOS los archivos antes de tocar el disco
  const validatedPlan: Array<{ safeDest: string; relativePath: string; originalContent: string; originalSha256: string }> = [];
  for (const item of manifest.files) {
    if (!item.relativePath || item.relativePath.includes('..') || path.isAbsolute(item.relativePath)) {
      throw new Error('SECURITY PATH-JAIL VIOLATION in backup manifest relativePath: ' + item.relativePath);
    }
    const safeDest = assertPathInsideTargetDir(targetDir, path.join(targetDir, item.relativePath));
    const computedOriginalHash = sha256Text(item.originalContent);
    if (computedOriginalHash !== item.originalSha256) {
      throw new Error('Backup integrity mismatch for ' + item.relativePath + ': expected ' + item.originalSha256 + ', got ' + computedOriginalHash);
    }
    validatedPlan.push({
      safeDest,
      relativePath: item.relativePath,
      originalContent: item.originalContent,
      originalSha256: item.originalSha256
    });
  }

  // Fase 2 (Escritura y verificacion post-rollback en disco)
  const restoredFiles: string[] = [];
  for (const entry of validatedPlan) {
    fs.writeFileSync(entry.safeDest, entry.originalContent, 'utf8');
    const diskVerifyHash = sha256Text(fs.readFileSync(entry.safeDest, 'utf8'));
    if (diskVerifyHash !== entry.originalSha256) {
      throw new Error('Post-rollback disk verification failed for ' + entry.relativePath);
    }
    restoredFiles.push(entry.relativePath);
  }
  return { restoredCount: restoredFiles.length, restoredFiles };
}

function pruneRoutesSafely(
  targetDir: string,
  routesToPrune: EvaluatedRoute[],
  mode: string
): { count: number; backupPath: string; timestampedBackupPath: string } {
  const { latestBackupPath, timestampedBackupPath, manifest } = createBackupBeforePrune(targetDir, routesToPrune, mode);
  const byFile = new Map<string, EvaluatedRoute[]>();
  for (const r of routesToPrune) {
    const list = byFile.get(r.file) || [];
    list.push(r);
    byFile.set(r.file, list);
  }

  let totalPruned = 0;
  for (const [rawFilePath, fileRoutes] of byFile.entries()) {
    const filePath = assertPathInsideTargetDir(targetDir, rawFilePath);
    const raw = fs.readFileSync(filePath, 'utf8').replace(/^\uFEFF/, '');
    const endsWithNewline = raw.endsWith('\n');
    const lines = raw.split(/\r?\n/);
    if (endsWithNewline && lines[lines.length - 1] === '') lines.pop();

    const sorted = [...fileRoutes].sort((a, b) => b.line - a.line);
    for (const r of sorted) {
      const startIdx = r.line - 1;
      const endIdx = r.endLine - 1;
      if (startIdx < 0 || endIdx >= lines.length) continue;
      if (lines[startIdx].trim().startsWith('/*')) continue;
      const stamp = new Date().toISOString();
      lines[startIdx] = '/* [Maiestor Stelfid Controlled-Retirement: ' + r.method + ' ' + r.fullRoute + ' - ' + stamp + ']\n' + lines[startIdx];
      lines[endIdx] = lines[endIdx] + '\n*/';
      totalPruned++;
    }

    const updatedContent = lines.join('\n') + (endsWithNewline ? '\n' : '');
    fs.writeFileSync(filePath, updatedContent, 'utf8');

    const fileEntry = manifest.files.find(f => f.filePath === filePath);
    if (fileEntry) {
      fileEntry.modifiedSha256 = sha256Text(updatedContent);
    }
  }

  const updatedManifestJson = JSON.stringify(manifest, null, 2) + '\n';
  fs.writeFileSync(timestampedBackupPath, updatedManifestJson, 'utf8');
  fs.writeFileSync(latestBackupPath, updatedManifestJson, 'utf8');

  return { count: totalPruned, backupPath: latestBackupPath, timestampedBackupPath };
}

async function main() {
  const args = process.argv.slice(2);
  let targetDir = process.cwd();
  let secretKey = process.env.STELFID_SECRET_KEY || 'sec_secretkey_test987';
  let minDays = Number(process.env.STELFID_MIN_DAYS || 14);
  let minNodes = Number(process.env.STELFID_MIN_NODES || 1);
  let mode: 'observe' | 'manual-approval' | 'controlled-prune' = 'observe';
  let approvalManifestPath: string | null = null;
  let generateApprovalPlanPath: string | null = null;
  let shouldRollback = false;
  let forcePrune = false;
  let exportEvidencePath: string | null = null;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if ((arg === '--dir' || arg === '-d') && args[i + 1]) targetDir = path.resolve(args[++i]);
    else if ((arg === '--secret' || arg === '-s') && args[i + 1]) secretKey = args[++i];
    else if (arg === '--min-days' && args[i + 1]) minDays = Number(args[++i]);
    else if (arg === '--min-nodes' && args[i + 1]) minNodes = Number(args[++i]);
    else if ((arg === '--export-evidence' || arg === '-e') && args[i + 1]) exportEvidencePath = args[++i];
    else if (arg === '--mode' && args[i + 1]) mode = args[++i] as any;
    else if (arg === '--approval-manifest' && args[i + 1]) approvalManifestPath = path.resolve(args[++i]);
    else if (arg === '--generate-approval-plan' && args[i + 1]) generateApprovalPlanPath = path.resolve(args[++i]);
    else if (arg === '--rollback') shouldRollback = true;
    else if (arg === '--prune') mode = 'controlled-prune';
    else if (arg === '--force-prune') { mode = 'controlled-prune'; forcePrune = true; }
  }

  if (shouldRollback) {
    const { restoredCount, restoredFiles } = rollbackFromLatestBackup(targetDir);
    console.log(' [Stelfid Rollback]: Restored ' + restoredCount + ' file(s) with verified SHA-256 (' + restoredFiles.join(', ') + ')');
    return;
  }

  const scanned = scanDirectoryForRoutes(targetDir, secretKey);
  const { map, context } = loadTelemetryWithShadowDetection(targetDir, minDays, minNodes, scanned);
  const evaluated = evaluateRoutesWithEvidence(scanned, map, context);

  printEvidenceReport(evaluated, context);

  if (exportEvidencePath) {
    const writtenPaths = exportAuditEvidenceFile(exportEvidencePath, evaluated, context);
    for (const wp of writtenPaths) {
      console.log(' [Stelfid Evidence Exporter]: Verifiable audit report written to: ' + wp);
    }
  }

  if (generateApprovalPlanPath) {
    const plan = {
      generatedAt: new Date().toISOString(),
      notice: 'Set approved=true ONLY after verifying no external cron, webhook, or partner depends on the candidate route.',
      candidates: evaluated.filter(r => r.state === 'CANDIDATE_FOR_MANUAL_REVIEW').map(r => ({
        hash: r.hash,
        method: r.method,
        fullRoute: r.fullRoute,
        file: path.relative(targetDir, r.file).replace(/\\/g, '/'),
        line: r.line,
        canAutoPrune: r.canAutoPrune,
        approved: false
      }))
    };
    fs.writeFileSync(generateApprovalPlanPath, JSON.stringify(plan, null, 2) + '\n', 'utf8');
    console.log(' [Stelfid Manual-Approval Plan]: Written to ' + generateApprovalPlanPath);
  }

  if (mode === 'manual-approval' || mode === 'controlled-prune') {
    let approvedMap: Map<string, { method: string; fullRoute: string }> | null = null;
    if (mode === 'manual-approval') {
      if (!approvalManifestPath || !fs.existsSync(approvalManifestPath)) {
        console.error(' [Stelfid Manual-Approval Error]: --mode manual-approval requires a valid --approval-manifest <path>.');
        process.exit(1);
      }
    }
    if (approvalManifestPath && fs.existsSync(approvalManifestPath)) {
      const rawPlan = JSON.parse(fs.readFileSync(approvalManifestPath, 'utf8'));
      approvedMap = new Map();
      for (const c of rawPlan.candidates || []) {
        if (c && c.approved === true && typeof c.hash === 'string') {
          approvedMap.set(c.hash, { method: String(c.method || '').toUpperCase(), fullRoute: String(c.fullRoute || '') });
        }
      }
    }

    // PROTECCION ESTRICTA: Jamas tocar @keep, Observe-Only (@deprecated), Heuristica de Nombre (webhooks/admin/cron) ni Plugins/Dinamicas
    const eligible = evaluated.filter(r => {
      if (r.isKeepExempt || r.isDeprecatedStage || r.isLowFrequencyPattern || r.hasDynamicPattern || r.prefixSource === 'plugin-registered') {
        return false;
      }
      if (approvedMap) {
        const entry = approvedMap.get(r.hash);
        if (!entry || entry.method !== r.method || entry.fullRoute !== r.fullRoute) {
          return false;
        }
        return r.hits === 0;
      }
      return forcePrune ? r.hits === 0 : r.canAutoPrune;
    });

    if (eligible.length === 0) {
      console.log(' [Stelfid Controlled-Retirement Guard]: No routes met controlled retirement criteria.');
    } else {
      const { count, backupPath } = pruneRoutesSafely(targetDir, eligible, mode);
      console.log(' [Stelfid Controlled-Retirement]: Commented out ' + count + ' route(s). Backup saved at: ' + backupPath);
    }
  }
}

main().catch(err => {
  console.error('Error running Maiestor Stelfid CLI:', err);
  process.exit(1);
});
