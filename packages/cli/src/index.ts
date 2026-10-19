#!/usr/bin/env node

import * as fs from 'fs';
import * as path from 'path';
import { scanDirectoryForRoutes } from './analyzer';
import {
  evaluateRoutesWithEvidence,
  printEvidenceReport,
  exportAuditEvidenceFile,
  TelemetryContext,
  EvaluatedRoute
} from './reporter';

function loadTelemetryWithContext(targetDir: string, minRequiredDays: number): {
  map: Map<string, number>;
  context: TelemetryContext;
} {
  const candidates = [
    path.join(targetDir, '.stelfid-local.json'),
    path.join(targetDir, '.aegis-local.json'),
    path.join(process.cwd(), '.stelfid-local.json'),
    path.join(process.cwd(), '.aegis-local.json'),
    path.join(process.cwd(), 'apps', 'test-service', '.stelfid-local.json'),
    path.join(process.cwd(), 'apps', 'test-service', '.aegis-local.json')
  ];

  const map = new Map<string, number>();
  let environment = 'local';
  let observationStartedAt: string | null = null;
  let observationDays = 0;
  let reactivationEventsCount = 0;

  const found = candidates.find(p => fs.existsSync(p));
  if (found) {
    try {
      const raw = JSON.parse(fs.readFileSync(found, 'utf8').replace(/^\uFEFF/, ''));
      if (raw._meta) {
        environment = raw._meta.environment || 'local';
        observationStartedAt = raw._meta.observationStartedAt || null;
        if (observationStartedAt) {
          const diffMs = Date.now() - new Date(observationStartedAt).getTime();
          observationDays = Math.max(0, diffMs / (1000 * 60 * 60 * 24));
        }
      }
      if (Array.isArray(raw.reactivationEvents)) {
        reactivationEventsCount = raw.reactivationEvents.length;
      }
      const entries = raw.routes || raw;
      for (const [hash, val] of Object.entries(entries as Record<string, any>)) {
        if (hash === '_meta' || hash === 'reactivationEvents') continue;
        map.set(hash, Number(val?.calls ?? 1));
      }
    } catch {}
  }

  return {
    map,
    context: {
      environment,
      observationDays,
      minRequiredDays,
      observationStartedAt,
      reactivationEventsCount
    }
  };
}

function pruneRoutesSafely(routesToPrune: EvaluatedRoute[]): number {
  const byFile = new Map<string, EvaluatedRoute[]>();
  for (const r of routesToPrune) {
    const list = byFile.get(r.file) || [];
    list.push(r);
    byFile.set(r.file, list);
  }

  let totalPruned = 0;
  for (const [filePath, fileRoutes] of byFile.entries()) {
    const raw = fs.readFileSync(filePath, 'utf8').replace(/^\uFEFF/, '');
    const lines = raw.split(/\r?\n/);
    const sorted = [...fileRoutes].sort((a, b) => b.line - a.line);

    for (const r of sorted) {
      const startIdx = r.line - 1;
      const endIdx = r.endLine - 1;
      if (startIdx < 0 || endIdx >= lines.length) continue;
      if (lines[startIdx].trim().startsWith('/*')) continue;

      const stamp = new Date().toISOString();
      lines[startIdx] = '/* [Maiestor Stelfid Safe-Retirement: ' + r.method + ' ' + r.fullRoute + ' - ' + stamp + ']\n' + lines[startIdx];
      lines[endIdx] = lines[endIdx] + '\n*/';
      totalPruned++;
    }
    fs.writeFileSync(filePath, lines.join('\n') + '\n', 'utf8');
  }
  return totalPruned;
}

async function main() {
  const args = process.argv.slice(2);
  let targetDir = process.cwd();
  let secretKey = process.env.STELFID_SECRET_KEY || process.env.AEGIS_SECRET_KEY || 'sec_secretkey_test987';
  let minDays = Number(process.env.STELFID_MIN_DAYS || 14);
  let shouldPrune = false;
  let forcePrune = false;
  let exportEvidencePath: string | null = null;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if ((arg === '--dir' || arg === '-d') && args[i + 1]) {
      targetDir = path.resolve(args[++i]);
    } else if ((arg === '--secret' || arg === '-s') && args[i + 1]) {
      secretKey = args[++i];
    } else if (arg === '--min-days' && args[i + 1]) {
      minDays = Number(args[++i]);
    } else if ((arg === '--export-evidence' || arg === '-e') && args[i + 1]) {
      exportEvidencePath = args[++i];
    } else if (arg === '--prune') {
      shouldPrune = true;
    } else if (arg === '--force-prune') {
      shouldPrune = true;
      forcePrune = true;
    }
  }

  const scanned = scanDirectoryForRoutes(targetDir, secretKey);
  const { map, context } = loadTelemetryWithContext(targetDir, minDays);
  const evaluated = evaluateRoutesWithEvidence(scanned, map, context);

  printEvidenceReport(evaluated, context);

  if (exportEvidencePath) {
    const writtenPaths = exportAuditEvidenceFile(exportEvidencePath, evaluated, context);
    for (const wp of writtenPaths) {
      console.log(' [Stelfid Evidence Exporter]: Verifiable audit report written to: ' + wp);
    }
    console.log('');
  }

  if (shouldPrune) {
    const eligible = evaluated.filter(r =>
      forcePrune
        ? (r.hits === 0 && !r.isKeepExempt)
        : r.canAutoPrune
    );

    if (eligible.length === 0) {
      console.log(' [Stelfid Safe-Prune Guard]: No routes met high-confidence retirement criteria.');
      console.log(' To protect production against premature removal (e.g., annual webhooks or short');
      console.log(' local telemetry windows), routes with insufficient observation are NOT pruned');
      console.log(' automatically. Use --force-prune in local testing or add // @stelfid-keep to exempt.\n');
    } else {
      const count = pruneRoutesSafely(eligible);
      console.log(' [Stelfid Safe-Retirement]: Safely commented out ' + count + ' route(s) with audit timestamps.\n');
    }
  }
}

main().catch(err => {
  console.error('Error running Maiestor Stelfid CLI:', err);
  process.exit(1);
});
