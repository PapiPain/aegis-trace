#!/usr/bin/env node

import * as path from 'path';
import * as fs from 'fs';
import * as readline from 'readline';
import { BlindAnalyzer, RouteEntry } from './analyzer';
import {
  AuditReportData,
  EndpointReportItem,
  generateJsonReport,
  generateMarkdownReport
} from './reporter';

const API_KEY = process.env.AEGIS_API_KEY || 'aegis_live_test123';
const CLIENT_SECRET = process.env.AEGIS_SECRET || 'sec_secretkey_test987';
const INGESTION_URL = process.env.AEGIS_URL || 'http://localhost:4000/v1/telemetry/hashes';

function getArgValue(flag: string): string | null {
  const args = process.argv.slice(2);
  const index = args.indexOf(flag);
  if (index !== -1 && index + 1 < args.length) {
    return args[index + 1];
  }
  const prefixMatch = args.find(a => a.startsWith(`${flag}=`));
  if (prefixMatch) {
    return prefixMatch.split('=')[1];
  }
  return null;
}

function askQuestion(query: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise(resolve => rl.question(query, ans => {
    rl.close();
    resolve(ans.trim().toLowerCase());
  }));
}

function createBackup(filePath: string) {
  const backupPath = `${filePath}.aegis.bak`;
  if (!fs.existsSync(backupPath)) {
    fs.copyFileSync(filePath, backupPath);
    console.log(`\n[Security] Preventive backup created at: ${path.basename(backupPath)}`);
  }
}

function restoreBackups(dir: string): number {
  let restored = 0;
  const entries = fs.readdirSync(dir);

  for (const entry of entries) {
    const fullPath = path.join(dir, entry);
    const stat = fs.statSync(fullPath);

    if (stat.isDirectory()) {
      if (!['node_modules', 'dist', 'build', '.git'].includes(entry)) {
        restored += restoreBackups(fullPath);
      }
    } else if (entry.endsWith('.aegis.bak')) {
      const originalPath = fullPath.slice(0, -'.aegis.bak'.length);
      fs.copyFileSync(fullPath, originalPath);
      fs.unlinkSync(fullPath);
      console.log(`âœ” Restored to original state: ${path.basename(originalPath)}`);
      restored++;
    }
  }

  return restored;
}

function readLocalTelemetryFile(sinceTimestamp: number): Map<string, number> | null {
  const candidates = [
    path.resolve(process.cwd(), '.aegis-local.json'),
    path.resolve(process.cwd(), 'apps/test-service/.aegis-local.json')
  ];

  const foundPath = candidates.find(p => fs.existsSync(p));
  if (!foundPath) return null;

  try {
    const raw = JSON.parse(fs.readFileSync(foundPath, 'utf8').replace(/^\uFEFF/, '')) as Record<
      string,
      { method: string; calls: number; lastSeen: number }
    >;
    const map = new Map<string, number>();
    for (const [hash, info] of Object.entries(raw)) {
      if (info.lastSeen >= sinceTimestamp) {
        map.set(hash, info.calls || 1);
      }
    }
    console.log(`âœ” Telemetry loaded in Zero-Server Local Mode (${path.basename(foundPath)})`);
    return map;
  } catch {
    return null;
  }
}

async function fetchIngestedHashes(days?: number): Promise<Map<string, number>> {
  const sinceTimestamp = days && days > 0 ? Date.now() - days * 24 * 60 * 60 * 1000 : 0;

  if (process.argv.includes('--local')) {
    const localMap = readLocalTelemetryFile(sinceTimestamp);
    if (localMap) return localMap;
  }

  try {
    const url = new URL(INGESTION_URL);
    if (days && days > 0) {
      url.searchParams.set('days', days.toString());
    }

    const res = await fetch(url.toString(), {
      method: 'GET',
      headers: {
        'X-Aegis-Key': API_KEY
      }
    });

    if (!res.ok) {
      throw new Error(`Server error (${res.status}): ${await res.text()}`);
    }

    const data = await res.json() as { hashes: Array<string | { hash: string; calls: number }> };
    const hashMetrics = new Map<string, number>();

    if (Array.isArray(data.hashes)) {
      for (const item of data.hashes) {
        if (typeof item === 'string') {
          hashMetrics.set(item, 1);
        } else if (item && typeof item === 'object') {
          hashMetrics.set(item.hash, item.calls || 1);
        }
      }
    }
    return hashMetrics;
  } catch (err: any) {
    const localMap = readLocalTelemetryFile(sinceTimestamp);
    if (localMap) {
      return localMap;
    }

    console.error(`[Error] Could not connect to Ingestion API and no .aegis-local.json file was found (${err.message})`);
    process.exit(1);
  }
}

function commentLines(filePath: string, startLine: number, endLine: number) {
  const fileLines = fs.readFileSync(filePath, 'utf8').split('\n');
  const timestamp = new Date().toISOString();

  fileLines.splice(startLine - 1, 0, `/* [AegisTrace: Dead-Code Audit - ${timestamp}]`);
  fileLines.splice(endLine + 1, 0, `*/`);

  fs.writeFileSync(filePath, fileLines.join('\n'), 'utf8');
}

function removeLines(filePath: string, startLine: number, endLine: number) {
  const fileLines = fs.readFileSync(filePath, 'utf8').split('\n');
  fileLines.splice(startLine - 1, endLine - startLine + 1);
  fs.writeFileSync(filePath, fileLines.join('\n'), 'utf8');
}

function computeRiskLevel(isAlive: boolean, isAuthenticated: boolean): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
  if (!isAlive && !isAuthenticated) return 'CRITICAL';
  if (!isAlive && isAuthenticated) return 'HIGH';
  if (isAlive && !isAuthenticated) return 'MEDIUM';
  return 'LOW';
}

async function handleZombieRoute(route: RouteEntry, confidenceLabel: string): Promise<'modified' | 'skipped'> {
  const authBanner = route.isAuthenticated
    ? `PROTECTED (${route.authMiddlewares.join(', ')})`
    : 'ðŸš¨ CRITICAL: UNAUTHENTICATED PUBLIC ENDPOINT';

  console.log('\n------------------------------------------------------------');
  console.log(`ALERT: Zombie Code detected in ${route.file} (Lines ${route.startLine}-${route.endLine})`);
  console.log(`Endpoint   : ${route.method} ${route.fullRoute}`);
  console.log(`Auth Guard : ${authBanner}`);
  console.log(`Confidence : ${confidenceLabel}`);
  console.log('Affected code preview:');
  console.log('------------------------------------------------------------');
  route.codeSnippet.forEach((line, idx) => {
    console.log(`  ${route.startLine + idx} | ${line}`);
  });
  console.log('------------------------------------------------------------');

  console.log('Available actions:');
  console.log('  [c] Comment out code block (Safe, reversible)');
  console.log('  [d] Delete code block permanently');
  console.log('  [s] Skip / Keep unchanged');
  console.log('  [q] Quit interactive assistant');

  const action = await askQuestion('\nSelect an action to execute [c/d/s/q]: ');

  if (action === 's' || action === '') {
    console.log('-> Block skipped without modifications.');
    return 'skipped';
  }

  if (action === 'q') {
    console.log('-> Operation aborted by user.');
    process.exit(0);
  }

  if (action === 'd') {
    console.log('\nâš ï¸  SECURITY WARNING âš ï¸');
    console.log('You are about to permanently delete source code lines from your file.');
    const confirmation = await askQuestion('To confirm permanent deletion, type "DELETE": ');

    if (confirmation !== 'delete') {
      console.log('-> Cancelled. No changes were made for safety.');
      return 'skipped';
    }

    createBackup(route.filePath);
    removeLines(route.filePath, route.startLine, route.endLine);
    console.log(`âœ” Code block successfully deleted from ${route.file}.`);
    return 'modified';
  }

  if (action === 'c') {
    const confirmation = await askQuestion('Confirm commenting out this route block? [y/n]: ');
    if (confirmation !== 'y' && confirmation !== 'yes') {
      console.log('-> Cancelled. No changes were made.');
      return 'skipped';
    }

    createBackup(route.filePath);
    commentLines(route.filePath, route.startLine, route.endLine);
    console.log(`âœ” Code block commented out with audit markers in ${route.file}.`);
    return 'modified';
  }

  return 'skipped';
}

async function main() {
  const args = process.argv.slice(2);

  const customDir = getArgValue('--dir');
  const targetPath = customDir 
    ? path.resolve(process.cwd(), customDir)
    : path.resolve(__dirname, '../../../apps/test-service/src');

  if (args.includes('--restore')) {
    console.log('===================================================================');
    console.log('           AEGIS-TRACE : BACKUP RESTORATION (.aegis.bak)           ');
    console.log('===================================================================');
    const count = restoreBackups(targetPath);
    console.log(`\nTotal files restored: ${count}\n`);
    return;
  }

  const outputFile = getArgValue('--output');
  const format = (getArgValue('--format') || 'json').toLowerCase();
  const daysArg = getArgValue('--days');
  const days = daysArg ? parseInt(daysArg, 10) : undefined;
  const isPruneMode = args.includes('--prune');
  const isDryRun = args.includes('--dry-run') || !isPruneMode;
  const failOnZombies = args.includes('--fail-on-zombies');

  console.log('===================================================================');
  console.log('           AEGIS-TRACE : ZERO-KNOWLEDGE DEAD-CODE AUDITOR          ');
  console.log('===================================================================');
  console.log(`Execution Mode   : ${isPruneMode ? 'INTERACTIVE (--prune)' : 'READ-ONLY (--dry-run)'}`);
  if (days) {
    console.log(`Time Window      : Last ${days} day(s)`);
  }
  console.log('Synchronizing cryptographic telemetry...');

  const activeHashMap = await fetchIngestedHashes(days);
  const totalObservedCalls = Array.from(activeHashMap.values()).reduce((acc, v) => acc + v, 0);

  console.log(`âœ” Active hashes retrieved: ${activeHashMap.size} (${totalObservedCalls} total calls)`);
  console.log(`Target Directory : ${targetPath}\n`);

  const analyzer = new BlindAnalyzer(CLIENT_SECRET);
  const files = analyzer.scanDirectory(targetPath);
  const routerPrefixes = analyzer.detectRouterPrefixes(files);

  const declaredRoutes = files.flatMap(file => {
    const prefix = routerPrefixes.get(file) || '';
    return analyzer.extractRoutes(file, prefix);
  });

  const totalRoutes = declaredRoutes.length;
  if (totalRoutes === 0) {
    console.log('No declared routes found to audit (or all routes are already commented out).');
    return;
  }

  const activeRoutes = declaredRoutes.filter(r => activeHashMap.has(r.hash));
  const zombieRoutes = declaredRoutes.filter(r => !activeHashMap.has(r.hash));
  const unauthenticatedZombies = zombieRoutes.filter(r => !r.isAuthenticated);

  const declaredHashSet = new Set(declaredRoutes.map(r => r.hash));
  const shadowHashesCount = Array.from(activeHashMap.keys()).filter(h => !declaredHashSet.has(h)).length;

  const confidenceLabel = totalObservedCalls >= 50
    ? 'HIGH (Representative traffic volume)'
    : totalObservedCalls > 0
      ? 'MEDIUM (Moderate traffic sample)'
      : 'LOW (No global traffic recorded yet)';

  console.log('--- CONSOLE AUDIT REPORT ---');
  for (const route of declaredRoutes) {
    const calls = activeHashMap.get(route.hash) || 0;
    const isAlive = calls > 0;
    const status = isAlive ? `[ACTIVE: ${calls} hits]`.padEnd(18) : '[ZOMBIE: 0 hits]  ';
    const authTag = route.isAuthenticated
      ? `[ðŸ”’ AUTH]`.padEnd(11)
      : (isAlive ? `[ðŸ”“ PUBLIC]` : `[ðŸš¨ NO-AUTH]`);
    console.log(`${status} ${authTag} ${route.method.padEnd(6)} ${route.fullRoute.padEnd(26)} -> ${route.file}:${route.startLine}`);
  }

  const reductionPct = totalRoutes > 0 
    ? Number(((zombieRoutes.length / totalRoutes) * 100).toFixed(1))
    : 0;

  console.log('\n--- ATTACK SURFACE & SECURITY METRICS ---');
  console.log(`Total declared endpoints         : ${totalRoutes}`);
  console.log(`Active endpoints (traffic)       : ${activeRoutes.length}`);
  console.log(`Inactive endpoints (zombie)      : ${zombieRoutes.length}`);
  console.log(`Unauthenticated zombies (CRIT)   : ${unauthenticatedZombies.length}`);
  console.log(`Shadow Endpoints detected        : ${shadowHashesCount}`);
  console.log(`Pruning confidence level         : ${confidenceLabel}`);
  console.log(`Attack surface reduction         : ${reductionPct}%\n`);

  const reportPayload: AuditReportData = {
    metadata: {
      tool: 'AegisTrace CLI',
      version: '1.3.0',
      generatedAt: new Date().toISOString(),
      targetDirectory: targetPath,
      apiKey: API_KEY,
      observationDays: days
    },
    summary: {
      totalDeclaredEndpoints: totalRoutes,
      activeEndpoints: activeRoutes.length,
      zombieEndpoints: zombieRoutes.length,
      unauthenticatedZombieEndpoints: unauthenticatedZombies.length,
      shadowEndpoints: shadowHashesCount,
      totalObservedCalls,
      confidenceLabel,
      attackSurfaceReductionPercentage: reductionPct
    },
    endpoints: declaredRoutes.map((route): EndpointReportItem => {
      const isAlive = activeHashMap.has(route.hash);
      return {
        method: route.method,
        route: route.fullRoute,
        file: route.file,
        fullPath: route.filePath,
        startLine: route.startLine,
        endLine: route.endLine,
        blindHash: route.hash,
        status: isAlive ? 'ACTIVE' : 'ZOMBIE',
        isAuthenticated: route.isAuthenticated,
        authMiddlewares: route.authMiddlewares,
        riskLevel: computeRiskLevel(isAlive, route.isAuthenticated),
        callCountObserved: activeHashMap.get(route.hash) || 0,
        codeSnippet: route.codeSnippet
      };
    })
  };

  if (outputFile) {
    if (format === 'markdown' || format === 'md' || outputFile.endsWith('.md')) {
      generateMarkdownReport(reportPayload, outputFile);
    } else {
      generateJsonReport(reportPayload, outputFile);
    }
  }

  if (isDryRun && !isPruneMode) {
    if (zombieRoutes.length > 0) {
      console.log('â„¹ Quick action commands available:');
      console.log('  â€¢ Interactive pruning : aegis-trace --prune');
      console.log('  â€¢ Restore backups     : aegis-trace --restore\n');
      if (failOnZombies) {
        process.exit(1);
      }
    }
    return;
  }

  const sortedZombies = [...zombieRoutes].sort((a, b) => {
    const fileCompare = a.filePath.localeCompare(b.filePath);
    if (fileCompare !== 0) return fileCompare;
    return b.startLine - a.startLine;
  });

  let mitigatedCount = 0;
  for (const zombie of sortedZombies) {
    const result = await handleZombieRoute(zombie, confidenceLabel);
    if (result === 'modified') mitigatedCount++;
  }

  console.log('\n===================================================================');
  console.log(`Audit complete. Successfully mitigated routes: ${mitigatedCount}`);
  console.log('To undo all changes at any time, run: aegis-trace --restore');
  console.log('===================================================================\n');
}

main();
