#!/usr/bin/env node

import * as path from 'path';
import * as fs from 'fs';
import * as readline from 'readline';
import { BlindAnalyzer, RouteEntry } from './analyzer';
import {
  AuditReportData,
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
    console.log(`\n[Seguridad] Respaldo preventivo creado en: ${path.basename(backupPath)}`);
  }
}

async function fetchIngestedHashes(): Promise<Set<string>> {
  try {
    const res = await fetch(INGESTION_URL, {
      method: 'GET',
      headers: {
        'X-Aegis-Key': API_KEY
      }
    });

    if (!res.ok) {
      throw new Error(`Error en servidor (${res.status}): ${await res.text()}`);
    }

    const data = await res.json() as { hashes: string[] };
    return new Set<string>(data.hashes);
  } catch (err: any) {
    console.error(`[Error] No se pudo sincronizar con Ingestion API: ${err.message}`);
    process.exit(1);
  }
}

async function handleZombieRoute(route: RouteEntry): Promise<'modified' | 'skipped'> {
  console.log('\n------------------------------------------------------------');
  console.log(`ALERTA: Código Zombi detectado en ${route.file} (Líneas ${route.startLine}-${route.endLine})`);
  console.log(`Endpoint: ${route.method} ${route.route}`);
  console.log('Vista previa del código afectado:');
  console.log('------------------------------------------------------------');
  route.codeSnippet.forEach((line, idx) => {
    console.log(`  ${route.startLine + idx} | ${line}`);
  });
  console.log('------------------------------------------------------------');

  console.log('Opciones disponibles:');
  console.log('  [c] Comentar el bloque de código (Seguro, reversible)');
  console.log('  [d] Eliminar el bloque de código');
  console.log('  [s] Omitir / Mantener sin cambios');
  console.log('  [q] Cancelar y salir del asistente');

  const action = await askQuestion('\n¿Qué acción deseas ejecutar? [c/d/s/q]: ');

  if (action === 's' || action === '') {
    console.log('-> Bloque omitido sin modificaciones.');
    return 'skipped';
  }

  if (action === 'q') {
    console.log('-> Operación abortada por el usuario.');
    process.exit(0);
  }

  if (action === 'd') {
    console.log('\n⚠️  ADVERTENCIA DE SEGURIDAD ⚠️');
    console.log('Estás a punto de eliminar código fuente permanentemente de tu archivo.');
    const confirmation = await askQuestion('Para confirmar la eliminación, escribe exactamente "ELIMINAR" (o cualquier otra tecla para cancelar): ');

    if (confirmation !== 'eliminar') {
      console.log('-> Cancelado. No se realizaron cambios por seguridad.');
      return 'skipped';
    }

    createBackup(route.filePath);
    removeLines(route.filePath, route.startLine, route.endLine);
    console.log(`✔ Bloque eliminado correctamente de ${route.file}.`);
    return 'modified';
  }

  if (action === 'c') {
    const confirmation = await askQuestion('¿Confirmas que deseas comentar este bloque de rutas? [s/n]: ');
    if (confirmation !== 's') {
      console.log('-> Cancelado. No se realizaron cambios.');
      return 'skipped';
    }

    createBackup(route.filePath);
    commentLines(route.filePath, route.startLine, route.endLine);
    console.log(`✔ Bloque comentado con marcas de auditoría en ${route.file}.`);
    return 'modified';
  }

  return 'skipped';
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

async function main() {
  const args = process.argv.slice(2);

  const customDir = getArgValue('--dir');
  const targetPath = customDir 
    ? path.resolve(process.cwd(), customDir)
    : path.resolve(__dirname, '../../../apps/test-service/src');

  const outputFile = getArgValue('--output');
  const format = (getArgValue('--format') || 'json').toLowerCase();
  const isPruneMode = args.includes('--prune');
  const isDryRun = args.includes('--dry-run') || !isPruneMode;

  console.log('===================================================================');
  console.log('            AEGIS-TRACE : AUDITOR DE CÓDIGO MUERTO                ');
  console.log('===================================================================');
  console.log(`Modo de ejecución: ${isPruneMode ? 'INTERACTIVO (--prune)' : 'SÓLO LECTURA (--dry-run)'}`);
  console.log('Sincronizando telemetría criptográfica con SQLite...');

  const ingestedHashes = await fetchIngestedHashes();
  console.log(`✔ Hashes activos consultados desde la API: ${ingestedHashes.size}`);
  console.log(`Directorio objetivo: ${targetPath}\n`);

  const analyzer = new BlindAnalyzer(CLIENT_SECRET);
  const files = analyzer.scanDirectory(targetPath);
  const declaredRoutes = files.flatMap(file => analyzer.extractRoutes(file));

  const totalRoutes = declaredRoutes.length;
  if (totalRoutes === 0) {
    console.log('No se encontraron rutas declaradas para auditar.');
    return;
  }

  const activeRoutes = declaredRoutes.filter(r => ingestedHashes.has(r.hash));
  const zombieRoutes = declaredRoutes.filter(r => !ingestedHashes.has(r.hash));

  console.log('--- REPORTE DE AUDITORÍA EN CONSOLA ---');
  for (const route of declaredRoutes) {
    const isAlive = ingestedHashes.has(route.hash);
    const status = isAlive ? '[ACTIVA] ' : '[ZOMBI]  ';
    console.log(`${status} ${route.method.padEnd(6)} ${route.route.padEnd(25)} -> ${route.file}:${route.startLine}`);
  }

  const reductionPct = totalRoutes > 0 
    ? Number(((zombieRoutes.length / totalRoutes) * 100).toFixed(1))
    : 0;

  console.log('\n--- MÉTRICAS DE SUPERFICIE DE ATAQUE ---');
  console.log(`Total de endpoints declarados : ${totalRoutes}`);
  console.log(`Endpoints activos con tráfico : ${activeRoutes.length}`);
  console.log(`Endpoints inactivos (zombi)   : ${zombieRoutes.length}`);
  console.log(`Reducción potencial de ataque : ${reductionPct}%\n`);

  // Construcción del reporte estructurado
  const reportPayload: AuditReportData = {
    metadata: {
      tool: 'AegisTrace CLI',
      version: '1.0.0',
      generatedAt: new Date().toISOString(),
      targetDirectory: targetPath,
      apiKey: API_KEY
    },
    summary: {
      totalDeclaredEndpoints: totalRoutes,
      activeEndpoints: activeRoutes.length,
      zombieEndpoints: zombieRoutes.length,
      attackSurfaceReductionPercentage: reductionPct
    },
    endpoints: declaredRoutes.map(route => {
      const isAlive = ingestedHashes.has(route.hash);
      return {
        method: route.method,
        route: route.route,
        file: route.file,
        fullPath: route.filePath,
        startLine: route.startLine,
        endLine: route.endLine,
        blindHash: route.hash,
        status: isAlive ? 'ACTIVE' : 'ZOMBIE',
        callCountObserved: isAlive ? 1 : 0,
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
      console.log('ℹ Para iniciar el asistente de limpieza interactiva con respaldo, ejecuta:');
      console.log('  aegis-trace --prune\n');
    }
    return;
  }

  let mitigatedCount = 0;
  for (const zombie of zombieRoutes) {
    const result = await handleZombieRoute(zombie);
    if (result === 'modified') mitigatedCount++;
  }

  console.log('\n===================================================================');
  console.log(`Auditoría finalizada. Rutas intervenidas con éxito: ${mitigatedCount}`);
  console.log('===================================================================\n');
}

main();