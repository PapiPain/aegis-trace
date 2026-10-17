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
      console.log(`✔ Restaurado a su estado original: ${path.basename(originalPath)}`);
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
    const raw = JSON.parse(fs.readFileSync(foundPath, 'utf8')) as Record<
      string,
      { method: string; calls: number; lastSeen: number }
    >;
    const map = new Map<string, number>();
    for (const [hash, info] of Object.entries(raw)) {
      if (info.lastSeen >= sinceTimestamp) {
        map.set(hash, info.calls || 1);
      }
    }
    console.log(`✔ Telemetría leída en Modo Zero-Server Local (${path.basename(foundPath)})`);
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
      throw new Error(`Error en servidor (${res.status}): ${await res.text()}`);
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
    // Fallback automático al archivo local Zero-Server si la API no está corriendo
    const localMap = readLocalTelemetryFile(sinceTimestamp);
    if (localMap) {
      return localMap;
    }

    console.error(`[Error] No se pudo conectar con Ingestion API ni se encontró .aegis-local.json (${err.message})`);
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

async function handleZombieRoute(route: RouteEntry, confidenceLabel: string): Promise<'modified' | 'skipped'> {
  console.log('\n------------------------------------------------------------');
  console.log(`ALERTA: Código Zombi detectado en ${route.file} (Líneas ${route.startLine}-${route.endLine})`);
  console.log(`Endpoint  : ${route.method} ${route.fullRoute}`);
  console.log(`Confianza : ${confidenceLabel}`);
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
    const confirmation = await askQuestion('Para confirmar la eliminación, escribe exactamente "ELIMINAR": ');

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

async function main() {
  const args = process.argv.slice(2);

  const customDir = getArgValue('--dir');
  const targetPath = customDir 
    ? path.resolve(process.cwd(), customDir)
    : path.resolve(__dirname, '../../../apps/test-service/src');

  // Comando rápido de reversión segura (--restore)
  if (args.includes('--restore')) {
    console.log('===================================================================');
    console.log('           AEGIS-TRACE : RESTAURACIÓN DE RESPALDOS (.bak)          ');
    console.log('===================================================================');
    const count = restoreBackups(targetPath);
    console.log(`\nTotal de archivos restaurados: ${count}\n`);
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
  console.log('            AEGIS-TRACE : AUDITOR DE CÓDIGO MUERTO                 ');
  console.log('===================================================================');
  console.log(`Modo de ejecución: ${isPruneMode ? 'INTERACTIVO (--prune)' : 'SÓLO LECTURA (--dry-run)'}`);
  if (days) {
    console.log(`Ventana temporal : Últimos ${days} día(s)`);
  }
  console.log('Sincronizando telemetría criptográfica con SQLite...');

  const activeHashMap = await fetchIngestedHashes(days);
  const totalObservedCalls = Array.from(activeHashMap.values()).reduce((acc, v) => acc + v, 0);

  console.log(`✔ Hashes activos consultados desde la API: ${activeHashMap.size} (${totalObservedCalls} llamadas totales)`);
  console.log(`Directorio objetivo: ${targetPath}\n`);

  const analyzer = new BlindAnalyzer(CLIENT_SECRET);
  const files = analyzer.scanDirectory(targetPath);
  const routerPrefixes = analyzer.detectRouterPrefixes(files);

  const declaredRoutes = files.flatMap(file => {
    const prefix = routerPrefixes.get(file) || '';
    return analyzer.extractRoutes(file, prefix);
  });

  const totalRoutes = declaredRoutes.length;
  if (totalRoutes === 0) {
    console.log('No se encontraron rutas declaradas para auditar (o todas ya fueron comentadas).');
    return;
  }

  const activeRoutes = declaredRoutes.filter(r => activeHashMap.has(r.hash));
  const zombieRoutes = declaredRoutes.filter(r => !activeHashMap.has(r.hash));

  // Detectar Shadow Endpoints (Tráfico recibido en la API que no corresponde a ninguna ruta estática declarada)
  const declaredHashSet = new Set(declaredRoutes.map(r => r.hash));
  const shadowHashesCount = Array.from(activeHashMap.keys()).filter(h => !declaredHashSet.has(h)).length;

  // Calcular nivel de confianza según el volumen de tráfico observado
  const confidenceLabel = totalObservedCalls >= 50
    ? 'ALTA (Volumen de tráfico representativo)'
    : totalObservedCalls > 0
      ? 'MEDIA (Muestra de tráfico moderada)'
      : 'BAJA (Sin tráfico global registrado aún)';

  console.log('--- REPORTE DE AUDITORÍA EN CONSOLA ---');
  for (const route of declaredRoutes) {
    const calls = activeHashMap.get(route.hash) || 0;
    const isAlive = calls > 0;
    const status = isAlive ? `[ACTIVA: ${calls} hits]`.padEnd(18) : '[ZOMBI: 0 hits]   ';
    console.log(`${status} ${route.method.padEnd(6)} ${route.fullRoute.padEnd(26)} -> ${route.file}:${route.startLine}`);
  }

  const reductionPct = totalRoutes > 0 
    ? Number(((zombieRoutes.length / totalRoutes) * 100).toFixed(1))
    : 0;

  console.log('\n--- MÉTRICAS DE SUPERFICIE DE ATAQUE ---');
  console.log(`Total de endpoints declarados : ${totalRoutes}`);
  console.log(`Endpoints activos con tráfico : ${activeRoutes.length}`);
  console.log(`Endpoints inactivos (zombi)   : ${zombieRoutes.length}`);
  console.log(`Shadow Endpoints detectados   : ${shadowHashesCount}`);
  console.log(`Nivel de confianza de poda    : ${confidenceLabel}`);
  console.log(`Reducción potencial de ataque : ${reductionPct}%\n`);

const reportPayload: AuditReportData = {
    metadata: {
      tool: 'AegisTrace CLI',
      version: '1.0.0',
      generatedAt: new Date().toISOString(),
      targetDirectory: targetPath,
      apiKey: API_KEY,
      observationDays: days
    },
    summary: {
      totalDeclaredEndpoints: totalRoutes,
      activeEndpoints: activeRoutes.length,
      zombieEndpoints: zombieRoutes.length,
      shadowEndpoints: shadowHashesCount,
      totalObservedCalls,
      confidenceLabel,
      attackSurfaceReductionPercentage: reductionPct
    },
    endpoints: declaredRoutes.map(route => {
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
      console.log('ℹ Comandos de acción rápida disponibles:');
      console.log('  • Limpieza interactiva : aegis-trace --prune');
      console.log('  • Revertir respaldos   : aegis-trace --restore\n');
      if (failOnZombies) {
        process.exit(1);
      }
    }
    return;
  }

  // Agrupar por archivo y ordenar de mayor a menor línea para no desplazar índices
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
  console.log(`Auditoría finalizada. Rutas intervenidas con éxito: ${mitigatedCount}`);
  console.log('Para deshacer todos los cambios en cualquier momento: aegis-trace --restore');
  console.log('===================================================================\n');
}

main();