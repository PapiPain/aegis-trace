import * as fs from 'fs';
import * as path from 'path';

export interface EndpointReportItem {
  method: string;
  route: string;
  file: string;
  fullPath: string;
  startLine: number;
  endLine: number;
  blindHash: string;
  status: 'ACTIVE' | 'ZOMBIE';
  callCountObserved: number;
  codeSnippet: string[];
}

export interface AuditReportData {
  metadata: {
    tool: string;
    version: string;
    generatedAt: string;
    targetDirectory: string;
    apiKey: string;
    observationDays?: number;
  };
  summary: {
    totalDeclaredEndpoints: number;
    activeEndpoints: number;
    zombieEndpoints: number;
    shadowEndpoints?: number;
    totalObservedCalls?: number;
    confidenceLabel?: string;
    attackSurfaceReductionPercentage: number;
  };
  endpoints: EndpointReportItem[];
}

export function generateJsonReport(data: AuditReportData, outputPath: string): void {
  const resolvedPath = path.resolve(process.cwd(), outputPath);
  fs.writeFileSync(resolvedPath, JSON.stringify(data, null, 2), 'utf8');
  console.log(`✔ Reporte JSON guardado en: ${resolvedPath}`);
}

export function generateMarkdownReport(data: AuditReportData, outputPath: string): void {
  const resolvedPath = path.resolve(process.cwd(), outputPath);
  const { metadata, summary, endpoints } = data;

  const shadowCount = summary.shadowEndpoints ?? 0;
  const totalCalls = summary.totalObservedCalls ?? 0;
  const confidence = summary.confidenceLabel ?? 'MEDIA (Muestra de tráfico moderada)';
  const windowText = metadata.observationDays
    ? `Últimos ${metadata.observationDays} día(s)`
    : 'Histórico completo';

  const zombieList = endpoints.filter(e => e.status === 'ZOMBIE');

  const lines: string[] = [
    '# 🛡️ AegisTrace — Reporte de Auditoría de Código Muerto',
    '',
    `> **Generado:** \`${metadata.generatedAt}\` | **Versión:** \`v${metadata.version}\` | **Ventana:** \`${windowText}\``,
    `> **Directorio Auditado:** \`${metadata.targetDirectory}\``,
    '',
    '---',
    '',
    '## 📊 Resumen de Superficie de Ataque y Telemetría',
    '',
    '| Métrica de Seguridad | Valor |',
    '| :--- | :--- |',
    `| **Total de Endpoints Declarados (AST)** | \`${summary.totalDeclaredEndpoints}\` |`,
    `| **Endpoints Activos (Con Tráfico)** | \`${summary.activeEndpoints}\` (${totalCalls} invocaciones totales) |`,
    `| **Endpoints Inactivos (Código Zombi)** | \`${summary.zombieEndpoints}\` |`,
    `| **Shadow Endpoints (Tráfico no declarado)** | \`${shadowCount}\` |`,
    `| **Nivel de Confianza de Poda** | **${confidence}** |`,
    `| **Reducción Potencial de Superficie de Ataque** | **${summary.attackSurfaceReductionPercentage}%** |`,
    ''
  ];

  if (shadowCount > 0) {
    lines.push(
      '### ⚠️ Alerta de Seguridad: Shadow Endpoints Detectados',
      `Se detectaron **${shadowCount} hash(es) de telemetría activa** en el servidor que no coinciden con ninguna ruta declarada estáticamente en el código analizado. Esto puede deberse a middlewares dinámicos, rutas heredadas ocultas o peticiones previas no normalizadas.`,
      ''
    );
  }

  lines.push(
    '---',
    '',
    '## 🗺️ Inventario Completo de Endpoints',
    '',
    '| Estado | Hits | Método | Ruta Normalizada | Ubicación | Nivel de Riesgo | Blind Hash (HMAC-SHA256) |',
    '| :--- | :---: | :---: | :--- | :--- | :---: | :--- |'
  );

  for (const ep of endpoints) {
    const statusBadge = ep.status === 'ACTIVE' ? '🟢 `ACTIVA`' : '🔴 `ZOMBI`';
    const isDestructive = ['DELETE', 'POST', 'PUT', 'PATCH'].includes(ep.method.toUpperCase());
    const riskBadge = ep.status === 'ZOMBIE'
      ? (isDestructive ? '🔥 **ALTO (Mutación)**' : '⚠️ Medio (Lectura)')
      : '✅ Seguro';
    const shortHash = `${ep.blindHash.slice(0, 12)}...`;

    lines.push(
      `| ${statusBadge} | \`${ep.callCountObserved}\` | **${ep.method}** | \`${ep.route}\` | \`${ep.file}:${ep.startLine}-${ep.endLine}\` | ${riskBadge} | \`${shortHash}\` |`
    );
  }

  lines.push('', '---', '');

  if (zombieList.length > 0) {
    lines.push(
      '## 🧟 Detalle de Código Zombi Candidato a Poda',
      '',
      'Los siguientes bloques de código no registraron tráfico legítimo durante el período de observación y representan superficie de ataque innecesaria:',
      ''
    );

    for (const z of zombieList) {
      lines.push(
        `### 🔴 \`${z.method}${z.route}\` — \`${z.file}\` (Líneas ${z.startLine}–${z.endLine})`,
        '',
        '```typescript',
        ...z.codeSnippet.map((line, idx) => `${String(z.startLine + idx).padStart(4, ' ')} | ${line}`),
        '```',
        ''
      );
    }

    lines.push(
      '---',
      '',
      '## 🛠️ Guía de Mitigación Segura (No Destructiva)',
      '',
      '1. **Limpieza Interactiva con Respaldo Automático (`.aegis.bak`):**',
      '   ```bash',
      '   npm run prune',
      '   # o directamente: npx aegis-trace --prune',
      '   ```',
      '2. **Reversión Instantánea (Roll-back en 1 clic):**',
      '   Si necesitas restaurar todos los archivos intervenidos a su estado exacto original:',
      '   ```bash',
      '   npm run restore',
      '   # o directamente: npx aegis-trace --restore',
      '   ```',
      ''
    );
  } else {
    lines.push(
      '## ✅ Superficie de Ataque Óptima',
      '',
      'No se detectaron endpoints zombi en este escaneo. Todas las rutas declaradas registran actividad verificada.',
      ''
    );
  }

  lines.push(
    '---',
    '*Audited with Zero-Knowledge Blind Indexing by **AegisTrace CLI**.*'
  );

  fs.writeFileSync(resolvedPath, lines.join('\n'), 'utf8');
  console.log(`✔ Reporte Markdown guardado en: ${resolvedPath}`);
}