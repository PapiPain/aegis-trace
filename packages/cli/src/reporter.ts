import * as fs from 'fs';
import * as path from 'path';
import { RouteEntry } from './analyzer';

export interface AuditReportData {
  metadata: {
    tool: string;
    version: string;
    generatedAt: string;
    targetDirectory: string;
    apiKey: string;
  };
  summary: {
    totalDeclaredEndpoints: number;
    activeEndpoints: number;
    zombieEndpoints: number;
    attackSurfaceReductionPercentage: number;
  };
  endpoints: Array<{
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
  }>;
}

export function generateJsonReport(
  data: AuditReportData,
  outputPath: string
): void {
  const resolvedPath = path.resolve(process.cwd(), outputPath);
  fs.writeFileSync(resolvedPath, JSON.stringify(data, null, 2), 'utf8');
  console.log(`✔ Reporte JSON detallado guardado en: ${resolvedPath}`);
}

export function generateMarkdownReport(
  data: AuditReportData,
  outputPath: string
): void {
  const resolvedPath = path.resolve(process.cwd(), outputPath);

  const lines: string[] = [
    `# AegisTrace — Reporte de Auditoría de Código Muerto`,
    ``,
    `> **Fecha de generación:** ${data.metadata.generatedAt}  `,
    `> **Directorio analizado:** \`${data.metadata.targetDirectory}\`  `,
    `> **Herramienta:** ${data.metadata.tool} v${data.metadata.version}`,
    ``,
    `---`,
    ``,
    `## Resumen Ejecutivo de Superficie de Ataque`,
    ``,
    `| Métrica | Valor |`,
    `| :--- | :--- |`,
    `| **Total de rutas declaradas** | \`${data.summary.totalDeclaredEndpoints}\` |`,
    `| **Rutas activas (con telemetría)** | \`${data.summary.activeEndpoints}\` |`,
    `| **Rutas zombi (sin tráfico)** | \`${data.summary.zombieEndpoints}\` |`,
    `| **Reducción potencial de superficie** | **${data.summary.attackSurfaceReductionPercentage}%** |`,
    ``,
    `---`,
    ``,
    `## Desglose de Rutas Auditadas`,
    ``,
    `| Estado | Método | Ruta | Archivo:Línea | Blind Hash (HMAC) |`,
    `| :--- | :--- | :--- | :--- | :--- |`
  ];

  for (const ep of data.endpoints) {
    const badge = ep.status === 'ACTIVE' ? '🟢 ACTIVA' : '🔴 ZOMBI';
    lines.push(
      `| ${badge} | \`${ep.method}\` | \`${ep.route}\` | \`${ep.file}:${ep.startLine}\` | \`${ep.blindHash.slice(0, 12)}...\` |`
    );
  }

  lines.push(``, `---`, `## Detalle de Código Zombi para Mitigación`, ``);

  const zombies = data.endpoints.filter(e => e.status === 'ZOMBIE');
  if (zombies.length === 0) {
    lines.push(`No se encontraron endpoints zombi. La superficie de ataque está limpia.`);
  } else {
    for (const z of zombies) {
      lines.push(
        `### \`${z.method} ${z.route}\` (\`${z.file}:${z.startLine}-${z.endLine}\`)`,
        ``,
        `\`\`\`typescript`,
        ...z.codeSnippet,
        `\`\`\``,
        ``
      );
    }
  }

  lines.push(
    `---`,
    `*Reporte generado de forma no destructiva mediante Zero-Knowledge Blind Matching.*`
  );

  fs.writeFileSync(resolvedPath, lines.join('\n'), 'utf8');
  console.log(`✔ Reporte Markdown guardado en: ${resolvedPath}`);
}