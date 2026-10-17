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
  isAuthenticated: boolean;
  authMiddlewares: string[];
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
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
    unauthenticatedZombieEndpoints: number;
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
  console.log(`✔ JSON report saved at: ${resolvedPath}`);
}

export function generateMarkdownReport(data: AuditReportData, outputPath: string): void {
  const resolvedPath = path.resolve(process.cwd(), outputPath);
  const { metadata, summary, endpoints } = data;

  const shadowCount = summary.shadowEndpoints ?? 0;
  const totalCalls = summary.totalObservedCalls ?? 0;
  const confidence = summary.confidenceLabel ?? 'MEDIUM (Moderate traffic sample)';
  const windowText = metadata.observationDays
    ? `Last ${metadata.observationDays} day(s)`
    : 'Full history';

  const zombieList = endpoints.filter(e => e.status === 'ZOMBIE');
  const criticalZombies = zombieList.filter(e => !e.isAuthenticated);

  const lines: string[] = [
    '# 🛡️ AegisTrace — Dead-Code & Attack Surface Audit Report',
    '',
    `> **Generated:** \`${metadata.generatedAt}\` | **Version:** \`v${metadata.version}\` | **Window:** \`${windowText}\``,
    `> **Audited Directory:** \`${metadata.targetDirectory}\``,
    `> **Compliance Mapping:** \`OWASP API9:2023 (Improper Inventory Management)\` · \`SOC2 CC6.1 (Attack Surface Reduction)\``,
    '',
    '---',
    '',
    '## 📊 Executive Attack Surface & Telemetry Summary',
    '',
    '| Security Metric | Value |',
    '| :--- | :--- |',
    `| **Total Declared Endpoints (AST)** | \`${summary.totalDeclaredEndpoints}\` |`,
    `| **Active Endpoints (With Traffic)** | \`${summary.activeEndpoints}\` (${totalCalls} total invocations) |`,
    `| **Inactive Endpoints (Zombie Code)** | \`${summary.zombieEndpoints}\` |`,
    `| **🚨 Unauthenticated Zombie Endpoints (CRITICAL)** | **\`${summary.unauthenticatedZombieEndpoints}\`** |`,
    `| **Shadow Endpoints (Undeclared Traffic)** | \`${shadowCount}\` |`,
    `| **Pruning Confidence Level** | **${confidence}** |`,
    `| **Potential Attack Surface Reduction** | **${summary.attackSurfaceReductionPercentage}%** |`,
    ''
  ];

  if (criticalZombies.length > 0) {
    lines.push(
      '### 🚨 CRITICAL SECURITY ALERT: Unauthenticated Zombie Endpoints Detected',
      `AegisTrace AST inspection identified **${criticalZombies.length} dormant endpoint(s)** with **0 production hits** that lack authentication middleware (\`JWT\`, \`Session\`, \`AuthGuard\`). Dormant unauthenticated routes are the #1 vector for **OWASP API9:2023** breaches and should be pruned or protected immediately.`,
      ''
    );
  }

  if (shadowCount > 0) {
    lines.push(
      '### ⚠️ Security Alert: Shadow Endpoints Detected',
      `Detected **${shadowCount} active telemetry hash(es)** in runtime that do not match any statically declared route in the analyzed codebase. This may be caused by dynamic middleware, hidden legacy routes, or unnormalized requests.`,
      ''
    );
  }

  lines.push(
    '---',
    '',
    '## 🗺️ Complete Endpoint Inventory & Auth Posture',
    '',
    '| Status | Hits | Method | Normalized Route | Auth Guard | Location | Risk Level | Blind Hash |',
    '| :--- | :---: | :---: | :--- | :---: | :--- | :--- | :--- |'
  );

  for (const ep of endpoints) {
    const statusBadge = ep.status === 'ACTIVE' ? '🟢 `ACTIVE`' : '🔴 `ZOMBIE`';
    const authBadge = ep.isAuthenticated
      ? `🔒 \`${ep.authMiddlewares.join(', ')}\``
      : '🔓 `NONE (Public)`';

    let riskBadge = '✅ Low (Active)';
    if (ep.riskLevel === 'CRITICAL') {
      riskBadge = '🚨 **CRITICAL (Unauth Zombie)**';
    } else if (ep.riskLevel === 'HIGH') {
      riskBadge = '🔥 **HIGH (Protected Zombie)**';
    } else if (ep.riskLevel === 'MEDIUM') {
      riskBadge = '⚠️ **MEDIUM (Public Active)**';
    }

    const shortHash = `${ep.blindHash.slice(0, 10)}...`;

    lines.push(
      `| ${statusBadge} | \`${ep.callCountObserved}\` | **${ep.method}** | \`${ep.route}\` | ${authBadge} | \`${ep.file}:${ep.startLine}-${ep.endLine}\` | ${riskBadge} | \`${shortHash}\` |`
    );
  }

  lines.push('', '---', '');

  if (zombieList.length > 0) {
    lines.push(
      '## 🧟 Zombie Code Candidates for Pruning (Unused Lines)',
      '',
      'The following code blocks registered zero legitimate runtime traffic during the observation period and represent unnecessary attack surface:',
      ''
    );

    for (const z of zombieList) {
      const authStatusText = z.isAuthenticated
        ? `🔒 Protected by \`${z.authMiddlewares.join(', ')}\``
        : `🚨 **UNAUTHENTICATED (Publicly Exposed)**`;

      lines.push(
        `### 🔴 \`${z.method}${z.route}\` — \`${z.file}\` (Lines ${z.startLine}–${z.endLine}) · ${authStatusText}`,
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
      '## 🛠️ Safe Mitigation Guide (Non-Destructive)',
      '',
      '1. **Interactive Cleanup with Automatic Backup (`.aegis.bak`):**',
      '   ```bash',
      '   npx @aegis-trace/cli --prune',
      '   ```',
      '2. **Instant Rollback (1-Click Restore):**',
      '   If you need to restore all modified files back to their exact original state:',
      '   ```bash',
      '   npx @aegis-trace/cli --restore',
      '   ```',
      ''
    );
  } else {
    lines.push(
      '## ✅ Optimal Attack Surface',
      '',
      'No zombie endpoints were detected in this scan. All declared routes show verified runtime activity.',
      ''
    );
  }

  lines.push(
    '---',
    '*Audited with Zero-Knowledge Blind Indexing by **AegisTrace SecOps CLI**.*'
  );

  fs.writeFileSync(resolvedPath, lines.join('\n'), 'utf8');
  console.log(`✔ Markdown report saved at: ${resolvedPath}`);
}
