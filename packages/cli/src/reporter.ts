import * as fs from 'fs';
import * as path from 'path';
import { createHash } from 'crypto';
import { AnalyzedRoute, RetirementState } from './analyzer';

export interface TelemetryContext {
  environment: string;
  observationDays: number;
  minRequiredDays: number;
  observationStartedAt: string | null;
  reactivationEventsCount: number;
}

export interface EvaluatedRoute extends AnalyzedRoute {
  hits: number;
  state: RetirementState;
  confidenceLabel: string;
  canAutoPrune: boolean;
}

export function evaluateRoutesWithEvidence(
  routes: AnalyzedRoute[],
  telemetryMap: Map<string, number>,
  ctx: TelemetryContext
): EvaluatedRoute[] {
  const isSufficientWindow = ctx.observationDays >= ctx.minRequiredDays && ctx.environment === 'production';

  return routes.map(r => {
    const hits = telemetryMap.get(r.hash) || 0;
    if (hits > 0) {
      return {
        ...r,
        hits,
        state: 'ACTIVE',
        confidenceLabel: 'Observed in runtime (' + hits + ' hits)',
        canAutoPrune: false
      };
    }
    if (r.isKeepExempt) {
      return {
        ...r,
        hits: 0,
        state: 'EXEMPT_KEEP',
        confidenceLabel: 'Protected by @stelfid-keep (' + (r.keepReason || 'intentional') + ')',
        canAutoPrune: false
      };
    }
    if (r.isDeprecatedStage) {
      return {
        ...r,
        hits: 0,
        state: 'STAGE_DEPRECATED',
        confidenceLabel: 'Staged Deprecation [Observe-Only Canary / Sunset: ' + (r.sunsetDate || 'active') + ']',
        canAutoPrune: isSufficientWindow
      };
    }
    if (!isSufficientWindow) {
      const reason = ctx.environment !== 'production'
        ? 'Env: ' + ctx.environment + ' (' + ctx.observationDays.toFixed(1) + 'd observed)'
        : 'Short window: ' + ctx.observationDays.toFixed(1) + 'd / ' + ctx.minRequiredDays + 'd required';
      return {
        ...r,
        hits: 0,
        state: 'UNOBSERVED_LOW_CONFIDENCE',
        confidenceLabel: 'Unobserved [Low Retirement Confidence - ' + reason + ']',
        canAutoPrune: false
      };
    }
    if (r.isAuthenticated) {
      return {
        ...r,
        hits: 0,
        state: 'CANDIDATE_PROTECTED',
        confidenceLabel: 'Retirement Candidate [High Confidence / Auth: ' + r.authMiddlewares.join(',') + ']',
        canAutoPrune: true
      };
    }
    return {
      ...r,
      hits: 0,
      state: 'CANDIDATE_UNAUTHENTICATED',
      confidenceLabel: 'CRITICAL Unauthenticated Retirement Candidate [OWASP API9:2023]',
      canAutoPrune: true
    };
  });
}

export function printEvidenceReport(evaluated: EvaluatedRoute[], ctx: TelemetryContext): void {
  console.log('\n================================================================================');
  console.log(' MAIESTOR STELFID - API Route Evidence & Retirement Auditor (v1.5.0)');
  console.log(' "Guiding API surface retirement with verifiable runtime evidence"');
  console.log('================================================================================');
  console.log(
    ' Telemetry Context : Env=' + ctx.environment.toUpperCase() +
    ' | Observed=' + ctx.observationDays.toFixed(1) + ' days' +
    ' (Min threshold: ' + ctx.minRequiredDays + 'd)' +
    ' | Canary Reactivations=' + ctx.reactivationEventsCount
  );
  console.log('--------------------------------------------------------------------------------\n');

  for (const r of evaluated) {
    const authTag = r.isAuthenticated ? 'Auth (' + r.authMiddlewares.join(',') + ')' : 'Public (No Auth)';
    const testTag = r.referencedInTests ? ' | Referenced in Tests' : '';
    const mountTag = r.prefixSource === 'auto-mount' ? ' [Auto-Mount]' : '';

    if (r.state === 'ACTIVE') {
      console.log(' [ACTIVE]      ' + r.method.padEnd(6) + ' ' + (r.fullRoute + mountTag).padEnd(45) + ' -> ' + r.hits + ' hits | ' + authTag);
    } else if (r.state === 'EXEMPT_KEEP') {
      console.log(' [KEEP/EXEMPT] ' + r.method.padEnd(6) + ' ' + (r.fullRoute + mountTag).padEnd(45) + ' -> Exempt: ' + r.keepReason + ' | ' + authTag);
    } else if (r.state === 'STAGE_DEPRECATED') {
      console.log(' [DEPRECATED]  ' + r.method.padEnd(6) + ' ' + (r.fullRoute + mountTag).padEnd(45) + ' -> 0 hits | ' + r.confidenceLabel);
    } else if (r.state === 'UNOBSERVED_LOW_CONFIDENCE') {
      const riskNote = r.isAuthenticated ? authTag : 'Unauthenticated (Review OWASP API9)';
      console.log(' [UNOBSERVED]  ' + r.method.padEnd(6) + ' ' + (r.fullRoute + mountTag).padEnd(45) + ' -> 0 hits | ' + riskNote + testTag);
      console.log('    +- Evidence: ' + r.confidenceLabel + ' (Line ' + r.line + ')');
    } else if (r.state === 'CANDIDATE_PROTECTED') {
      console.log(' [CANDIDATE]   ' + r.method.padEnd(6) + ' ' + (r.fullRoute + mountTag).padEnd(45) + ' -> 0 hits | ' + authTag + testTag);
      console.log('    +- Evidence: ' + r.confidenceLabel + ' (Line ' + r.line + ')');
    } else {
      console.log(' [CRITICAL]    ' + r.method.padEnd(6) + ' ' + (r.fullRoute + mountTag).padEnd(45) + ' -> 0 hits | ' + authTag + testTag);
      console.log('    +- Evidence: ' + r.confidenceLabel + ' (Line ' + r.line + ')');
    }
  }

  const activeCount = evaluated.filter(r => r.state === 'ACTIVE').length;
  const exemptCount = evaluated.filter(r => r.state === 'EXEMPT_KEEP').length;
  const deprecatedCount = evaluated.filter(r => r.state === 'STAGE_DEPRECATED').length;
  const unobservedCount = evaluated.filter(r => r.state === 'UNOBSERVED_LOW_CONFIDENCE').length;
  const candidateCount = evaluated.filter(r => r.state === 'CANDIDATE_PROTECTED' || r.state === 'CANDIDATE_UNAUTHENTICATED').length;
  const unauthZeroHits = evaluated.filter(r => r.hits === 0 && !r.isAuthenticated && !r.isKeepExempt).length;

  console.log('\n--------------------------------------------------------------------------------');
  console.log(' EVIDENCE SUMMARY:');
  console.log('    * Total Endpoints Scanned         : ' + evaluated.length);
  console.log('    * Active in Runtime               : ' + activeCount);
  console.log('    * Intentional / Exempt (@keep)    : ' + exemptCount);
  console.log('    * Staged Deprecation (@deprecated): ' + deprecatedCount);
  console.log('    * Unobserved (Needs More Data)    : ' + unobservedCount);
  console.log('    * Verified Retirement Ready       : ' + candidateCount);
  console.log('    * Unauthenticated w/ 0 Hits       : ' + unauthZeroHits);
  console.log('================================================================================\n');
}

export function exportAuditEvidenceFile(
  outputSpec: string,
  evaluated: EvaluatedRoute[],
  ctx: TelemetryContext
): string[] {
  const generatedAt = new Date().toISOString();
  const bt = String.fromCharCode(96);
  const payloadForDigest = JSON.stringify({
    generatedAt,
    context: ctx,
    routes: evaluated.map(r => ({
      method: r.method,
      fullRoute: r.fullRoute,
      hash: r.hash,
      hits: r.hits,
      state: r.state,
      isAuthenticated: r.isAuthenticated
    }))
  });
  const integritySha256 = createHash('sha256').update(payloadForDigest).digest('hex');

  // Si el usuario pasa 'all' o separa por comas, o pasa un nombre base, resolvemos los destinos
  let targets: string[] = [];
  if (outputSpec.toLowerCase() === 'all' || outputSpec.toLowerCase() === 'both') {
    targets = [
      'STELFID_AUDIT_EVIDENCE.md',
      'STELFID_AUDIT_EVIDENCE.json',
      'STELFID_AUDIT_EVIDENCE.csv',
      'STELFID_AUDIT_EVIDENCE.sarif.json'
    ];
  } else if (outputSpec.includes(',')) {
    targets = outputSpec.split(',').map(s => s.trim()).filter(Boolean);
  } else {
    targets = [outputSpec.trim()];
  }

  const writtenFiles: string[] = [];

  for (const target of targets) {
    const resolvedOut = path.resolve(target);
    const lower = resolvedOut.toLowerCase();

    if (lower.endsWith('.sarif') || lower.endsWith('.sarif.json')) {
      // Formato estandar SARIF 2.1.0 para GitHub Code Scanning / IDE Security Tabs
      const sarifReport = {
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        version: '2.1.0',
        runs: [
          {
            tool: {
              driver: {
                name: 'Maiestor Stelfid',
                version: '1.5.0',
                informationUri: 'https://github.com/PapiPain/maiestor-stelfid',
                rules: [
                  {
                    id: 'OWASP-API9-UNAUTH-UNOBSERVED',
                    shortDescription: { text: 'Unauthenticated & Unobserved API Route (OWASP API9:2023)' }
                  },
                  {
                    id: 'STELFID-RETIREMENT-CANDIDATE',
                    shortDescription: { text: 'Unused API Route Candidate for Safe Retirement' }
                  }
                ]
              }
            },
            results: evaluated
              .filter(r => r.hits === 0 && !r.isKeepExempt)
              .map(r => ({
                ruleId: r.isAuthenticated ? 'STELFID-RETIREMENT-CANDIDATE' : 'OWASP-API9-UNAUTH-UNOBSERVED',
                level: r.isAuthenticated ? 'note' : 'warning',
                message: { text: r.method + ' ' + r.fullRoute + ' — ' + r.confidenceLabel },
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: { uri: path.relative(process.cwd(), r.file).replace(/\\\\/g, '/') },
                      region: { startLine: r.line, endLine: r.endLine }
                    }
                  }
                ]
              }))
          }
        ]
      };
      fs.writeFileSync(resolvedOut, JSON.stringify(sarifReport, null, 2) + '\n', 'utf8');
      writtenFiles.push(resolvedOut);
      continue;
    }

    if (lower.endsWith('.json')) {
      const jsonReport = {
        vendor: 'Maiestor Stelfid Labs',
        engine: '@m_stelfid/cli@1.5.0',
        generatedAt,
        integritySha256,
        disclaimer: 'Technical API inventory and runtime telemetry evidence report to support internal security reviews and OWASP API9:2023 controls. Does not constitute automatic SOC 2 or ISO 27001 certification.',
        telemetryContext: ctx,
        summary: {
          totalEndpoints: evaluated.length,
          activeEndpoints: evaluated.filter(r => r.state === 'ACTIVE').length,
          exemptKeepEndpoints: evaluated.filter(r => r.state === 'EXEMPT_KEEP').length,
          stagedDeprecatedEndpoints: evaluated.filter(r => r.state === 'STAGE_DEPRECATED').length,
          verifiedRetirementCandidates: evaluated.filter(r => r.canAutoPrune).length,
          unauthenticatedZeroHitEndpoints: evaluated.filter(r => r.hits === 0 && !r.isAuthenticated && !r.isKeepExempt).length
        },
        endpoints: evaluated
      };
      fs.writeFileSync(resolvedOut, JSON.stringify(jsonReport, null, 2) + '\n', 'utf8');
      writtenFiles.push(resolvedOut);
      continue;
    }

    if (lower.endsWith('.csv')) {
      const csvRows = [
        'Method,FullRoute,PrefixSource,Authenticated,AuthMiddlewares,RuntimeHits,State,CanAutoPrune,File,Line,ConfidenceEvidence'
      ];
      for (const r of evaluated) {
        const safeEvidence = '"' + r.confidenceLabel.replace(/"/g, '""') + '"';
        const safeAuth = '"' + r.authMiddlewares.join(';') + '"';
        csvRows.push([
          r.method,
          r.fullRoute,
          r.prefixSource,
          r.isAuthenticated,
          safeAuth,
          r.hits,
          r.state,
          r.canAutoPrune,
          path.relative(process.cwd(), r.file).replace(/\\\\/g, '/'),
          r.line,
          safeEvidence
        ].join(','));
      }
      fs.writeFileSync(resolvedOut, csvRows.join('\n') + '\n', 'utf8');
      writtenFiles.push(resolvedOut);
      continue;
    }

    // Por defecto: Markdown (.md)
    const mdLines: string[] = [
      '# Maiestor Stelfid - API Surface & Retirement Evidence Report',
      '',
      '- **Generated At:** ' + bt + generatedAt + bt,
      '- **Engine Version:** ' + bt + '@m_stelfid/cli@1.5.0' + bt,
      '- **Environment Observed:** ' + bt + ctx.environment.toUpperCase() + bt,
      '- **Observation Window:** ' + bt + ctx.observationDays.toFixed(2) + ' days' + bt + ' (Minimum threshold: ' + bt + ctx.minRequiredDays + ' days' + bt + ')',
      '- **Evidence Integrity Digest (SHA-256):** ' + bt + integritySha256 + bt,
      '',
      '> **Scope & Compliance Notice:** This document provides technical inventory and runtime telemetry evidence to support internal engineering and security reviews (including controls related to **OWASP API9:2023 - Improper Inventory Management**). It does not by itself grant or constitute formal SOC 2 or ISO 27001 certification.',
      '',
      '## Endpoint Inventory & Retirement Confidence',
      '',
      '| Method | Full Route | Prefix Source | Auth Controls | Runtime Hits | State | Evidence & Confidence |',
      '| :--- | :--- | :--- | :--- | :--- | :--- | :--- |'
    ];

    for (const r of evaluated) {
      const authCell = r.isAuthenticated ? bt + r.authMiddlewares.join(', ') + bt : 'None (Public)';
      mdLines.push(
        '| ' + bt + r.method + bt + ' | ' + bt + r.fullRoute + bt + ' | ' + bt + r.prefixSource + bt + ' | ' +
        authCell + ' | ' + bt + r.hits + bt + ' | **' + r.state + '** | ' + r.confidenceLabel + ' |'
      );
    }

    mdLines.push('');
    mdLines.push('---');
    mdLines.push('*Generated by **Maiestor Stelfid Labs** (' + bt + '@m_stelfid/cli' + bt + ').*');

    fs.writeFileSync(resolvedOut, mdLines.join('\n') + '\n', 'utf8');
    writtenFiles.push(resolvedOut);
  }

  return writtenFiles;
}
