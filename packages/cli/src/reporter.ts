import * as fs from 'fs';
import * as path from 'path';
import { createHash } from 'crypto';
import { AnalyzedRoute, RetirementState } from './analyzer';

export interface NodeSlice {
  calls: number;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface ShadowApiEntry {
  hash: string;
  calls: number;
  firstSeenAt: string;
  lastSeenAt: string;
  observedSpanDays: number;
  observedNodesCount: number;
  nodeBreakdown: Record<string, NodeSlice>;
  statusCodes: Record<string, number>;
  owaspMapping: string;
}

export interface TelemetryContext {
  telemetrySourceClassification?: string;
  environment: string;
  nodeCount: number;
  expectedMinNodes: number;
  nodeCoverageVerified: boolean;
  observationDays: number;
  minRequiredDays: number;
  observationWindowVerified: boolean;
  observationStartedAt: string | null;
  reactivationEventsCount: number;
  shadowApis: ShadowApiEntry[];
}

export interface EvaluatedRoute extends AnalyzedRoute {
  hits: number;
  state: RetirementState;
  owaspLifecycleTag: string;
  owaspAuthNote: string;
  confidenceLabel: string;
  canAutoPrune: boolean;
  requiresExplicitApproval: boolean;
  autoPruneBlockers: string[];
}

export interface CanonicalAuditSummary {
  totalEndpointsScanned: number;
  activeEndpoints: number;
  exemptKeepEndpoints: number;
  lowFrequencyProtectedEndpoints: number;
  dynamicOrPluginProtectedEndpoints: number;
  stagedDeprecatedObserveOnlyEndpoints: number;
  unobservedLowConfidenceEndpoints: number;
  candidatesForManualReview: number;
  eligibleForControlledPruneWithApproval: number;
  publicEndpointsRequiringAuthReview: number;
  shadowApisDetected: number;
}

export function computeCanonicalSummary(evaluated: EvaluatedRoute[], ctx: TelemetryContext): CanonicalAuditSummary {
  return {
    totalEndpointsScanned: evaluated.length,
    activeEndpoints: evaluated.filter(r => r.state === 'ACTIVE').length,
    exemptKeepEndpoints: evaluated.filter(r => r.state === 'EXEMPT_KEEP').length,
    lowFrequencyProtectedEndpoints: evaluated.filter(r => r.state === 'LOW_FREQUENCY_PROTECTED').length,
    dynamicOrPluginProtectedEndpoints: evaluated.filter(r => r.state === 'DYNAMIC_OR_PLUGIN_PROTECTED').length,
    stagedDeprecatedObserveOnlyEndpoints: evaluated.filter(r => r.state === 'STAGE_DEPRECATED').length,
    unobservedLowConfidenceEndpoints: evaluated.filter(r => r.state === 'UNOBSERVED_LOW_CONFIDENCE').length,
    candidatesForManualReview: evaluated.filter(r => r.state === 'CANDIDATE_FOR_MANUAL_REVIEW').length,
    eligibleForControlledPruneWithApproval: evaluated.filter(r => r.canAutoPrune).length,
    publicEndpointsRequiringAuthReview: evaluated.filter(r => !r.isAuthenticated && !r.isKeepExempt).length,
    shadowApisDetected: ctx.shadowApis.length
  };
}

export function evaluateRoutesWithEvidence(
  routes: AnalyzedRoute[],
  telemetryMap: Map<string, number>,
  ctx: TelemetryContext
): EvaluatedRoute[] {
  const isSufficientWindow = ctx.observationWindowVerified && ctx.nodeCoverageVerified && ctx.environment === 'production';

  return routes.map(r => {
    const hits = telemetryMap.get(r.hash) || 0;
    const owaspAuthNote = r.isAuthenticated
      ? 'Auth Verified (' + r.authMiddlewares.join(', ') + ')'
      : 'No Auth Middleware Detected (Verify if public by design or review OWASP API2:2023)';

    if (hits > 0) {
      return {
        ...r,
        hits,
        state: 'ACTIVE',
        owaspLifecycleTag: 'INVENTORY_ACTIVE',
        owaspAuthNote,
        confidenceLabel: 'Observed in runtime (' + hits + ' hits across cluster)',
        canAutoPrune: false,
        requiresExplicitApproval: true,
        autoPruneBlockers: ['Route has active runtime traffic (' + hits + ' hits)']
      };
    }

    if (r.isKeepExempt) {
      return {
        ...r,
        hits: 0,
        state: 'EXEMPT_KEEP',
        owaspLifecycleTag: 'INVENTORY_EXEMPT_KEEP',
        owaspAuthNote,
        confidenceLabel: 'Protected by @stelfid-keep (' + (r.keepReason || 'intentional') + ')',
        canAutoPrune: false,
        requiresExplicitApproval: true,
        autoPruneBlockers: ['Protected by explicit @stelfid-keep exemption']
      };
    }

    if (r.isDeprecatedStage) {
      return {
        ...r,
        hits: 0,
        state: 'STAGE_DEPRECATED',
        owaspLifecycleTag: 'OWASP_API9_STAGED_DEPRECATION',
        owaspAuthNote,
        confidenceLabel: 'Observe-Only Canary [Sunset: ' + (r.sunsetDate || 'staged') + ' — Protected from Automated Retirement]',
        canAutoPrune: false,
        requiresExplicitApproval: true,
        autoPruneBlockers: ['Route is in Observe-Only staged deprecation (@stelfid-deprecated)']
      };
    }

    // PROTECCION DE PODA SEGURA (Punto 2): Si una ruta con 0 hits coincide con patrones de baja frecuencia
    // (webhook, callback, tarea administrativa mensual/anual), queda protegida automaticamente.
    if (r.isLowFrequencyPattern) {
      return {
        ...r,
        hits: 0,
        state: 'LOW_FREQUENCY_PROTECTED',
        owaspLifecycleTag: 'INVENTORY_LOW_FREQUENCY_PROTECTED',
        owaspAuthNote,
        confidenceLabel: 'Protected by Conservative Name Heuristic (' + r.lowFrequencyReason + ' — Name heuristic is a safety guard, NOT empirical frequency evidence)',
        canAutoPrune: false,
        requiresExplicitApproval: true,
        autoPruneBlockers: ['Low-frequency / administrative / webhook pattern protected by default']
      };
    }

    // PROTECCION DE REGRESION (Punto 1): Rutas dinamicas complejas o registradas por plugins
    if (r.hasDynamicPattern || r.prefixSource === 'plugin-registered') {
      return {
        ...r,
        hits: 0,
        state: 'DYNAMIC_OR_PLUGIN_PROTECTED',
        owaspLifecycleTag: 'INVENTORY_DYNAMIC_OR_PLUGIN_PROTECTED',
        owaspAuthNote,
        confidenceLabel: 'Protected Dynamic/Plugin Route (source=' + r.prefixSource + ' — requires manual architecture review)',
        canAutoPrune: false,
        requiresExplicitApproval: true,
        autoPruneBlockers: ['Dynamic route pattern or external plugin registration cannot be pruned automatically']
      };
    }

    if (!isSufficientWindow) {
      const blockers: string[] = [];
      if (ctx.environment !== 'production') blockers.push('Environment is ' + ctx.environment + ' (requires production)');
      if (!ctx.observationWindowVerified) blockers.push('Observed ' + ctx.observationDays.toFixed(1) + 'd < ' + ctx.minRequiredDays + 'd minimum');
      if (!ctx.nodeCoverageVerified) blockers.push('Observed ' + ctx.nodeCount + ' node(s) < ' + ctx.expectedMinNodes + ' required');

      return {
        ...r,
        hits: 0,
        state: 'UNOBSERVED_LOW_CONFIDENCE',
        owaspLifecycleTag: 'OWASP_API9_UNVERIFIED_WINDOW',
        owaspAuthNote,
        confidenceLabel: 'Unobserved [Low Confidence — ' + blockers.join('; ') + ']',
        canAutoPrune: false,
        requiresExplicitApproval: true,
        autoPruneBlockers: blockers
      };
    }

    const pruneBlockers: string[] = [];
    if (r.referencedInTests) {
      pruneBlockers.push('Referenced in test suite (requires test cleanup before retirement)');
    }
    if (r.prefixSource === 'auto-mount' || r.prefixSource === 'chained-route') {
      pruneBlockers.push('Mounted via router prefix or chained route (' + r.prefixSource + ')');
    }
    if (ctx.reactivationEventsCount > 0) {
      pruneBlockers.push('Cluster recorded ' + ctx.reactivationEventsCount + ' canary reactivation event(s)');
    }

    const canAutoPrune = pruneBlockers.length === 0;
    const extraNote = canAutoPrune
      ? '0 Observed Hits in Window — Eligible ONLY in Controlled-Prune with Backup/Approval (Absence of traffic != proof of no future need)'
      : 'Blocked from Automated Retirement (' + pruneBlockers.join('; ') + ')';

    return {
      ...r,
      hits: 0,
      state: 'CANDIDATE_FOR_MANUAL_REVIEW',
      owaspLifecycleTag: 'OWASP_API9_RETIREMENT_CANDIDATE',
      owaspAuthNote,
      confidenceLabel: 'Candidate for Manual Review [OWASP API9:2023 Inventory — ' + extraNote + ']',
      canAutoPrune,
      requiresExplicitApproval: true,
      autoPruneBlockers: pruneBlockers
    };
  });
}

export function buildCanonicalIntegrityPayload(
  evaluated: EvaluatedRoute[],
  ctx: TelemetryContext,
  summary: CanonicalAuditSummary
): string {
  return JSON.stringify({
    schemaVersion: '1.7.0-rc.1',
    environment: ctx.environment,
    nodeCount: ctx.nodeCount,
    observationDays: Number(ctx.observationDays.toFixed(4)),
    summary,
    telemetrySourceClassification: 'SYNTHETIC_OR_OBSERVED_TELEMETRY',
    executiveQuestionsAnswered: {
      q1_existingCodeInventory: {
        totalStaticRoutes: summary.totalEndpointsScanned,
        authenticatedRoutes: summary.totalEndpointsScanned - summary.publicEndpointsRequiringAuthReview,
        publicRoutesRequiringApi2Review: summary.publicEndpointsRequiringAuthReview
      },
      q2_runtimeTrafficAndShadowApis: {
        documentedActiveRoutes: summary.activeEndpoints,
        undocumentedShadowApisInRuntime: summary.shadowApisDetected
      },
      q3_safeRetirementWithRollback: {
        eligibleWithHumanApprovalAndBackup: summary.eligibleForControlledPruneWithApproval,
        protectedRoutesBlockedFromPrune: summary.exemptKeepEndpoints + summary.lowFrequencyProtectedEndpoints + summary.dynamicOrPluginProtectedEndpoints + summary.stagedDeprecatedObserveOnlyEndpoints,
        requiresApprovalManifest: true,
        supportsSha256VerifiedRollback: true
      }
    },
    endpoints: evaluated.map(r => ({
      method: r.method,
      fullRoute: r.fullRoute,
      hash: r.hash,
      hits: r.hits,
      state: r.state,
      canAutoPrune: r.canAutoPrune,
      isAuthenticated: r.isAuthenticated,
      owaspLifecycleTag: r.owaspLifecycleTag
    })),
    shadowApis: ctx.shadowApis.map(s => ({
      hash: s.hash,
      calls: s.calls,
      firstSeenAt: s.firstSeenAt,
      lastSeenAt: s.lastSeenAt,
      observedNodesCount: s.observedNodesCount
    }))
  });
}

export function printEvidenceReport(evaluated: EvaluatedRoute[], ctx: TelemetryContext): void {
  const summary = computeCanonicalSummary(evaluated, ctx);
  console.log('\n================================================================================');
  console.log(' MAIESTOR STELFID - API Route Evidence & Retirement Auditor (v1.7.0-rc.1)');
  console.log(' "Guiding API surface retirement with verifiable runtime evidence"');
  console.log('================================================================================');
  console.log(
    ' Telemetry Context : Env=' + ctx.environment.toUpperCase() +
    ' | Nodes=' + ctx.nodeCount + ' (Verified=' + ctx.nodeCoverageVerified + ')' +
    ' | Observed=' + ctx.observationDays.toFixed(1) + 'd (Min=' + ctx.minRequiredDays + 'd, Verified=' + ctx.observationWindowVerified + ')' +
    ' | Shadow APIs=' + ctx.shadowApis.length
  );
  console.log('--------------------------------------------------------------------------------\n');

  for (const r of evaluated) {
    const mountTag = r.prefixSource !== 'direct' ? ' [' + r.prefixSource + ']' : '';
    if (r.state === 'ACTIVE') {
      console.log(' [ACTIVE]            ' + r.method.padEnd(6) + ' ' + (r.fullRoute + mountTag).padEnd(45) + ' -> ' + r.hits + ' hits | ' + r.owaspAuthNote);
    } else if (r.state === 'EXEMPT_KEEP') {
      console.log(' [KEEP/EXEMPT]       ' + r.method.padEnd(6) + ' ' + (r.fullRoute + mountTag).padEnd(45) + ' -> Exempt: ' + r.keepReason + ' | ' + r.owaspAuthNote);
    } else if (r.state === 'LOW_FREQUENCY_PROTECTED') {
      console.log(' [LOW-FREQ GUARD]    ' + r.method.padEnd(6) + ' ' + (r.fullRoute + mountTag).padEnd(45) + ' -> 0 hits | Protected (Webhook/Admin/Scheduled)');
    } else if (r.state === 'DYNAMIC_OR_PLUGIN_PROTECTED') {
      console.log(' [PLUGIN/DYN GUARD]  ' + r.method.padEnd(6) + ' ' + (r.fullRoute + mountTag).padEnd(45) + ' -> 0 hits | Protected (' + r.prefixSource + ')');
    } else if (r.state === 'STAGE_DEPRECATED') {
      console.log(' [OBSERVE-ONLY]      ' + r.method.padEnd(6) + ' ' + (r.fullRoute + mountTag).padEnd(45) + ' -> 0 hits | ' + r.confidenceLabel);
    } else if (r.state === 'UNOBSERVED_LOW_CONFIDENCE') {
      console.log(' [UNOBSERVED]        ' + r.method.padEnd(6) + ' ' + (r.fullRoute + mountTag).padEnd(45) + ' -> 0 hits | ' + r.confidenceLabel);
    } else {
      console.log(' [MANUAL REVIEW]     ' + r.method.padEnd(6) + ' ' + (r.fullRoute + mountTag).padEnd(45) + ' -> 0 hits | ControlledPruneEligible=' + r.canAutoPrune);
      console.log('    +- Evidence    : ' + r.confidenceLabel + ' (Line ' + r.line + ')');
      console.log('    +- Auth Check  : ' + r.owaspAuthNote);
    }
  }

  if (ctx.shadowApis.length > 0) {
    console.log('\n--------------------------------------------------------------------------------');
    console.log(' [SHADOW APIs DETECTED IN RUNTIME — OWASP API9:2023 IMPROPER INVENTORY]:');
    for (const s of ctx.shadowApis) {
      const codes = Object.entries(s.statusCodes).map(([k, v]) => k + ':' + v).join(', ');
      const nodesDesc = Object.entries(s.nodeBreakdown).map(([n, d]) => n + '=' + d.calls).join(', ');
      console.log(' [SHADOW API]        Hash=' + s.hash.slice(0, 16) + '... -> ' + s.calls + ' hits (HTTP ' + codes + ') | Nodes=' + s.observedNodesCount + ' (' + nodesDesc + ')');
      console.log('    +- Temporal    : FirstSeen=' + s.firstSeenAt + ' | LastSeen=' + s.lastSeenAt + ' | Span=' + s.observedSpanDays.toFixed(2) + ' days');
    }
  }

  console.log('\n--------------------------------------------------------------------------------');
  const protectedCount = summary.exemptKeepEndpoints + summary.lowFrequencyProtectedEndpoints + summary.dynamicOrPluginProtectedEndpoints + summary.stagedDeprecatedObserveOnlyEndpoints;
  console.log(' MAIESTOR STELFID — 3 CORE EXECUTIVE ANSWERS:');
  console.log(`   1. What endpoints actually exist in code?        : ${summary.totalEndpointsScanned} static routes scanned (${summary.totalEndpointsScanned - summary.publicEndpointsRequiringAuthReview} auth-guarded, ${summary.publicEndpointsRequiringAuthReview} public/review OWASP API2)`);
  console.log(`   2. Which receive traffic (including undocumented)?: ${summary.activeEndpoints} documented active in runtime + ${summary.shadowApisDetected} undocumented Shadow API(s) (OWASP API9)`);
  console.log(`   3. What can be retired safely with rollback?     : ${summary.eligibleForControlledPruneWithApproval} eligible for approved retirement (w/ SHA-256 backup & --rollback) | ${protectedCount} protected from retirement`);
  console.log('--------------------------------------------------------------------------------');
  console.log(' CANONICAL EVIDENCE SUMMARY (v1.7.0-rc.1 — Safe Gradual Rollout):');
  console.log('    * Total Static Endpoints Scanned               : ' + summary.totalEndpointsScanned);
  console.log('    * Active in Runtime                            : ' + summary.activeEndpoints);
  console.log('    * Intentional / Exempt (@keep)                 : ' + summary.exemptKeepEndpoints);
  console.log('    * Low-Frequency Protected (Webhook/Admin/Cron) : ' + summary.lowFrequencyProtectedEndpoints);
  console.log('    * Dynamic / Plugin Protected                   : ' + summary.dynamicOrPluginProtectedEndpoints);
  console.log('    * Staged Deprecation (Observe-Only)            : ' + summary.stagedDeprecatedObserveOnlyEndpoints);
  console.log('    * Candidates for Manual Review (0 hits)        : ' + summary.candidatesForManualReview);
  console.log('    * Eligible for Controlled Prune (w/ Approval)  : ' + summary.eligibleForControlledPruneWithApproval);
  console.log('    * Public Endpoints (Verify Auth / API2)        : ' + summary.publicEndpointsRequiringAuthReview);
  console.log('    * Shadow APIs in Runtime (OWASP API9)          : ' + summary.shadowApisDetected);
  console.log('================================================================================\n');
}

export function exportAuditEvidenceFile(
  outputSpec: string,
  evaluated: EvaluatedRoute[],
  ctx: TelemetryContext
): string[] {
  const generatedAt = new Date().toISOString();
  const bt = String.fromCharCode(96);
  const summary = computeCanonicalSummary(evaluated, ctx);
  const canonicalPayload = buildCanonicalIntegrityPayload(evaluated, ctx, summary);
  const integritySha256 = createHash('sha256').update(canonicalPayload, 'utf8').digest('hex');

  const integrityVerificationSpec = {
    algorithm: 'SHA-256',
    digestHex: integritySha256,
    canonicalInputField: 'canonicalIntegrityPayload',
    howToVerifyCommand: "node -e \"const crypto=require('crypto'),fs=require('fs'),r=JSON.parse(fs.readFileSync('STELFID_AUDIT_EVIDENCE.json','utf8'));console.log(crypto.createHash('sha256').update(JSON.stringify(r.canonicalIntegrityPayload),'utf8').digest('hex')===r.integritySha256 ? 'VALID_INTEGRITY' : 'TAMPERED');\"",
    trustBoundaryNotice: 'This SHA-256 digest guarantees post-generation data integrity. It does NOT prove creator identity; sign in CI with Sigstore/GPG for provenance.',
    semanticWarning: 'IMPORTANT: Zero observed hits in a verified window demonstrates absence of observed traffic under those conditions; it does NOT automatically prove absence of external dependencies or future business need.',
    liabilityAndSafetyNotice: 'OPERATOR RESPONSIBILITY NOTICE: Maiestor Stelfid provides decision-support evidence only. Heuristic path guards (/webhook, /admin, /cron) are conservative lexical filters, NOT empirical frequency proofs. Code modification requires explicit human approval (--approval-manifest) and verified local backups. The user/operator assumes full responsibility for reviewing and approving any endpoint retirement.'
  };

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
      const sarifResults: any[] = [];
      for (const r of evaluated) {
        if (r.state !== 'ACTIVE' && r.state !== 'EXEMPT_KEEP') {
          sarifResults.push({
            ruleId: 'OWASP-API9-INVENTORY-LIFECYCLE',
            level: r.state === 'CANDIDATE_FOR_MANUAL_REVIEW' ? 'warning' : 'note',
            message: { text: '[' + r.state + '] ' + r.method + ' ' + r.fullRoute + ' (hits=' + r.hits + ', controlledPruneEligible=' + r.canAutoPrune + ') — ' + r.confidenceLabel },
            properties: { state: r.state, hits: r.hits, canAutoPrune: r.canAutoPrune, owaspLifecycleTag: r.owaspLifecycleTag },
            locations: [{
              physicalLocation: {
                artifactLocation: { uri: path.relative(process.cwd(), r.file).replace(/\\\\/g, '/') },
                region: { startLine: r.line, endLine: r.endLine }
              }
            }]
          });
        }
        if (!r.isAuthenticated && !r.isKeepExempt) {
          sarifResults.push({
            ruleId: 'OWASP-API2-AUTH-COVERAGE-REVIEW',
            level: 'note',
            message: { text: '[AUTH_REVIEW] ' + r.method + ' ' + r.fullRoute + ' — ' + r.owaspAuthNote },
            properties: { state: r.state, isAuthenticated: false },
            locations: [{
              physicalLocation: {
                artifactLocation: { uri: path.relative(process.cwd(), r.file).replace(/\\\\/g, '/') },
                region: { startLine: r.line, endLine: r.endLine }
              }
            }]
          });
        }
      }
      for (const s of ctx.shadowApis) {
        sarifResults.push({
          ruleId: 'OWASP-API9-SHADOW-ENDPOINT',
          level: 'warning',
          message: { text: '[SHADOW_API] BlindHash=' + s.hash + ' observed ' + s.calls + ' hits across ' + s.observedNodesCount + ' node(s) over ' + s.observedSpanDays.toFixed(2) + ' days' },
          properties: { state: 'SHADOW_API', calls: s.calls, firstSeenAt: s.firstSeenAt, lastSeenAt: s.lastSeenAt, observedSpanDays: s.observedSpanDays }
        });
      }
      const sarifReport = {
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        version: '2.1.0',
        properties: { integritySha256, integrityVerification: integrityVerificationSpec, summary },
        runs: [{
          tool: {
            driver: {
              name: 'Maiestor Stelfid',
              version: '1.7.0-rc.1',
              informationUri: 'https://github.com/PapiPain/maiestor-stelfid',
              rules: [
                { id: 'OWASP-API9-INVENTORY-LIFECYCLE', shortDescription: { text: 'OWASP API9:2023 Improper Inventory Management' } },
                { id: 'OWASP-API2-AUTH-COVERAGE-REVIEW', shortDescription: { text: 'OWASP API2:2023 Broken Authentication Review' } },
                { id: 'OWASP-API9-SHADOW-ENDPOINT', shortDescription: { text: 'OWASP API9:2023 Undocumented Shadow API' } }
              ]
            }
          },
          results: sarifResults
        }]
      };
      fs.writeFileSync(resolvedOut, JSON.stringify(sarifReport, null, 2) + '\n', 'utf8');
      writtenFiles.push(resolvedOut);
      continue;
    }

    if (lower.endsWith('.json')) {
      const jsonReport = {
        vendor: 'Maiestor Stelfid Labs',
        engine: '@m_stelfid/cli@1.7.0-rc.1',
        generatedAt,
        integritySha256,
        integrityVerification: integrityVerificationSpec,
        canonicalIntegrityPayload: JSON.parse(canonicalPayload),
        disclaimer: integrityVerificationSpec.semanticWarning,
        telemetryContext: ctx,
        summary,
        endpoints: evaluated,
        shadowApis: ctx.shadowApis
      };
      fs.writeFileSync(resolvedOut, JSON.stringify(jsonReport, null, 2) + '\n', 'utf8');
      writtenFiles.push(resolvedOut);
      continue;
    }

    if (lower.endsWith('.csv')) {
      const csvRows = [
        'RecordType,Method,FullRouteOrBlindHash,PrefixSource,Authenticated,AuthMiddlewares,RuntimeHits,State,ControlledPruneEligible,OwaspLifecycleTag,OwaspAuthReview,FirstSeenAt,LastSeenAt,ObservedSpanDays,ObservedNodesCount,File,Line,ConfidenceEvidence'
      ];
      for (const r of evaluated) {
        const safeEvidence = '"' + r.confidenceLabel.replace(/"/g, '""') + '"';
        const safeAuth = '"' + r.authMiddlewares.join(';') + '"';
        const safeAuthNote = '"' + r.owaspAuthNote.replace(/"/g, '""') + '"';
        csvRows.push([
          'STATIC_ENDPOINT',
          r.method,
          r.fullRoute,
          r.prefixSource,
          r.isAuthenticated,
          safeAuth,
          r.hits,
          r.state,
          r.canAutoPrune,
          r.owaspLifecycleTag,
          safeAuthNote,
          ctx.observationStartedAt || '',
          '',
          ctx.observationDays.toFixed(2),
          ctx.nodeCount,
          path.relative(process.cwd(), r.file).replace(/\\\\/g, '/'),
          r.line,
          safeEvidence
        ].join(','));
      }
      for (const s of ctx.shadowApis) {
        csvRows.push([
          'SHADOW_API',
          'RUNTIME',
          'BLIND_HASH:' + s.hash,
          'runtime-only',
          'unknown',
          '""',
          s.calls,
          'SHADOW_API',
          'false',
          s.owaspMapping,
          '"Verify undocumented runtime route"',
          s.firstSeenAt,
          s.lastSeenAt,
          s.observedSpanDays.toFixed(2),
          s.observedNodesCount,
          'runtime-untracked',
          0,
          '"Active in runtime (<400 HTTP) across ' + s.observedNodesCount + ' nodes over ' + s.observedSpanDays.toFixed(2) + ' days"'
        ].join(','));
      }
      fs.writeFileSync(resolvedOut, csvRows.join('\n') + '\n', 'utf8');
      writtenFiles.push(resolvedOut);
      continue;
    }

    const mdLines: string[] = [
      '# Maiestor Stelfid (v1.7.0-rc.1) - API Surface & Retirement Evidence Report',
      '',
      '> **Critical Safety Notice:** ' + integrityVerificationSpec.semanticWarning,
      '',
      '- **Generated At:** ' + bt + generatedAt + bt,
      '- **Engine Version:** ' + bt + '@m_stelfid/cli@1.7.0-rc.1' + bt,
      '- **Environment & Node Coverage:** ' + bt + ctx.environment.toUpperCase() + bt + ' (' + bt + ctx.nodeCount + ' nodes' + bt + ', Coverage Verified: ' + bt + ctx.nodeCoverageVerified + bt + ')',
      '- **Observation Window:** ' + bt + ctx.observationDays.toFixed(2) + ' days' + bt + ' (Min threshold: ' + bt + ctx.minRequiredDays + ' days' + bt + ', Window Verified: ' + bt + ctx.observationWindowVerified + bt + ')',
      '- **Canonical Payload Integrity (SHA-256):** ' + bt + integritySha256 + bt,
      '',
      '## 1. Canonical Summary (Identical Across MD, JSON, CSV, SARIF)',
      '',
      '| Metric | Count |',
      '| :--- | :--- |',
      '| **Total Static Endpoints Scanned** | ' + bt + summary.totalEndpointsScanned + bt + ' |',
      '| **Active in Runtime** | ' + bt + summary.activeEndpoints + bt + ' |',
      '| **Intentional / Exempt (`@stelfid-keep`)** | ' + bt + summary.exemptKeepEndpoints + bt + ' |',
      '| **Low-Frequency Protected (Webhook/Admin/Scheduled)** | ' + bt + summary.lowFrequencyProtectedEndpoints + bt + ' |',
      '| **Dynamic / Plugin Protected** | ' + bt + summary.dynamicOrPluginProtectedEndpoints + bt + ' |',
      '| **Staged Deprecation (`Observe-Only`)** | ' + bt + summary.stagedDeprecatedObserveOnlyEndpoints + bt + ' |',
      '| **Candidates for Manual Review (`0 hits`)** | ' + bt + summary.candidatesForManualReview + bt + ' |',
      '| **Eligible for Controlled Prune (Requires Approval & Backup)** | ' + bt + summary.eligibleForControlledPruneWithApproval + bt + ' |',
      '| **Public Endpoints (Auth Review `OWASP API2:2023`)** | ' + bt + summary.publicEndpointsRequiringAuthReview + bt + ' |',
      '| **Shadow APIs in Runtime (`OWASP API9:2023`)** | ' + bt + summary.shadowApisDetected + bt + ' |'
    ];
    fs.writeFileSync(resolvedOut, mdLines.join('\n') + '\n', 'utf8');
    writtenFiles.push(resolvedOut);
  }
  return writtenFiles;
}
