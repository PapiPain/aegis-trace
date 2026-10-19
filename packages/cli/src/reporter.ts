import { AnalyzedRoute, RetirementState } from './analyzer';

export interface TelemetryContext {
  environment: string;
  observationDays: number;
  minRequiredDays: number;
  observationStartedAt: string | null;
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

    if (!isSufficientWindow) {
      const reason = ctx.environment !== 'production'
        ? 'Env: ' + ctx.environment + ' (' + ctx.observationDays.toFixed(1) + 'd observed)'
        : 'Short window: ' + ctx.observationDays.toFixed(1) + 'd / ' + ctx.minRequiredDays + 'd required';
      return {
        ...r,
        hits: 0,
        state: 'UNOBSERVED_LOW_CONFIDENCE',
        confidenceLabel: 'Unobserved [Low Retirement Confidence — ' + reason + ']',
        canAutoPrune: false
      };
    }

    if (r.isAuthenticated) {
      return {
        ...r,
        hits: 0,
        state: 'CANDIDATE_PROTECTED',
        confidenceLabel: 'Retirement Candidate [High Confidence · Auth: ' + r.authMiddlewares.join(',') + ']',
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
  console.log(' 🏛️  MAIESTOR STELFID — API Route Evidence & Retirement Auditor (v1.4.0)');
  console.log('     "Guiding API surface retirement with verifiable runtime evidence"');
  console.log('================================================================================');
  console.log(
    ' Telemetry Context : Env=' + ctx.environment.toUpperCase() +
    ' | Observed=' + ctx.observationDays.toFixed(1) + ' days' +
    ' (Min threshold for safe retirement: ' + ctx.minRequiredDays + ' days)'
  );
  console.log('--------------------------------------------------------------------------------\n');

  for (const r of evaluated) {
    const authTag = r.isAuthenticated ? '🔒 Auth (' + r.authMiddlewares.join(',') + ')' : '🔓 Public (No Auth)';
    const testTag = r.referencedInTests ? ' | 🧪 Referenced in Tests' : '';

    if (r.state === 'ACTIVE') {
      console.log(' 🟢 [ACTIVE]      ' + r.method.padEnd(6) + ' ' + r.fullRoute.padEnd(32) + ' -> ' + r.hits + ' hits | ' + authTag);
    } else if (r.state === 'EXEMPT_KEEP') {
      console.log(' 📌 [KEEP/EXEMPT] ' + r.method.padEnd(6) + ' ' + r.fullRoute.padEnd(32) + ' -> Exempt: ' + r.keepReason);
    } else if (r.state === 'UNOBSERVED_LOW_CONFIDENCE') {
      const riskNote = r.isAuthenticated ? authTag : '⚠️ Unauthenticated (Review OWASP API9)';
      console.log(' 🟡 [UNOBSERVED]  ' + r.method.padEnd(6) + ' ' + r.fullRoute.padEnd(32) + ' -> 0 hits | ' + riskNote + testTag);
      console.log('    └─ Evidence   : ' + r.confidenceLabel + ' (Line ' + r.line + ')');
    } else if (r.state === 'CANDIDATE_PROTECTED') {
      console.log(' 🔴 [CANDIDATE]   ' + r.method.padEnd(6) + ' ' + r.fullRoute.padEnd(32) + ' -> 0 hits | ' + authTag + testTag);
      console.log('    └─ Evidence   : ' + r.confidenceLabel + ' (Line ' + r.line + ')');
    } else {
      console.log(' 🚨 [CRITICAL]    ' + r.method.padEnd(6) + ' ' + r.fullRoute.padEnd(32) + ' -> 0 hits | ' + authTag + testTag);
      console.log('    └─ Evidence   : ' + r.confidenceLabel + ' (Line ' + r.line + ')');
    }
  }

  const activeCount = evaluated.filter(r => r.state === 'ACTIVE').length;
  const exemptCount = evaluated.filter(r => r.state === 'EXEMPT_KEEP').length;
  const unobservedCount = evaluated.filter(r => r.state === 'UNOBSERVED_LOW_CONFIDENCE').length;
  const candidateCount = evaluated.filter(r => r.state === 'CANDIDATE_PROTECTED' || r.state === 'CANDIDATE_UNAUTHENTICATED').length;
  const unauthZeroHits = evaluated.filter(r => r.hits === 0 && !r.isAuthenticated && !r.isKeepExempt).length;

  console.log('\n--------------------------------------------------------------------------------');
  console.log(' 📊 EVIDENCE SUMMARY:');
  console.log('    • Total Endpoints Scanned         : ' + evaluated.length);
  console.log('    • 🟢 Active in Runtime            : ' + activeCount);
  console.log('    • 📌 Intentional / Exempt (@keep) : ' + exemptCount);
  console.log('    • 🟡 Unobserved (Needs More Data) : ' + unobservedCount);
  console.log('    • 🔴 Verified Retirement Ready    : ' + candidateCount);
  console.log('    • 🚨 Unauthenticated w/ 0 Hits    : ' + unauthZeroHits);
  console.log('================================================================================\n');
}
