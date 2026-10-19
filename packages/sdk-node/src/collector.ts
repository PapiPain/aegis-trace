import * as fs from 'fs';
import * as path from 'path';
import { randomUUID } from 'crypto';
import { generateBlindHash, normalizeRoute } from './crypto';

export interface DeprecatedRoutePolicy {
  method?: string;
  route: string;
  sunsetDate?: string;
  replacementRoute?: string;
  policy?: 'observe' | 'warn-header';
}

export interface DormantTouchEvent {
  hash: string;
  method: string;
  normalizedRoute: string;
  statusCode: number;
  touchedAt: string;
  environment: string;
  note: string;
}

export interface StelfidOptions {
  apiKey?: string;
  secretKey: string;
  nodeId?: string;
  environment?: 'local' | 'staging' | 'production' | string;
  flushIntervalMs?: number;
  requestTimeoutMs?: number;
  shutdownTimeoutMs?: number;
  localFilePath?: string;
  ingestUrl?: string;
  deprecatedRoutes?: DeprecatedRoutePolicy[];
  dormantHashes?: string[];
  onDormantRouteTouched?: (event: DormantTouchEvent) => void;
}

interface RouteCounter {
  calls: number;
  pendingDeltaCalls: number;
  pendingDeltaStatusCodes: Record<string, number>;
  firstSeenAt: string;
  lastSeenAt: string;
  statusCodes: Record<string, number>;
  reactivationCount: number;
  isMatchedExpressRoute: boolean;
}

export interface DeltaPayloadItem {
  hash: string;
  deltaCalls: number;
  firstSeenAt: string;
  lastSeenAt: string;
  deltaStatusCodes: Record<string, number>;
  isMatchedExpressRoute: boolean;
}

export interface DeltaBatchEnvelope {
  batchId: string;
  vendor: string;
  schemaVersion: string;
  nodeId: string;
  environment: string;
  observationStartedAt: string;
  createdAt: string;
  deltas: DeltaPayloadItem[];
  reactivationEvents: DormantTouchEvent[];
}

export interface EmpiricalSyncStats {
  flush_attempts: number;
  flush_sent_http: number;
  flush_skipped_zero_delta: number;
  http_requests_sent: number;
  batches_retried: number;
  batches_acked: number;
  idempotent_replays_acked: number;
  failed_http_responses: number;
  savings_pct: number;
  last_sync_status: string;
  acked_batch_ids: string[];
}

export async function sendBatchWithAbortTimeout(
  urlStr: string,
  apiKey: string | undefined,
  batch: DeltaBatchEnvelope,
  timeoutMs: number
): Promise<{
  ok: boolean;
  status: number;
  idempotentReplay?: boolean;
  abortedByTimeout: boolean;
  elapsedMs: number;
}> {
  const startMs = Date.now();
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Stelfid-Batch-Id': batch.batchId
    };
    if (apiKey) {
      headers['Authorization'] = 'Bearer ' + apiKey;
      headers['X-Stelfid-Key'] = apiKey;
    }
    const response = await fetch(urlStr, {
      method: 'POST',
      headers,
      body: JSON.stringify(batch),
      signal: controller.signal
    });

    const elapsedMs = Date.now() - startMs;
    if (!response.ok) {
      return { ok: false, status: response.status, abortedByTimeout: false, elapsedMs };
    }

    const data: any = await response.json().catch(() => null);
    if (!data || data.ok !== true || data.ackedBatchId !== batch.batchId) {
      return { ok: false, status: response.status, abortedByTimeout: false, elapsedMs };
    }

    return {
      ok: true,
      status: response.status,
      idempotentReplay: Boolean(data.idempotentReplay),
      abortedByTimeout: false,
      elapsedMs
    };
  } catch {
    const elapsedMs = Date.now() - startMs;
    return { ok: false, status: 0, abortedByTimeout: timedOut || controller.signal.aborted, elapsedMs };
  } finally {
    clearTimeout(timer);
  }
}

export function stelfidTelemetry(options: StelfidOptions) {
  const secretKey = options.secretKey || 'sec_secretkey_test987';
  const environment = options.environment || process.env.NODE_ENV || 'local';
  const nodeId = options.nodeId || process.env.HOSTNAME || ('node-' + process.pid);
  const flushIntervalMs = options.flushIntervalMs || 30000;
  const requestTimeoutMs = options.requestTimeoutMs || 2500;
  const shutdownTimeoutMs = options.shutdownTimeoutMs || 5000;
  const localFile = options.localFilePath || path.join(process.cwd(), '.stelfid-local.json');
  const ingestUrl = options.ingestUrl || process.env.STELFID_INGEST_URL || '';

  const deprecationMap = new Map<string, DeprecatedRoutePolicy>();
  if (Array.isArray(options.deprecatedRoutes)) {
    for (const item of options.deprecatedRoutes) {
      const m = (item.method || 'ANY').toUpperCase();
      const norm = normalizeRoute(item.route);
      deprecationMap.set(m + ':' + norm, item);
      if (!item.method) {
        for (const verb of ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']) {
          deprecationMap.set(verb + ':' + norm, item);
        }
      }
    }
  }

  const dormantSet = new Set<string>(options.dormantHashes || []);
  let observationStartedAt = new Date().toISOString();
  const memoryStore = new Map<string, RouteCounter>();
  const reactivationEvents: DormantTouchEvent[] = [];

  // Cola FIFO de lotes sellados inmutables (garantiza que un fallo post-commit reintente el MISMO batchId
  // sin mezclar ni perder los nuevos deltas que sigan entrando en pendingDeltaCalls)
  const sealedBatchQueue: DeltaBatchEnvelope[] = [];
  let isFlushing = false;
  let dirtyDisk = false;

  const syncStats: EmpiricalSyncStats = {
    flush_attempts: 0,
    flush_sent_http: 0,
    flush_skipped_zero_delta: 0,
    http_requests_sent: 0,
    batches_retried: 0,
    batches_acked: 0,
    idempotent_replays_acked: 0,
    failed_http_responses: 0,
    savings_pct: 0,
    last_sync_status: 'local-only',
    acked_batch_ids: []
  };

  // Formula exacta:
  // Ahorro (%) = (flush_skipped_zero_delta / (flush_skipped_zero_delta + flush_sent_http)) * 100
  const recomputeSavings = () => {
    const denom = syncStats.flush_skipped_zero_delta + syncStats.flush_sent_http;
    if (denom > 0) {
      syncStats.savings_pct = Number(((syncStats.flush_skipped_zero_delta / denom) * 100).toFixed(2));
    } else {
      syncStats.savings_pct = 0;
    }
  };

  if (fs.existsSync(localFile)) {
    try {
      const raw = JSON.parse(fs.readFileSync(localFile, 'utf8').replace(/^\uFEFF/, ''));
      if (raw && raw._meta) {
        if (raw._meta.observationStartedAt) observationStartedAt = raw._meta.observationStartedAt;
        if (Array.isArray(raw._meta.sealedBatchQueue)) {
          sealedBatchQueue.push(...raw._meta.sealedBatchQueue);
        }
        if (raw._meta.deltaSyncStats) {
          Object.assign(syncStats, raw._meta.deltaSyncStats);
        }
      }
      if (Array.isArray(raw.reactivationEvents)) {
        reactivationEvents.push(...raw.reactivationEvents.slice(-50));
      }
      const existingRoutes = raw.routes || raw;
      for (const [hash, data] of Object.entries(existingRoutes as Record<string, any>)) {
        if (hash === '_meta' || hash === 'reactivationEvents') continue;
        memoryStore.set(hash, {
          calls: Number(data?.calls ?? 0),
          pendingDeltaCalls: Number(data?.pendingDeltaCalls ?? 0),
          pendingDeltaStatusCodes: data?.pendingDeltaStatusCodes || {},
          firstSeenAt: data?.firstSeenAt || observationStartedAt,
          lastSeenAt: data?.lastSeenAt || data?.lastSeen || new Date().toISOString(),
          statusCodes: data?.statusCodes || {},
          reactivationCount: Number(data?.reactivationCount ?? 0),
          isMatchedExpressRoute: data?.isMatchedExpressRoute !== false
        });
      }
    } catch {
      // Fail-open
    }
  }

  const flushToDisk = () => {
    if (!dirtyDisk && fs.existsSync(localFile)) return;
    dirtyDisk = false;
    recomputeSavings();
    const nowIso = new Date().toISOString();
    const routesOut: Record<string, any> = {};

    for (const [hash, info] of memoryStore.entries()) {
      // Persistir en pendingDeltaCalls UNICAMENTE los deltas no sellados.
      // Los lotes ya sellados viven en _meta.sealedBatchQueue hasta recibir ACK valido del servidor.
      routesOut[hash] = {
        calls: info.calls,
        pendingDeltaCalls: info.pendingDeltaCalls,
        pendingDeltaStatusCodes: info.pendingDeltaStatusCodes,
        firstSeenAt: info.firstSeenAt,
        lastSeen: info.lastSeenAt,
        statusCodes: info.statusCodes,
        reactivationCount: info.reactivationCount || 0,
        isMatchedExpressRoute: info.isMatchedExpressRoute
      };
    }

    const output = {
      _meta: {
        vendor: 'Maiestor Stelfid',
        schemaVersion: '1.6.4',
        nodeId,
        environment,
        observationStartedAt,
        lastFlushedAt: nowIso,
        sealedBatchQueue,
        deltaSyncStats: syncStats
      },
      reactivationEvents: reactivationEvents.slice(-50),
      routes: routesOut
    };

    try {
      fs.writeFileSync(localFile, JSON.stringify(output, null, 2) + '\n', 'utf8');
    } catch {
      // Fail-open
    }
  };

  const sealCurrentDeltasIntoQueue = (): void => {
    const snapshotDeltas: DeltaPayloadItem[] = [];
    for (const [hash, info] of memoryStore.entries()) {
      if (info.pendingDeltaCalls > 0) {
        snapshotDeltas.push({
          hash,
          deltaCalls: info.pendingDeltaCalls,
          firstSeenAt: info.firstSeenAt,
          lastSeenAt: info.lastSeenAt,
          deltaStatusCodes: { ...info.pendingDeltaStatusCodes },
          isMatchedExpressRoute: info.isMatchedExpressRoute
        });
        info.pendingDeltaCalls = 0;
        info.pendingDeltaStatusCodes = {};
      }
    }
    if (snapshotDeltas.length > 0) {
      sealedBatchQueue.push({
        batchId: 'batch_' + randomUUID(),
        vendor: 'Maiestor Stelfid',
        schemaVersion: '1.6.4',
        nodeId,
        environment,
        observationStartedAt,
        createdAt: new Date().toISOString(),
        deltas: snapshotDeltas,
        reactivationEvents: reactivationEvents.slice(-10)
      });
    }
  };

  const flushDeltaToCloud = async (customTimeoutMs?: number): Promise<boolean> => {
    if (!ingestUrl) {
      dirtyDisk = true;
      flushToDisk();
      return false;
    }
    // Regla 5: No permitir que dos ejecuciones de flushDeltaToCloud() procesen simultaneamente
    if (isFlushing) return false;
    isFlushing = true;

    try {
      syncStats.flush_attempts += 1;
      const hadQueuedBeforeSeal = sealedBatchQueue.length > 0;

      // Empaquetar cualquier delta nuevo en un lote sellado con su propio batchId
      sealCurrentDeltasIntoQueue();

      // Persistir la cola en disco ANTES de enviar por red
      dirtyDisk = true;
      flushToDisk();

      if (sealedBatchQueue.length === 0) {
        syncStats.flush_skipped_zero_delta += 1;
        recomputeSavings();
        dirtyDisk = true;
        flushToDisk();
        return true;
      }

      syncStats.flush_sent_http += 1;
      const effectiveTimeout = customTimeoutMs || requestTimeoutMs;
      let allSucceeded = true;

      // Enviar en orden FIFO cada lote sellado pendiente
      while (sealedBatchQueue.length > 0) {
        const currentBatch = sealedBatchQueue[0];
        if (hadQueuedBeforeSeal) {
          syncStats.batches_retried += 1;
        }
        syncStats.http_requests_sent += 1;

        const result = await sendBatchWithAbortTimeout(
          ingestUrl,
          options.apiKey,
          currentBatch,
          effectiveTimeout
        );

        if (result.ok) {
          sealedBatchQueue.shift();
          dirtyDisk = true;
          flushToDisk();
          syncStats.batches_acked += 1;
          if (result.idempotentReplay) {
            syncStats.idempotent_replays_acked += 1;
          }
          syncStats.acked_batch_ids.push(currentBatch.batchId);
          syncStats.last_sync_status = result.idempotentReplay ? 'synced-idempotent-replay' : 'synced-ok';
        } else {
          // Fallo HTTP 500 o Timeout:
          // Conservamos currentBatch en el frente de sealedBatchQueue CON SU MISMO batchId
          // mientras las nuevas llamadas se siguen acumulando en pendingDeltaCalls.
          syncStats.failed_http_responses += 1;
          syncStats.last_sync_status = 'retry-queued (http=' + result.status + ')';
          allSucceeded = false;
          break;
        }
      }

      recomputeSavings();
      dirtyDisk = true;
      flushToDisk();
      return allSucceeded;
    } finally {
      isFlushing = false;
    }
  };

  const timer = setInterval(() => {
    void flushDeltaToCloud(requestTimeoutMs);
  }, flushIntervalMs);
  if (typeof timer.unref === 'function') timer.unref();

  const onShutdown = () => {
    try {
      sealCurrentDeltasIntoQueue();
      dirtyDisk = true;
      flushToDisk();
      void flushDeltaToCloud(shutdownTimeoutMs);
    } catch {}
  };
  process.once('SIGTERM', onShutdown);
  process.once('SIGINT', onShutdown);

  const middleware: any = function stelfidMiddleware(req: any, res: any, next: any) {
    const rawPath = (req.baseUrl || '') + (req.route?.path || req.path || req.url || '/');
    const method = (req.method || 'GET').toUpperCase();
    const normPath = normalizeRoute(rawPath.split('?')[0]);

    const depPolicy = deprecationMap.get(method + ':' + normPath);
    if (depPolicy && typeof res.setHeader === 'function') {
      res.setHeader('Deprecation', 'true');
      res.setHeader('X-Stelfid-Lifecycle', 'deprecated-candidate');
      if (depPolicy.sunsetDate) res.setHeader('Sunset', depPolicy.sunsetDate);
      if (depPolicy.replacementRoute) {
        res.setHeader('Link', '<' + depPolicy.replacementRoute + '>; rel="successor-version"');
      }
    }

    res.on('finish', () => {
      try {
        const statusCode = Number(res.statusCode || 200);
        const hasMatchedRoute = Boolean(req.route && req.route.path);
        if (!hasMatchedRoute && statusCode >= 400) return;

        const finalRoutePath = (req.baseUrl || '') + (req.route?.path || req.path || req.url || '/');
        const cleanRoutePath = finalRoutePath.split('?')[0];
        const hash = generateBlindHash(method, cleanRoutePath, secretKey);
        const now = new Date().toISOString();
        const statusKey = String(statusCode);
        const isDormantWatched = dormantSet.has(hash) || Boolean(depPolicy);

        const current = memoryStore.get(hash);
        if (current) {
          current.calls += 1;
          current.pendingDeltaCalls += 1;
          current.pendingDeltaStatusCodes[statusKey] = (current.pendingDeltaStatusCodes[statusKey] || 0) + 1;
          current.lastSeenAt = now;
          current.statusCodes[statusKey] = (current.statusCodes[statusKey] || 0) + 1;
          if (hasMatchedRoute) current.isMatchedExpressRoute = true;
          if (isDormantWatched) current.reactivationCount = (current.reactivationCount || 0) + 1;
        } else {
          memoryStore.set(hash, {
            calls: 1,
            pendingDeltaCalls: 1,
            pendingDeltaStatusCodes: { [statusKey]: 1 },
            firstSeenAt: now,
            lastSeenAt: now,
            statusCodes: { [statusKey]: 1 },
            reactivationCount: isDormantWatched ? 1 : 0,
            isMatchedExpressRoute: hasMatchedRoute
          });
        }

        if (isDormantWatched) {
          const evt: DormantTouchEvent = {
            hash,
            method,
            normalizedRoute: normalizeRoute(cleanRoutePath),
            statusCode,
            touchedAt: now,
            environment,
            note: 'Observe-Only Canary: Dormant or deprecated route received traffic.'
          };
          reactivationEvents.push(evt);
          if (typeof options.onDormantRouteTouched === 'function') {
            options.onDormantRouteTouched(evt);
          }
        }

        dirtyDisk = true;
        flushToDisk();
      } catch {}
    });
    next();
  };

  middleware.flushNow = flushDeltaToCloud;
  middleware.getSyncStats = () => ({
    ...syncStats,
    acked_batch_ids: [...syncStats.acked_batch_ids],
    queued_batch_ids: sealedBatchQueue.map(b => b.batchId),
    pending_unsealed_deltas: Array.from(memoryStore.values()).reduce((a, b) => a + b.pendingDeltaCalls, 0)
  });
  return middleware;
}

export const aegisTraceMiddleware = stelfidTelemetry;
export const aegisTrace = stelfidTelemetry;
