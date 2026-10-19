import * as fs from 'fs';
import * as path from 'path';
import { generateBlindHash } from './crypto';

export interface StelfidOptions {
  apiKey?: string;
  secretKey: string;
  environment?: 'local' | 'staging' | 'production' | string;
  flushIntervalMs?: number;
  localFilePath?: string;
  ingestUrl?: string;
  minObservationDays?: number;
}

interface RouteCounter {
  calls: number;
  firstSeenAt: string;
  lastSeenAt: string;
  statusCodes: Record<string, number>;
}

export interface TelemetryEnvelope {
  vendor: string;
  schemaVersion: string;
  environment: string;
  observationStartedAt: string;
  lastFlushedAt: string;
  routes: Record<string, RouteCounter>;
}

export function stelfidTelemetry(options: StelfidOptions) {
  const secretKey = options.secretKey || 'sec_secretkey_test987';
  const environment = options.environment || process.env.NODE_ENV || 'local';
  const flushIntervalMs = options.flushIntervalMs || 30000;
  const localFile = options.localFilePath || path.join(process.cwd(), '.stelfid-local.json');

  let observationStartedAt = new Date().toISOString();
  const memoryStore = new Map<string, RouteCounter>();
  let dirty = false;

  // Cargar estado previo para preservar observationStartedAt real
  if (fs.existsSync(localFile)) {
    try {
      const raw = JSON.parse(fs.readFileSync(localFile, 'utf8').replace(/^\uFEFF/, ''));
      if (raw && raw._meta && raw._meta.observationStartedAt) {
        observationStartedAt = raw._meta.observationStartedAt;
      }
      const existingRoutes = raw.routes || raw;
      for (const [hash, data] of Object.entries(existingRoutes as Record<string, any>)) {
        if (hash === '_meta') continue;
        memoryStore.set(hash, {
          calls: Number(data?.calls ?? 0),
          firstSeenAt: data?.firstSeenAt || observationStartedAt,
          lastSeenAt: data?.lastSeenAt || data?.lastSeen || new Date().toISOString(),
          statusCodes: data?.statusCodes || {}
        });
      }
    } catch {
      // Ignorar archivo corrupto
    }
  }

  const flushToDisk = () => {
    if (!dirty && fs.existsSync(localFile)) return;
    dirty = false;

    const nowIso = new Date().toISOString();
    const output: Record<string, any> = {
      _meta: {
        vendor: 'Maiestor Stelfid',
        schemaVersion: '1.4.0',
        environment,
        observationStartedAt,
        lastFlushedAt: nowIso
      }
    };

    for (const [hash, info] of memoryStore.entries()) {
      output[hash] = {
        calls: info.calls,
        firstSeenAt: info.firstSeenAt,
        lastSeen: info.lastSeenAt,
        statusCodes: info.statusCodes
      };
    }

    try {
      fs.writeFileSync(localFile, JSON.stringify(output, null, 2) + '\n', 'utf8');
    } catch {
      // No interrumpir ejecucion del servidor en produccion
    }
  };

  const timer = setInterval(flushToDisk, flushIntervalMs);
  if (typeof timer.unref === 'function') {
    timer.unref();
  }

  return function stelfidMiddleware(req: any, res: any, next: any) {
    res.on('finish', () => {
      try {
        const routePath = (req.baseUrl || '') + (req.route?.path || req.path || req.url || '/');
        const method = req.method || 'GET';
        const hash = generateBlindHash(method, routePath, secretKey);
        const now = new Date().toISOString();
        const statusKey = String(res.statusCode || 200);

        const current = memoryStore.get(hash);
        if (current) {
          current.calls += 1;
          current.lastSeenAt = now;
          current.statusCodes[statusKey] = (current.statusCodes[statusKey] || 0) + 1;
        } else {
          memoryStore.set(hash, {
            calls: 1,
            firstSeenAt: now,
            lastSeenAt: now,
            statusCodes: { [statusKey]: 1 }
          });
        }
        dirty = true;
        flushToDisk();
      } catch {
        // Fail-open siempre para no afectar produccion
      }
    });
    next();
  };
}

// Alias de retrocompatibilidad
export const aegisTraceMiddleware = stelfidTelemetry;
export const aegisTrace = stelfidTelemetry;
