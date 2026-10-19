import * as fs from 'fs';
import * as path from 'path';
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
  environment?: 'local' | 'staging' | 'production' | string;
  flushIntervalMs?: number;
  localFilePath?: string;
  ingestUrl?: string;
  deprecatedRoutes?: DeprecatedRoutePolicy[];
  dormantHashes?: string[];
  onDormantRouteTouched?: (event: DormantTouchEvent) => void;
}

interface RouteCounter {
  calls: number;
  firstSeenAt: string;
  lastSeenAt: string;
  statusCodes: Record<string, number>;
  reactivationCount?: number;
}

export interface TelemetryEnvelope {
  vendor: string;
  schemaVersion: string;
  environment: string;
  observationStartedAt: string;
  lastFlushedAt: string;
  routes: Record<string, RouteCounter>;
  reactivationEvents?: DormantTouchEvent[];
}

export function stelfidTelemetry(options: StelfidOptions) {
  const secretKey = options.secretKey || 'sec_secretkey_test987';
  const environment = options.environment || process.env.NODE_ENV || 'local';
  const flushIntervalMs = options.flushIntervalMs || 30000;
  const localFile = options.localFilePath || path.join(process.cwd(), '.stelfid-local.json');

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
  let dirty = false;

  if (fs.existsSync(localFile)) {
    try {
      const raw = JSON.parse(fs.readFileSync(localFile, 'utf8').replace(/^\uFEFF/, ''));
      if (raw && raw._meta && raw._meta.observationStartedAt) {
        observationStartedAt = raw._meta.observationStartedAt;
      }
      if (Array.isArray(raw.reactivationEvents)) {
        reactivationEvents.push(...raw.reactivationEvents.slice(-50));
      }
      const existingRoutes = raw.routes || raw;
      for (const [hash, data] of Object.entries(existingRoutes as Record<string, any>)) {
        if (hash === '_meta' || hash === 'reactivationEvents') continue;
        memoryStore.set(hash, {
          calls: Number(data?.calls ?? 0),
          firstSeenAt: data?.firstSeenAt || observationStartedAt,
          lastSeenAt: data?.lastSeenAt || data?.lastSeen || new Date().toISOString(),
          statusCodes: data?.statusCodes || {},
          reactivationCount: Number(data?.reactivationCount ?? 0)
        });
      }
    } catch {
      // Fail-open
    }
  }

  const flushToDisk = () => {
    if (!dirty && fs.existsSync(localFile)) return;
    dirty = false;
    const nowIso = new Date().toISOString();
    const output: Record<string, any> = {
      _meta: {
        vendor: 'Maiestor Stelfid',
        schemaVersion: '1.5.0',
        environment,
        observationStartedAt,
        lastFlushedAt: nowIso
      },
      reactivationEvents: reactivationEvents.slice(-50)
    };
    for (const [hash, info] of memoryStore.entries()) {
      output[hash] = {
        calls: info.calls,
        firstSeenAt: info.firstSeenAt,
        lastSeen: info.lastSeenAt,
        statusCodes: info.statusCodes,
        reactivationCount: info.reactivationCount || 0
      };
    }
    try {
      fs.writeFileSync(localFile, JSON.stringify(output, null, 2) + '\n', 'utf8');
    } catch {
      // Fail-open
    }
  };

  const timer = setInterval(flushToDisk, flushIntervalMs);
  if (typeof timer.unref === 'function') timer.unref();

  return function stelfidMiddleware(req: any, res: any, next: any) {
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
        const finalRoutePath = (req.baseUrl || '') + (req.route?.path || req.path || req.url || '/');
        const cleanRoutePath = finalRoutePath.split('?')[0];
        const hash = generateBlindHash(method, cleanRoutePath, secretKey);
        const now = new Date().toISOString();
        const statusKey = String(res.statusCode || 200);
        const isDormantWatched = dormantSet.has(hash) || Boolean(depPolicy);

        const current = memoryStore.get(hash);
        if (current) {
          current.calls += 1;
          current.lastSeenAt = now;
          current.statusCodes[statusKey] = (current.statusCodes[statusKey] || 0) + 1;
          if (isDormantWatched) current.reactivationCount = (current.reactivationCount || 0) + 1;
        } else {
          memoryStore.set(hash, {
            calls: 1,
            firstSeenAt: now,
            lastSeenAt: now,
            statusCodes: { [statusKey]: 1 },
            reactivationCount: isDormantWatched ? 1 : 0
          });
        }

        if (isDormantWatched) {
          const evt: DormantTouchEvent = {
            hash,
            method,
            normalizedRoute: normalizeRoute(cleanRoutePath),
            statusCode: Number(res.statusCode || 200),
            touchedAt: now,
            environment,
            note: 'Observe-Only Canary: Dormant or deprecated route received traffic.'
          };
          reactivationEvents.push(evt);
          if (typeof options.onDormantRouteTouched === 'function') {
            options.onDormantRouteTouched(evt);
          }
        }
        dirty = true;
        flushToDisk();
      } catch {
        // Fail-open
      }
    });
    next();
  };
}

export const aegisTraceMiddleware = stelfidTelemetry;
export const aegisTrace = stelfidTelemetry;
