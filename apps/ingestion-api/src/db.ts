import { DatabaseSync } from 'node:sqlite';
import * as path from 'path';

const dbPath = path.resolve(__dirname, '../aegis.db');
const db = new DatabaseSync(dbPath);

// Optimización de concurrencia para lecturas y escrituras simultáneas
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA synchronous = NORMAL;
  CREATE TABLE IF NOT EXISTS telemetry_events (
    api_key TEXT NOT NULL,
    route_hash TEXT NOT NULL,
    method TEXT NOT NULL,
    call_count INTEGER DEFAULT 1,
    last_seen INTEGER NOT NULL,
    PRIMARY KEY (api_key, route_hash)
  );
`);

export interface TelemetryRow {
  api_key: string;
  route_hash: string;
  method: string;
  call_count: number;
  last_seen: number;
}

// Prepared statements pre-compilados una sola vez en memoria
const upsertStmt = db.prepare(`
  INSERT INTO telemetry_events (api_key, route_hash, method, call_count, last_seen)
  VALUES (?, ?, ?, ?, ?)
  ON CONFLICT(api_key, route_hash) DO UPDATE SET
    call_count = call_count + excluded.call_count,
    last_seen = excluded.last_seen;
`);

const activeHashesStmt = db.prepare(`
  SELECT route_hash AS hash, call_count AS calls
  FROM telemetry_events
  WHERE api_key = ? AND last_seen >= ?
`);

const allTelemetryStmt = db.prepare(`
  SELECT api_key, route_hash, method, call_count, last_seen
  FROM telemetry_events
  WHERE api_key = ?
  ORDER BY last_seen DESC
`);

export function upsertTelemetryEvent(
  apiKey: string,
  routeHash: string,
  method: string,
  count: number,
  timestamp: number
): void {
  upsertStmt.run(apiKey, routeHash, method, count, timestamp);
}

// Inserción en lote atómica para maximizar rendimiento del endpoint /v1/telemetry
export function upsertTelemetryBatch(
  apiKey: string,
  events: Array<{ routeHash: string; method: string; count?: number }>,
  timestamp: number
): void {
  db.exec('BEGIN IMMEDIATE;');
  try {
    for (const event of events) {
      upsertStmt.run(
        apiKey,
        event.routeHash,
        event.method,
        event.count || 1,
        timestamp
      );
    }
    db.exec('COMMIT;');
  } catch (err) {
    db.exec('ROLLBACK;');
    throw err;
  }
}

export function getActiveHashes(
  apiKey: string,
  sinceTimestamp: number = 0
): Array<{ hash: string; calls: number }> {
  return activeHashesStmt.all(apiKey, sinceTimestamp) as unknown as Array<{
    hash: string;
    calls: number;
  }>;
}

export function getAllTelemetry(apiKey: string): TelemetryRow[] {
  return allTelemetryStmt.all(apiKey) as unknown as TelemetryRow[];
}