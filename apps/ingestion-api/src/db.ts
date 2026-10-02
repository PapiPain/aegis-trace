import { DatabaseSync } from 'node:sqlite';
import * as path from 'path';

const dbPath = path.resolve(__dirname, '../aegis.db');
const db = new DatabaseSync(dbPath);

db.exec(`
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

export function upsertTelemetryEvent(
  apiKey: string,
  routeHash: string,
  method: string,
  count: number,
  timestamp: number
): void {
  const statement = db.prepare(`
    INSERT INTO telemetry_events (api_key, route_hash, method, call_count, last_seen)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(api_key, route_hash) DO UPDATE SET
      call_count = call_count + excluded.call_count,
      last_seen = excluded.last_seen;
  `);

  statement.run(apiKey, routeHash, method, count, timestamp);
}

export function getActiveHashes(apiKey: string): string[] {
  const statement = db.prepare(`
    SELECT route_hash FROM telemetry_events
    WHERE api_key = ?
  `);

  const rows = statement.all(apiKey) as unknown as Array<{ route_hash: string }>;
  return rows.map(r => r.route_hash);
}

export function getAllTelemetry(apiKey: string): TelemetryRow[] {
  const statement = db.prepare(`
    SELECT api_key, route_hash, method, call_count, last_seen
    FROM telemetry_events
    WHERE api_key = ?
    ORDER BY last_seen DESC
  `);

  return statement.all(apiKey) as unknown as TelemetryRow[];
}