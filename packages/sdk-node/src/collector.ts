import * as fs from 'fs';
import * as path from 'path';
import { BlindIndexer } from './crypto';

export interface TelemetryHit {
  method: string;
  routePattern: string;
}

export interface AegisTraceOptions {
  apiKey?: string;
  clientSecret?: string;
  ingestionUrl?: string;
  localFilePath?: string;
  flushIntervalMs?: number;
}

const MAX_BUFFER_ENTRIES = 1000;

export class AegisTraceCollector {
  private buffer: Map<string, { method: string; routeHash: string; count: number }> = new Map();
  private timer: NodeJS.Timeout | null = null;
  private apiKey: string;
  private ingestionUrl: string | null;
  private localFilePath: string;
  private flushIntervalMs: number;
  private indexer: BlindIndexer;

  constructor(options: AegisTraceOptions = {}) {
    this.apiKey = options.apiKey || process.env.AEGIS_API_KEY || 'aegis_local_dev';
    const secret = options.clientSecret || process.env.AEGIS_SECRET || 'sec_aegis_default_local_key';
    this.ingestionUrl = options.ingestionUrl || process.env.AEGIS_URL || null;
    this.localFilePath = options.localFilePath || path.resolve(process.cwd(), '.aegis-local.json');
    this.flushIntervalMs = options.flushIntervalMs || 3000;
    this.indexer = new BlindIndexer(secret);

    this.timer = setInterval(() => {
      this.flush().catch((err) => {
        console.error('[AegisTrace SDK] Error no controlado en flush:', err);
      });
    }, this.flushIntervalMs);

    if (this.timer.unref) {
      this.timer.unref();
    }

    const shutdownHandler = () => {
      this.destroy().catch(() => {});
    };
    process.once('SIGINT', shutdownHandler);
    process.once('SIGTERM', shutdownHandler);
  }

  public recordHit(method: string, routePattern: string): void {
    const normalizedMethod = method.toUpperCase();
    const routeHash = this.indexer.hashRoute(normalizedMethod, routePattern);
    const key = `${normalizedMethod}:${routeHash}`;

    const existing = this.buffer.get(key);
    if (existing) {
      existing.count += 1;
    } else if (this.buffer.size < MAX_BUFFER_ENTRIES) {
      this.buffer.set(key, {
        method: normalizedMethod,
        routeHash,
        count: 1
      });
    }
  }

  private flushToLocalFile(events: Array<{ method: string; routeHash: string; count: number }>): void {
    let store: Record<string, { method: string; calls: number; lastSeen: number }> = {};

    if (fs.existsSync(this.localFilePath)) {
      try {
        store = JSON.parse(fs.readFileSync(this.localFilePath, 'utf8'));
      } catch {
        store = {};
      }
    }

    const now = Date.now();
    for (const ev of events) {
      if (store[ev.routeHash]) {
        store[ev.routeHash].calls += ev.count;
        store[ev.routeHash].lastSeen = now;
      } else {
        store[ev.routeHash] = {
          method: ev.method,
          calls: ev.count,
          lastSeen: now
        };
      }
    }

    fs.writeFileSync(this.localFilePath, JSON.stringify(store, null, 2), 'utf8');
  }

  public async flush(): Promise<void> {
    if (this.buffer.size === 0) return;

    const snapshot = new Map(this.buffer);
    this.buffer.clear();

    const events = Array.from(snapshot.values());

    // Modo Zero-Server Local si no se configuró ingestionUrl
    if (!this.ingestionUrl) {
      this.flushToLocalFile(events);
      return;
    }

    const timestamp = Date.now().toString();
    const body = JSON.stringify({ events });
    const signature = this.indexer.signPayload(body, timestamp);

    try {
      const response = await fetch(this.ingestionUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Aegis-Key': this.apiKey,
          'X-Aegis-Timestamp': timestamp,
          'X-Aegis-Signature': signature
        },
        body
      });

      if (!response.ok) {
        throw new Error(`Servidor respondió con código ${response.status}`);
      }
    } catch (err: any) {
      // Fallback inteligente: si el servidor remoto no está disponible, restaurar en memoria
      for (const [key, item] of snapshot.entries()) {
        const current = this.buffer.get(key);
        if (current) {
          current.count += item.count;
        } else if (this.buffer.size < MAX_BUFFER_ENTRIES) {
          this.buffer.set(key, item);
        }
      }
    }
  }

  public async destroy(): Promise<void> {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    await this.flush();
  }
}