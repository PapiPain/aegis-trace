import { createHmac } from 'node:crypto';

export interface TelemetryHit {
  method: string;
  routePattern: string;
}

export class AegisTraceCollector {
  private buffer: Map<string, { method: string; routeHash: string; count: number }> = new Map();
  private timer: NodeJS.Timeout | null = null;
  private apiKey: string;
  private clientSecret: string;
  private ingestionUrl: string;
  private flushIntervalMs: number;

  constructor(options: { apiKey: string; clientSecret: string; ingestionUrl: string; flushIntervalMs?: number }) {
    this.apiKey = options.apiKey;
    this.clientSecret = options.clientSecret;
    this.ingestionUrl = options.ingestionUrl;
    this.flushIntervalMs = options.flushIntervalMs || 3000;

    this.timer = setInterval(() => this.flush(), this.flushIntervalMs);
  }

  // Genera el Blind Hash SHA256 con el secret del cliente
  private computeHash(method: string, routePattern: string): string {
    const canonical = `${method.toUpperCase()}:${routePattern.toLowerCase()}`;
    return createHmac('sha256', this.clientSecret)
      .update(canonical)
      .digest('hex');
  }

  public recordHit(method: string, routePattern: string): void {
    const normalizedMethod = method.toUpperCase();
    const routeHash = this.computeHash(normalizedMethod, routePattern);
    const key = `${normalizedMethod}:${routeHash}`;

    const existing = this.buffer.get(key);
    if (existing) {
      existing.count += 1;
    } else {
      this.buffer.set(key, {
        method: normalizedMethod,
        routeHash,
        count: 1
      });
    }
  }

  public async flush(): Promise<void> {
    if (this.buffer.size === 0) return;

    const events = Array.from(this.buffer.values());
    this.buffer.clear();

    const timestamp = Date.now().toString();
    const body = JSON.stringify({ events });

    // Firma de transporte anti-tampering
    const signature = createHmac('sha256', this.clientSecret)
      .update(`${timestamp}.${body}`)
      .digest('hex');

    try {
      await fetch(this.ingestionUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Aegis-Key': this.apiKey,
          'X-Aegis-Timestamp': timestamp,
          'X-Aegis-Signature': signature
        },
        body
      });
    } catch (err) {
      console.error('[AegisTrace SDK] Error enviando telemetría:', err);
    }
  }

  public destroy(): void {
    if (this.timer) clearInterval(this.timer);
    this.flush();
  }
}