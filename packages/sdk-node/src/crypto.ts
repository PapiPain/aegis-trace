import { createHmac } from 'node:crypto';

export class BlindIndexer {
  private secretKey: string;

  constructor(secretKey: string) {
    this.secretKey = secretKey;
  }

  // Normalización canónica 100% espejo con BlindAnalyzer en el CLI
  public normalizeRoute(routePattern: string): string {
    let normalized = routePattern.trim().toLowerCase();

    // 1. Colapsar múltiples slashes accidentales (ej. de sub-routers /api/ + /users -> /api/users)
    normalized = normalized.replace(/\/+/g, '/');

    // 2. Homogeneizar :id, :userId, :slug a :param
    normalized = normalized.replace(/:[a-zA-Z0-9_]+/g, ':param');

    // 3. Remover trailing slash excepto en la raíz '/'
    if (normalized.length > 1 && normalized.endsWith('/')) {
      normalized = normalized.slice(0, -1);
    }

    return normalized.startsWith('/') ? normalized : `/${normalized}`;
  }

  // Mismo formato canónico que analyzer.ts: METHOD:/ruta
  public hashRoute(method: string, routePattern: string): string {
    const canonical = `${method.toUpperCase()}:${this.normalizeRoute(routePattern)}`;
    return createHmac('sha256', this.secretKey)
      .update(canonical)
      .digest('hex');
  }

  public signPayload(payload: string, timestamp: string | number): string {
    const dataToSign = `${timestamp}.${payload}`;
    return createHmac('sha256', this.secretKey)
      .update(dataToSign)
      .digest('hex');
  }
}
