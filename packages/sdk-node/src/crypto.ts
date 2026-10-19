import { createHmac } from 'crypto';

export function normalizeRoute(routePattern: string): string {
  let normalized = routePattern.trim().toLowerCase();
  normalized = normalized.replace(/\/+/g, '/');
  normalized = normalized.replace(/:[a-zA-Z0-9_]+/g, ':param');
  if (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }
  return normalized.startsWith('/') ? normalized : '/' + normalized;
}

export function generateBlindHash(method: string, routePattern: string, secretKey: string): string {
  const canonical = method.toUpperCase() + ':' + normalizeRoute(routePattern);
  return createHmac('sha256', secretKey).update(canonical).digest('hex');
}
