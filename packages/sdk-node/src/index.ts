import { Request, Response, NextFunction } from 'express';
import { AegisTraceCollector } from './collector';

export interface AegisTraceOptions {
  apiKey: string;
  clientSecret: string;
  ingestionUrl: string;
  flushIntervalMs?: number;
}

export function aegisTrace(options: AegisTraceOptions) {
  const collector = new AegisTraceCollector(options);

  return (req: Request, res: Response, next: NextFunction): void => {
    res.on('finish', () => {
      // Captura la plantilla (/api/users/:id) en lugar del valor crudo (/api/users/10)
      const routePattern = (req.route && req.route.path) ? req.route.path : req.path;
      
      // Orden correcto: method primero, routePattern segundo
      collector.recordHit(req.method, routePattern);
    });

    next();
  };
}

export { AegisTraceCollector };