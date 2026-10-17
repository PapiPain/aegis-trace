import { Request, Response, NextFunction } from 'express';
import { AegisTraceCollector, AegisTraceOptions } from './collector';

export function aegisTrace(options: AegisTraceOptions = {}) {
  const collector = new AegisTraceCollector(options);

  return (req: Request, res: Response, next: NextFunction): void => {
    res.on('finish', () => {
      if (!req.route || !req.route.path) {
        return;
      }

      const basePath = req.baseUrl || '';
      const subPath = typeof req.route.path === 'string' ? req.route.path : '';
      
      let fullPattern = `${basePath}${subPath}`;

      if (!fullPattern.startsWith('/')) {
        fullPattern = '/' + fullPattern;
      }
      if (fullPattern.length > 1 && fullPattern.endsWith('/')) {
        fullPattern = fullPattern.slice(0, -1);
      }

      collector.recordHit(req.method.toUpperCase(), fullPattern);
    });

    next();
  };
}

export { AegisTraceCollector, AegisTraceOptions };