import * as fs from 'fs';
import * as path from 'path';
import { createHmac } from 'crypto';

export interface RouteEntry {
  method: string;
  route: string;
  file: string;
  filePath: string;
  startLine: number;
  endLine: number;
  codeSnippet: string[];
  hash: string;
}

export class BlindAnalyzer {
  private secretKey: string;

  constructor(secretKey: string) {
    this.secretKey = secretKey;
  }

  // Ahora recibe tanto el método como la ruta para coincidir 1:1 con el SDK
  public hashRoute(method: string, routePattern: string): string {
    const canonical = `${method.toUpperCase()}:${routePattern.trim().toLowerCase()}`;
    return createHmac('sha256', this.secretKey)
      .update(canonical)
      .digest('hex');
  }

  public scanDirectory(dir: string, fileList: string[] = []): string[] {
    const files = fs.readdirSync(dir);

    for (const file of files) {
      const fullPath = path.join(dir, file);
      const stat = fs.statSync(fullPath);

      if (stat.isDirectory()) {
        if (file !== 'node_modules' && file !== 'dist') {
          this.scanDirectory(fullPath, fileList);
        }
      } else if (file.endsWith('.ts') || file.endsWith('.js')) {
        fileList.push(fullPath);
      }
    }

    return fileList;
  }

  public extractRoutes(filePath: string): RouteEntry[] {
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');
    const routes: RouteEntry[] = [];

    const routeRegex = /(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/i;

    for (let i = 0; i < lines.length; i++) {
      const match = lines[i].match(routeRegex);
      if (match) {
        const method = match[1].toUpperCase();
        const route = match[2];
        // Pasamos method y route
        const hash = this.hashRoute(method, route);

        // Detectar el bloque de cierre simple de la función buscando ');'
        let endLine = i;
        while (endLine < lines.length && !lines[endLine].includes(');')) {
          endLine++;
        }

        const snippet = lines.slice(i, endLine + 1);

        routes.push({
          method,
          route,
          file: path.basename(filePath),
          filePath,
          startLine: i + 1,
          endLine: endLine + 1,
          codeSnippet: snippet,
          hash
        });

        i = endLine; // Saltar al final del bloque analizado
      }
    }

    return routes;
  }
}