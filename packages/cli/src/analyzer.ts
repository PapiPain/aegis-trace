import * as fs from 'fs';
import * as path from 'path';
import { createHmac } from 'crypto';

export interface RouteEntry {
  method: string;
  route: string;
  fullRoute: string;
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

  // Normalización canónica idéntica a la del SDK
  public normalizeRoute(routePattern: string): string {
    let normalized = routePattern.trim().toLowerCase();

    // Colapsar múltiples slashes accidentales (ej: //api///users -> /api/users)
    normalized = normalized.replace(/\/+/g, '/');

    // Unificar cualquier parámetro dinámico (:id, :userId, :slug) a :param
    normalized = normalized.replace(/:[a-zA-Z0-9_]+/g, ':param');

    // Remover trailing slash excepto si es la raíz '/'
    if (normalized.length > 1 && normalized.endsWith('/')) {
      normalized = normalized.slice(0, -1);
    }

    return normalized.startsWith('/') ? normalized : `/${normalized}`;
  }

  public hashRoute(method: string, routePattern: string): string {
    const canonical = `${method.toUpperCase()}:${this.normalizeRoute(routePattern)}`;
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
        if (!['node_modules', 'dist', 'build', '.git', 'coverage'].includes(file)) {
          this.scanDirectory(fullPath, fileList);
        }
      } else if (
        (file.endsWith('.ts') || file.endsWith('.js')) &&
        !file.endsWith('.d.ts') &&
        !file.endsWith('.test.ts') &&
        !file.endsWith('.spec.ts') &&
        !file.endsWith('.aegis.bak')
      ) {
        fileList.push(fullPath);
      }
    }

    return fileList;
  }

  // Detecta si en los archivos principales se montan routers con prefijo: app.use('/api/users', userRouter)
  public detectRouterPrefixes(files: string[]): Map<string, string> {
    const filePrefixes = new Map<string, string>();
    const importMap = new Map<string, string>(); // varName -> resolvedFilePath

    for (const filePath of files) {
      const content = fs.readFileSync(filePath, 'utf8');
      const dir = path.dirname(filePath);

      // 1. Rastrear imports locales: import userRouter from './routes/users'
      const importRegex = /import\s+(?:\{\s*([a-zA-Z0-9_]+)\s*\}|([a-zA-Z0-9_]+))\s+from\s+['"`](\.[^'"`]+)['"`]/g;
      let impMatch: RegExpExecArray | null;
      while ((impMatch = importRegex.exec(content)) !== null) {
        const varName = impMatch[1] || impMatch[2];
        const relPath = impMatch[3];
        const candidates = [
          path.resolve(dir, `${relPath}.ts`),
          path.resolve(dir, `${relPath}.js`),
          path.resolve(dir, relPath, 'index.ts'),
          path.resolve(dir, relPath, 'index.js')
        ];
        const found = candidates.find(c => fs.existsSync(c));
        if (found) {
          importMap.set(varName, found);
        }
      }

      // 2. Rastrear montajes: app.use('/api/v1', userRouter)
      const useRegex = /(?:app|router)\.use\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*([a-zA-Z0-9_]+)/g;
      let useMatch: RegExpExecArray | null;
      while ((useMatch = useRegex.exec(content)) !== null) {
        const prefix = useMatch[1];
        const routerVar = useMatch[2];
        const targetFile = importMap.get(routerVar);
        if (targetFile) {
          filePrefixes.set(targetFile, prefix);
        }
      }
    }

    return filePrefixes;
  }

  public extractRoutes(filePath: string, routerPrefix: string = ''): RouteEntry[] {
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');
    const routes: RouteEntry[] = [];

    // Permitir que el usuario fuerce un prefijo con comentario si usa carga dinámica: // @aegis-prefix /api/v1
    const prefixCommentMatch = content.match(/\/\/\s*@aegis-prefix\s+([^\s]+)/);
    const activePrefix = prefixCommentMatch ? prefixCommentMatch[1].trim() : routerPrefix;

    const methodStartRegex = /\b(?:app|router)\.(get|post|put|delete|patch)\s*\(/i;
    const stringLiteralRegex = /^\s*['"`]([^'"`]+)['"`]/;

    let inBlockComment = false;

    for (let i = 0; i < lines.length; i++) {
      const rawLine = lines[i];
      const trimmed = rawLine.trim();

      // Controlar bloques de comentarios /* ... */ (incluyendo los que genera AegisTrace --prune)
      if (inBlockComment) {
        if (trimmed.includes('*/')) {
          inBlockComment = false;
        }
        continue;
      }

      if (trimmed.startsWith('/*')) {
        if (!trimmed.includes('*/')) {
          inBlockComment = true;
        }
        continue;
      }

      // Ignorar comentarios de una sola línea
      if (trimmed.startsWith('//')) {
        continue;
      }

      const methodMatch = rawLine.match(methodStartRegex);
      if (!methodMatch) continue;

      const method = methodMatch[1].toUpperCase();
      const afterParenIndex = (methodMatch.index || 0) + methodMatch[0].length;
      const restOfFirstLine = rawLine.slice(afterParenIndex);

      // Buscar el path de la ruta en la misma línea o en la siguiente (soporte para Prettier multilínea)
      let rawRoute: string | null = null;
      const sameLineRoute = restOfFirstLine.match(stringLiteralRegex);

      if (sameLineRoute) {
        rawRoute = sameLineRoute[1];
      } else if (i + 1 < lines.length) {
        const nextLineRoute = lines[i + 1].match(stringLiteralRegex);
        if (nextLineRoute) {
          rawRoute = nextLineRoute[1];
        }
      }

      if (!rawRoute) continue;

      // Combinar con prefijo de Router si existe
      const fullRoute = activePrefix
        ? `${activePrefix.replace(/\/$/, '')}/${rawRoute.replace(/^\//, '')}`
        : rawRoute;

      const hash = this.hashRoute(method, fullRoute);

      // Balanceo seguro de paréntesis ignorando paréntesis dentro de strings o comentarios
      let endLine = i;
      let openParens = 0;
      let started = false;
      let inString: string | null = null;

      for (let j = i; j < lines.length; j++) {
        const line = lines[j];
        for (let k = 0; k < line.length; k++) {
          const char = line[k];
          const prevChar = k > 0 ? line[k - 1] : '';

          // Si empieza un comentario '//' fuera de un string, ignorar el resto de la línea
          if (!inString && char === '/' && line[k + 1] === '/') {
            break;
          }

          // Manejo de apertura y cierre de comillas (' " `)
          if ((char === "'" || char === '"' || char === '`') && prevChar !== '\\') {
            if (!inString) {
              inString = char;
            } else if (inString === char) {
              inString = null;
            }
            continue;
          }

          // Solo contar paréntesis si NO estamos dentro de un texto entre comillas
          if (!inString) {
            if (char === '(') {
              openParens++;
              started = true;
            } else if (char === ')') {
              openParens--;
            }
          }
        }

        if (started && openParens <= 0) {
          endLine = j;
          break;
        }
      }

      const snippet = lines.slice(i, endLine + 1);

      routes.push({
        method,
        route: rawRoute,
        fullRoute,
        file: path.basename(filePath),
        filePath,
        startLine: i + 1,
        endLine: endLine + 1,
        codeSnippet: snippet,
        hash
      });

      i = endLine;
    }

    return routes;
  }
}