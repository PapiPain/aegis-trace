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
  isAuthenticated: boolean;
  authMiddlewares: string[];
}

const AUTH_KEYWORD_REGEX = /(?:auth|jwt|token|guard|protect|session|admin|role|permission|passport|clerk|supabase|bearer|verify|private|secure|logged|requireAuth|isAuthenticated|checkRole|apiKeyAuth)/i;
const IGNORED_IDENTIFIERS = new Set([
  'req', 'res', 'next', 'async', 'await', 'err', 'request', 'response', 'app', 'router',
  'aegisTrace', 'aegisTraceMiddleware', 'apiKey', 'secretKey', 'express', 'json', 'urlencoded',
  'cors', 'helmet', 'morgan', 'compression', 'cookieParser', 'rateLimit', 'true', 'false', 'null'
]);

export class BlindAnalyzer {
  private secretKey: string;

  constructor(secretKey: string) {
    this.secretKey = secretKey;
  }

  public normalizeRoute(routePattern: string): string {
    let normalized = routePattern.trim().toLowerCase();
    normalized = normalized.replace(/\/+/g, '/');
    normalized = normalized.replace(/:[a-zA-Z0-9_]+/g, ':param');

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

  public detectRouterPrefixes(files: string[]): Map<string, string> {
    const filePrefixes = new Map<string, string>();
    const importMap = new Map<string, string>();

    for (const filePath of files) {
      const content = fs.readFileSync(filePath, 'utf8');
      const dir = path.dirname(filePath);

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

      const useRegex = /(?:app|router)\.use\s*\(\s*['"`]([^'"`]+)['"`]\s*,([\s\S]*?)\)/g;
      let useMatch: RegExpExecArray | null;
      while ((useMatch = useRegex.exec(content)) !== null) {
        const prefix = useMatch[1];
        const restArgs = useMatch[2];
        for (const [varName, targetFile] of importMap.entries()) {
          if (new RegExp(`\\b${varName}\\b`).test(restArgs)) {
            filePrefixes.set(targetFile, prefix);
          }
        }
      }
    }

    return filePrefixes;
  }

  private detectRouteAuth(snippet: string[], globalFileAuth: string[]): { isAuthenticated: boolean; authMiddlewares: string[] } {
    const detected = new Set<string>(globalFileAuth);
    const fullText = snippet.join('\n');

    if (/\/\/\s*@aegis-auth/i.test(fullText)) {
      detected.add('@aegis-auth');
    }

    const headerMatch = fullText.match(/\b(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"`][^'"`]+['"`]\s*,([\s\S]*)/i);
    if (headerMatch) {
      const argsSegment = headerMatch[1];
      const beforeArrow = argsSegment.split('=>')[0] || argsSegment;
      const beforeFunction = beforeArrow.split(/\bfunction\b/)[0] || beforeArrow;
      // Strip parameter list like (req, res, next) at the end of beforeArrow
      const middlewareZone = beforeFunction.replace(/\(\s*(?:req\vert{}request)\b[^)]*\)\s*$/i, '');

      const identifiers = middlewareZone.match(/\b[a-zA-Z_][a-zA-Z0-9_.]*\b/g) || [];
      for (const id of identifiers) {
        if (IGNORED_IDENTIFIERS.has(id)) continue;
        if (AUTH_KEYWORD_REGEX.test(id)) {
          detected.add(id);
        }
      }
    }

    const bodyAuthMatch = fullText.match(/\b(?:verifyToken|verifyJwt|checkAuth|requireAuth|getSession|authenticate)\s*\(/i);
    if (bodyAuthMatch) {
      detected.add(bodyAuthMatch[0].replace(/\($/, '').trim());
    }

    const list = Array.from(detected);
    return {
      isAuthenticated: list.length > 0,
      authMiddlewares: list
    };
  }

  public extractRoutes(filePath: string, routerPrefix: string = ''): RouteEntry[] {
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');
    const routes: RouteEntry[] = [];

    const prefixCommentMatch = content.match(/\/\/\s*@aegis-prefix\s+([^\s]+)/);
    const activePrefix = prefixCommentMatch ? prefixCommentMatch[1].trim() : routerPrefix;

    const globalFileAuth: string[] = [];
    const globalUseRegex = /\b(?:app|router)\.use\s*\(\s*([a-zA-Z_][a-zA-Z0-9_.]*)\s*(?:\(\vert{},\vert{}\))/g;
    let gMatch: RegExpExecArray | null;
    while ((gMatch = globalUseRegex.exec(content)) !== null) {
      const fnName = gMatch[1];
      if (!IGNORED_IDENTIFIERS.has(fnName) && AUTH_KEYWORD_REGEX.test(fnName)) {
        globalFileAuth.push(fnName);
      }
    }

    const methodStartRegex = /\b(?:app|router)\.(get|post|put|delete|patch)\s*\(/i;
    const stringLiteralRegex = /^\s*['"`]([^'"`]+)['"`]/;

    let inBlockComment = false;

    for (let i = 0; i < lines.length; i++) {
      const rawLine = lines[i];
      const trimmed = rawLine.trim();

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

      if (trimmed.startsWith('//')) {
        continue;
      }

      const methodMatch = rawLine.match(methodStartRegex);
      if (!methodMatch) continue;

      const method = methodMatch[1].toUpperCase();
      const afterParenIndex = (methodMatch.index || 0) + methodMatch[0].length;
      const restOfFirstLine = rawLine.slice(afterParenIndex);

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

      const fullRoute = activePrefix
        ? `${activePrefix.replace(/\/$/, '')}/${rawRoute.replace(/^\//, '')}`
        : rawRoute;

      const hash = this.hashRoute(method, fullRoute);

      let endLine = i;
      let openParens = 0;
      let started = false;
      let inString: string | null = null;

      for (let j = i; j < lines.length; j++) {
        const line = lines[j];
        for (let k = 0; k < line.length; k++) {
          const char = line[k];
          const prevChar = k > 0 ? line[k - 1] : '';

          if (!inString && char === '/' && line[k + 1] === '/') {
            break;
          }

          if ((char === "'" || char === '"' || char === '`') && prevChar !== '\\') {
            if (!inString) {
              inString = char;
            } else if (inString === char) {
              inString = null;
            }
            continue;
          }

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
      const authInfo = this.detectRouteAuth(snippet, globalFileAuth);

      routes.push({
        method,
        route: rawRoute,
        fullRoute,
        file: path.basename(filePath),
        filePath,
        startLine: i + 1,
        endLine: endLine + 1,
        codeSnippet: snippet,
        hash,
        isAuthenticated: authInfo.isAuthenticated,
        authMiddlewares: authInfo.authMiddlewares
      });

      i = endLine;
    }

    return routes;
  }
}
