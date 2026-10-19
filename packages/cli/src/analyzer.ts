import * as fs from 'fs';
import * as path from 'path';
import { createHmac } from 'crypto';

export type RetirementState =
  | 'ACTIVE'
  | 'EXEMPT_KEEP'
  | 'STAGE_DEPRECATED'
  | 'UNOBSERVED_LOW_CONFIDENCE'
  | 'CANDIDATE_PROTECTED'
  | 'CANDIDATE_UNAUTHENTICATED';

export interface AnalyzedRoute {
  file: string;
  method: string;
  rawRoute: string;
  fullRoute: string;
  prefixSource: 'auto-mount' | 'annotation' | 'none';
  line: number;
  endLine: number;
  hash: string;
  isAuthenticated: boolean;
  authMiddlewares: string[];
  isKeepExempt: boolean;
  keepReason: string | null;
  isDeprecatedStage: boolean;
  sunsetDate: string | null;
  referencedInTests: boolean;
}

const AUTH_KEYWORD_REGEX = /(?:auth|jwt|token|guard|protect|session|admin|role|permission|passport|clerk|supabase|bearer|verify|private|secure|logged|requireAuth|isAuthenticated|checkRole|apiKeyAuth)/i;

const IGNORED_IDENTIFIERS = new Set([
  'req', 'res', 'next', 'async', 'await', 'err', 'request', 'response', 'app', 'router',
  'aegisTrace', 'aegisTraceMiddleware', 'stelfidTelemetry', 'apiKey', 'secretKey', 'express',
  'json', 'urlencoded', 'cors', 'helmet', 'morgan', 'compression', 'cookieParser', 'rateLimit',
  'true', 'false', 'null'
]);

export function normalizeRoute(routePattern: string): string {
  let normalized = routePattern.trim().toLowerCase();
  normalized = normalized.replace(/\/+/g, '/');
  normalized = normalized.replace(/:[a-zA-Z0-9_]+/g, ':param');
  if (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }
  return normalized.startsWith('/') ? normalized : '/' + normalized;
}

export function hashRoute(method: string, routePattern: string, secretKey: string): string {
  const canonical = method.toUpperCase() + ':' + normalizeRoute(routePattern);
  return createHmac('sha256', secretKey).update(canonical).digest('hex');
}

function loadIgnorePatterns(targetDir: string): string[] {
  const ignoreFiles = [
    path.join(targetDir, '.stelfidignore'),
    path.join(process.cwd(), '.stelfidignore')
  ];
  const found = ignoreFiles.find(f => fs.existsSync(f));
  if (!found) return [];
  try {
    return fs.readFileSync(found, 'utf8')
      .split(/\r?\n/)
      .map(l => l.trim())
      .filter(l => l.length > 0 && !l.startsWith('#'));
  } catch {
    return [];
  }
}

function isRouteIgnored(fullRoute: string, relFile: string, patterns: string[]): boolean {
  for (const pat of patterns) {
    if (fullRoute === pat || fullRoute.startsWith(pat.replace(/\*$/, ''))) return true;
    if (relFile.replace(/\\/g, '/').includes(pat.replace(/\*$/, ''))) return true;
  }
  return false;
}

function collectTestReferences(targetDir: string): string {
  const chunks: string[] = [];
  function walkTests(dir: string) {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (['node_modules', 'dist', '.git'].includes(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walkTests(full);
      } else if (/\.(test|spec)\.(ts|js)$/i.test(entry.name)) {
        try { chunks.push(fs.readFileSync(full, 'utf8')); } catch {}
      }
    }
  }
  walkTests(targetDir);
  return chunks.join('\n');
}

function buildCrossFileMountPrefixMap(sourceFiles: string[]): Map<string, string> {
  const prefixByFile = new Map<string, string>();
  const resolveImportTarget = (fromFile: string, importSpec: string): string | null => {
    if (!importSpec.startsWith('.')) return null;
    const base = path.resolve(path.dirname(fromFile), importSpec);
    const candidates = [
      base,
      base + '.ts',
      base + '.js',
      path.join(base, 'index.ts'),
      path.join(base, 'index.js')
    ];
    return candidates.find(c => fs.existsSync(c) && fs.statSync(c).isFile()) || null;
  };

  for (const file of sourceFiles) {
    let content = '';
    try { content = fs.readFileSync(file, 'utf8'); } catch { continue; }
    const importedVars = new Map<string, string>();

    const esmRegex = /import\s+(?:\*\s+as\s+)?([a-zA-Z0-9_$]+|\{[^{}]+\})\s+from\s+['"]([^'"]+)['"]/g;
    let m: RegExpExecArray | null;
    while ((m = esmRegex.exec(content)) !== null) {
      const clause = m[1].trim();
      const spec = m[2].trim();
      const resolved = resolveImportTarget(file, spec);
      if (!resolved) continue;
      if (clause.startsWith('{')) {
        const names = clause.slice(1, -1).split(',').map(s => s.trim());
        for (const n of names) {
          const parts = n.split(/\s+as\s+/i);
          const localName = (parts[1] || parts[0]).trim();
          if (localName) importedVars.set(localName, resolved);
        }
      } else {
        importedVars.set(clause, resolved);
      }
    }

    const cjsRegex = /(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
    while ((m = cjsRegex.exec(content)) !== null) {
      const resolved = resolveImportTarget(file, m[2].trim());
      if (resolved) importedVars.set(m[1].trim(), resolved);
    }

    const mountRegex = /\b(?:app|router|[a-zA-Z0-9_$]*Router)\.use\s*\(\s*['"`]([^'"`]+)['"`]\s*,([^;\n]+)\)/g;
    while ((m = mountRegex.exec(content)) !== null) {
      const mountPrefix = m[1].trim();
      const argsPart = m[2];
      const argIds = argsPart.match(/\b[a-zA-Z_$][a-zA-Z0-9_$]*\b/g) || [];
      for (const id of argIds) {
        const targetFile = importedVars.get(id);
        if (targetFile) {
          const existingParentPrefix = prefixByFile.get(file) || '';
          const combined = existingParentPrefix
            ? existingParentPrefix.replace(/\/$/, '') + '/' + mountPrefix.replace(/^\//, '')
            : mountPrefix;
          prefixByFile.set(targetFile, combined);
        }
      }
    }
  }
  return prefixByFile;
}

export function scanDirectoryForRoutes(targetDir: string, secretKey: string): AnalyzedRoute[] {
  const sourceFiles: string[] = [];
  const testCorpus = collectTestReferences(targetDir);
  const ignorePatterns = loadIgnorePatterns(targetDir);

  function walk(currentDir: string) {
    if (!fs.existsSync(currentDir)) return;
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      if (['node_modules', 'dist', '.git', 'coverage'].includes(entry.name)) continue;
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (/\.(ts|js)$/i.test(entry.name) && !/\.(test|spec|d)\.(ts|js)$/i.test(entry.name)) {
        sourceFiles.push(path.resolve(fullPath));
      }
    }
  }
  walk(targetDir);

  const autoMountPrefixes = buildCrossFileMountPrefixMap(sourceFiles);
  const results: AnalyzedRoute[] = [];
  for (const filePath of sourceFiles) {
    const autoPrefix = autoMountPrefixes.get(filePath) || '';
    const fileRoutes = parseFileRoutes(filePath, secretKey, testCorpus, autoPrefix);
    for (const r of fileRoutes) {
      const relFile = path.relative(targetDir, r.file);
      if (!isRouteIgnored(r.fullRoute, relFile, ignorePatterns)) {
        results.push(r);
      }
    }
  }
  return results;
}

function parseFileRoutes(
  filePath: string,
  secretKey: string,
  testCorpus: string,
  autoDetectedPrefix: string
): AnalyzedRoute[] {
  const rawContent = fs.readFileSync(filePath, 'utf8').replace(/^\uFEFF/, '');
  const lines = rawContent.split(/\r?\n/);
  const routes: AnalyzedRoute[] = [];

  const prefixMatch = rawContent.match(/\/\/\s*@(?:stelfid|aegis)-prefix\s+([^\s]+)/i);
  const annotatedPrefix = prefixMatch ? prefixMatch[1].trim() : '';
  const activePrefix = annotatedPrefix || autoDetectedPrefix;
  const prefixSource: 'auto-mount' | 'annotation' | 'none' = annotatedPrefix
    ? 'annotation'
    : (autoDetectedPrefix ? 'auto-mount' : 'none');

  const globalFileAuth: string[] = [];
  const globalUseRegex = /\b(?:app|router|[a-zA-Z0-9_$]*Router)\.use\s*\(\s*([a-zA-Z_][a-zA-Z0-9_.]*)\s*(?:\(|,|\))/g;
  let gMatch: RegExpExecArray | null;
  while ((gMatch = globalUseRegex.exec(rawContent)) !== null) {
    const fnName = gMatch[1];
    if (!IGNORED_IDENTIFIERS.has(fnName) && AUTH_KEYWORD_REGEX.test(fnName)) {
      globalFileAuth.push(fnName);
    }
  }

  const methodStartRegex = /\b(?:app|router|[a-zA-Z0-9_$]*Router)\.(get|post|put|delete|patch)\s*\(/i;
  const stringLiteralRegex = /^\s*['"`]([^'"`]+)['"`]/;
  let inBlockComment = false;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();
    if (inBlockComment) {
      if (trimmed.includes('*/')) inBlockComment = false;
      continue;
    }
    if (trimmed.startsWith('/*')) {
      if (!trimmed.includes('*/')) inBlockComment = true;
      continue;
    }
    if (trimmed.startsWith('//')) continue;

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
      if (nextLineRoute) rawRoute = nextLineRoute[1];
    }
    if (!rawRoute) continue;

    const cleanRaw = rawRoute === '/' ? '' : rawRoute.replace(/^\//, '');
    const fullRoute = activePrefix
      ? (cleanRaw ? activePrefix.replace(/\/$/, '') + '/' + cleanRaw : activePrefix)
      : rawRoute;
    const hash = hashRoute(method, fullRoute, secretKey);

    let endLine = i;
    let openParens = 0;
    let started = false;
    let inString: string | null = null;

    for (let j = i; j < lines.length; j++) {
      const line = lines[j];
      for (let k = 0; k < line.length; k++) {
        const char = line[k];
        const prevChar = k > 0 ? line[k - 1] : '';
        if (!inString && char === '/' && line[k + 1] === '/') break;
        if ((char === "'" || char === '"' || char === '`') && prevChar !== '\\') {
          if (!inString) inString = char;
          else if (inString === char) inString = null;
          continue;
        }
        if (!inString) {
          if (char === '(') { openParens++; started = true; }
          else if (char === ')') { openParens--; }
        }
      }
      if (started && openParens <= 0) {
        endLine = j;
        break;
      }
    }

    const prevLineText = i > 0 ? lines[i - 1] : '';
    const prev2LineText = i > 1 ? lines[i - 2] : '';
    const snippetText = prev2LineText + '\n' + prevLineText + '\n' + lines.slice(i, endLine + 1).join('\n');

    const keepMatch = snippetText.match(/\/\/\s*@(?:stelfid-keep|keep-route|aegis-keep)(?:\s*[:=]?\s*(.*))?$/im);
    const isKeepExempt = Boolean(keepMatch);
    const keepReason = keepMatch ? (keepMatch[1]?.trim() || 'Intentional low-frequency / emergency route') : null;

    const depMatch = snippetText.match(/\/\/\s*@(?:stelfid-deprecated|deprecate-route)(?:\s*[:=]?\s*(.*))?$/im);
    const isDeprecatedStage = Boolean(depMatch);
    const sunsetDate = depMatch ? (depMatch[1]?.trim() || 'pending-sunset') : null;

    const detectedAuth = new Set<string>(globalFileAuth);
    if (/\/\/\s*@(?:stelfid|aegis)-auth/i.test(snippetText)) {
      detectedAuth.add('@stelfid-auth');
    }

    const bodySnippet = lines.slice(i, endLine + 1).join('\n');
    const headerMatch = bodySnippet.match(/\b(?:app|router|[a-zA-Z0-9_$]*Router)\.(?:get|post|put|delete|patch)\s*\(\s*['"`][^'"`]+['"`]\s*,([\s\S]*)/i);
    if (headerMatch) {
      const beforeArrow = headerMatch[1].split('=>')[0] || headerMatch[1];
      const beforeFn = beforeArrow.split(/\bfunction\b/)[0] || beforeArrow;
      const mwZone = beforeFn.replace(/\(\s*(?:req|request)\b[^)]*\)\s*$/i, '');
      const ids = mwZone.match(/\b[a-zA-Z_][a-zA-Z0-9_.]*\b/g) || [];
      for (const id of ids) {
        if (!IGNORED_IDENTIFIERS.has(id) && AUTH_KEYWORD_REGEX.test(id)) {
          detectedAuth.add(id);
        }
      }
    }

    const authList = Array.from(detectedAuth);
    const referencedInTests = testCorpus.includes(rawRoute) || testCorpus.includes(fullRoute);

    routes.push({
      file: filePath,
      method,
      rawRoute,
      fullRoute,
      prefixSource,
      line: i + 1,
      endLine: endLine + 1,
      hash,
      isAuthenticated: authList.length > 0,
      authMiddlewares: authList,
      isKeepExempt,
      keepReason,
      isDeprecatedStage,
      sunsetDate,
      referencedInTests
    });

    i = endLine;
  }
  return routes;
}
