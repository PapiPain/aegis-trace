import * as fs from 'fs';
import * as path from 'path';
import { generateBlindHash, normalizeRoute } from './crypto';

export type RetirementState =
  | 'ACTIVE'
  | 'EXEMPT_KEEP'
  | 'LOW_FREQUENCY_PROTECTED'
  | 'DYNAMIC_OR_PLUGIN_PROTECTED'
  | 'STAGE_DEPRECATED'
  | 'UNOBSERVED_LOW_CONFIDENCE'
  | 'CANDIDATE_FOR_MANUAL_REVIEW';

export interface AnalyzedRoute {
  method: string;
  rawRoute: string;
  fullRoute: string;
  normalizedRoute: string;
  prefixSource: 'direct' | 'auto-mount' | 'chained-route' | 'plugin-registered';
  hash: string;
  file: string;
  line: number;
  endLine: number;
  isKeepExempt: boolean;
  keepReason: string | null;
  isDeprecatedStage: boolean;
  sunsetDate: string | null;
  isAuthenticated: boolean;
  authMiddlewares: string[];
  referencedInTests: boolean;
  isLowFrequencyPattern: boolean;
  lowFrequencyReason: string | null;
  hasDynamicPattern: boolean;
}

const AUTH_PATTERNS = /auth|jwt|bearer|session|guard|protect|passport|clerk|auth0|supabase|verifyToken|requireRole|apiKey|oauth|sso|externalAuth/i;
const LOW_FREQ_ROUTE_PATTERNS = /(\/webhook|\/webhooks|\/callback|\/callbacks|\/cron|\/scheduled|\/monthly|\/annual|\/quarterly|\/reconcil|\/admin|\/internal|\/backoffice|\/audit-export|\/disaster-recovery|\/migration)/i;

function collectFiles(dir: string, out: string[] = []): string[] {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (['node_modules', 'dist', '.git', '.stelfid-backups'].includes(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) collectFiles(full, out);
    else if (/\.(ts|js|mjs|cjs)$/.test(entry.name)) out.push(full);
  }
  return out;
}

function discoverRouterMounts(files: string[]): Map<string, { prefix: string; globalAuth: string[] }> {
  const importVarToFile = new Map<string, string>();
  const fileToMountInfo = new Map<string, { prefix: string; globalAuth: string[] }>();

  for (const file of files) {
    const content = fs.readFileSync(file, 'utf8');
    const dir = path.dirname(file);

    const impRegex = /(?:import\s+(\w+)\s+from\s+['"]([^'"]+)['"]|const\s+(\w+)\s*=\s*require\(['"]([^'"]+)['"]\))/g;
    let m: RegExpExecArray | null;
    while ((m = impRegex.exec(content)) !== null) {
      const varName = m[1] || m[3];
      const relPath = m[2] || m[4];
      if (varName && relPath && relPath.startsWith('.')) {
        for (const ext of ['.ts', '.js', '/index.ts', '/index.js', '']) {
          const resolved = path.resolve(dir, relPath + ext);
          if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
            importVarToFile.set(file + '::' + varName, resolved);
            break;
          }
        }
      }
    }

    // Detectar app.use('/prefix', [optionalAuth], routerVar)
    const useRegex = /\b(?:app|router|server|\w*Router|\w*App)\.use\(\s*['"]([^'"]+)['"]\s*,\s*([^)]+)\)/g;
    while ((m = useRegex.exec(content)) !== null) {
      const prefix = m[1];
      const argsRaw = m[2].split(',').map(s => s.trim()).filter(Boolean);
      const targetVar = argsRaw[argsRaw.length - 1];
      const mountAuths = argsRaw.slice(0, -1).filter(a => AUTH_PATTERNS.test(a));
      const targetFile = importVarToFile.get(file + '::' + targetVar);
      if (targetFile) {
        fileToMountInfo.set(targetFile, { prefix, globalAuth: mountAuths });
      }
    }
  }
  return fileToMountInfo;
}

export function scanDirectoryForRoutes(targetDir: string, secretKey: string): AnalyzedRoute[] {
  const allFiles = collectFiles(targetDir);
  const testFiles = allFiles.filter(f => /\.(test|spec)\.(ts|js)$/.test(f));
  const sourceFiles = allFiles.filter(f => !/\.(test|spec)\.(ts|js)$/.test(f));
  const testCorpus = testFiles.map(f => fs.readFileSync(f, 'utf8')).join('\n');
  const routerMounts = discoverRouterMounts(sourceFiles);
  const results: AnalyzedRoute[] = [];

  for (const file of sourceFiles) {
    const raw = fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '');
    const lines = raw.split(/\r?\n/);
    const mountInfo = routerMounts.get(file);
    const filePrefix = mountInfo ? mountInfo.prefix : '';

    // Detectar router.use(externalAuthMiddleware) a nivel de archivo
    const fileLevelAuths: string[] = mountInfo ? [...mountInfo.globalAuth] : [];
    for (const line of lines) {
      const routerUseMatch = line.match(/\b(?:router|app)\.use\(\s*([a-zA-Z0-9_$.]+)\s*\)/);
      if (routerUseMatch && AUTH_PATTERNS.test(routerUseMatch[1])) {
        if (!fileLevelAuths.includes(routerUseMatch[1])) fileLevelAuths.push(routerUseMatch[1]);
      }
    }

    const isPluginFile = /plugin|extension|addons/i.test(path.basename(file)) || /export\s+function\s+register\w*Plugin/i.test(raw);

    let inBlockComment = false;
    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i];
      const trimmed = lineText.trim();
      if (trimmed.startsWith('/*')) inBlockComment = true;
      if (inBlockComment) {
        if (trimmed.includes('*/')) inBlockComment = false;
        continue;
      }
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      // Soportar: app.get('/path', ...) o router.post('/path', [mw1, mw2], ...) o pluginApp.get(...)
      const stdMatch = lineText.match(/\b(?:app|router|server|\w*Router|\w*App)\.(get|post|put|delete|patch)\(\s*['"`]([^'"`]+)['"`]\s*(?:,\s*(.+))?$/i);
      // Soportar: app.route('/path').get(mw, handler)
      const chainedMatch = !stdMatch ? lineText.match(/\b(?:app|router)\.route\(\s*['"`]([^'"`]+)['"`]\s*\)\.(get|post|put|delete|patch)\((.*)$/i) : null;

      if (!stdMatch && !chainedMatch) continue;

      const method = (stdMatch ? stdMatch[1] : chainedMatch![2]).toUpperCase();
      const rawRoute = stdMatch ? stdMatch[2] : chainedMatch![1];
      const restOfCall = (stdMatch ? (stdMatch[3] || '') : (chainedMatch![3] || ''));

      // Determinar bloque completo (inicio a fin del handler)
      let endLine = i + 1;
      let parenDepth = 0;
      for (let j = i; j < lines.length; j++) {
        for (const ch of lines[j]) {
          if (ch === '(') parenDepth++;
          else if (ch === ')') parenDepth--;
        }
        if (parenDepth <= 0 && j >= i) {
          endLine = j + 1;
          break;
        }
      }

      // Recolectar UNICAMENTE lineas de comentario inmediatamente encima de esta ruta
      // (deteniendose si hay una linea en blanco o codigo de otra ruta previa).
      const attachedComments: string[] = [];
      for (let k = i - 1; k >= Math.max(0, i - 5); k--) {
        const prevTrim = lines[k].trim();
        if (prevTrim.startsWith('//') || prevTrim.startsWith('/*') || prevTrim.startsWith('*') || prevTrim.endsWith('*/')) {
          attachedComments.unshift(prevTrim);
        } else {
          break;
        }
      }
      const prevWindow = attachedComments.join('\n');
      // Exigir directiva explicita (evitar falsos positivos como 'SIN @stelfid-keep')
      const keepMatch = !/\b(?:sin|no|without|not)\s+@(?:stelfid|aegis)-keep/i.test(prevWindow)
        ? prevWindow.match(/@(?:stelfid|aegis)-keep(?:\s+([^\s*)\]]+))?/i)
        : null;
      const depMatch = !/\b(?:sin|no|without|not)\s+@(?:stelfid|aegis)-deprecated/i.test(prevWindow)
        ? prevWindow.match(/@(?:stelfid|aegis)-deprecated(?:\s+([^\s*)\]]+))?/i)
        : null;

      // Extraer middlewares de autenticacion (incluyendo callbacks dentro de arrays [mw1, mw2])
      const blockSnippet = lines.slice(i, Math.min(lines.length, i + 4)).join(' ');
      const tokens = (restOfCall + ' ' + blockSnippet)
        .replace(/[\[\]()]/g, ' ')
        .split(/[\s,]+/)
        .map(t => t.trim())
        .filter(Boolean);
      const detectedAuths = [...fileLevelAuths];
      for (const tok of tokens) {
        if (AUTH_PATTERNS.test(tok) && !tok.startsWith('req') && !tok.startsWith('res') && !tok.includes('=>') && !tok.includes('/')) {
          const cleanTok = tok.replace(/[^a-zA-Z0-9_$.]/g, '');
          if (cleanTok && !detectedAuths.includes(cleanTok)) detectedAuths.push(cleanTok);
        }
      }

      const fullRoute = filePrefix
        ? (filePrefix.endsWith('/') ? filePrefix.slice(0, -1) : filePrefix) + (rawRoute.startsWith('/') ? rawRoute : '/' + rawRoute)
        : rawRoute;
      const normalized = normalizeRoute(fullRoute);
      const hash = generateBlindHash(method, fullRoute, secretKey);

      // Detectar si es ruta con patron de baja frecuencia (webhook, callback, tarea mensual/anual, admin)
      const isLowFrequencyPattern = LOW_FREQ_ROUTE_PATTERNS.test(fullRoute);
      const lowFrequencyReason = isLowFrequencyPattern
        ? 'Conservative Lexical Path Heuristic (Matches /webhook, /admin, /monthly, /cron — Precautionary guard by route name, NOT runtime evidence of low-frequency usage)'
        : null;

      // Detectar patrones dinamicos complejos (regex en ruta, comodines *, interpolacion ${})
      const hasDynamicPattern = /[\*\$\(\)\?]/.test(rawRoute);
      const prefixSource: AnalyzedRoute['prefixSource'] = isPluginFile
        ? 'plugin-registered'
        : chainedMatch
        ? 'chained-route'
        : filePrefix
        ? 'auto-mount'
        : 'direct';

      const referencedInTests = testCorpus.includes(fullRoute) || testCorpus.includes(rawRoute);

      results.push({
        method,
        rawRoute,
        fullRoute,
        normalizedRoute: normalized,
        prefixSource,
        hash,
        file,
        line: i + 1,
        endLine,
        isKeepExempt: Boolean(keepMatch),
        keepReason: keepMatch ? (keepMatch[1] || 'intentional-keep') : null,
        isDeprecatedStage: Boolean(depMatch),
        sunsetDate: depMatch ? (depMatch[1] || 'staged') : null,
        isAuthenticated: detectedAuths.length > 0,
        authMiddlewares: detectedAuths,
        referencedInTests,
        isLowFrequencyPattern,
        lowFrequencyReason,
        hasDynamicPattern
      });
    }
  }
  return results;
}
