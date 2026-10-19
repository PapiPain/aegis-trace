import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { createHmac } from 'crypto';

interface ScannedRoute {
  method: string;
  rawRoute: string;
  fullRoute: string;
  startLine: number;
  endLine: number;
  hash: string;
  isAuthenticated: boolean;
  authMiddlewares: string[];
  isKeepExempt: boolean;
  keepReason: string | null;
  hits: number;
}

const AUTH_KEYWORD_REGEX = /(?:auth|jwt|token|guard|protect|session|admin|role|permission|passport|clerk|supabase|bearer|verify|private|secure|logged|requireAuth|isAuthenticated|checkRole|apiKeyAuth)/i;

const IGNORED_IDENTIFIERS = new Set([
  'req', 'res', 'next', 'async', 'await', 'err', 'request', 'response', 'app', 'router',
  'aegisTrace', 'aegisTraceMiddleware', 'stelfidTelemetry', 'apiKey', 'secretKey', 'express',
  'json', 'urlencoded', 'cors', 'helmet', 'morgan', 'compression', 'cookieParser', 'rateLimit',
  'true', 'false', 'null'
]);

function normalizeRoute(routePattern: string): string {
  let normalized = routePattern.trim().toLowerCase();
  normalized = normalized.replace(/\/+/g, '/');
  normalized = normalized.replace(/:[a-zA-Z0-9_]+/g, ':param');
  if (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }
  return normalized.startsWith('/') ? normalized : '/' + normalized;
}

function hashRoute(method: string, routePattern: string, secretKey: string): string {
  const canonical = method.toUpperCase() + ':' + normalizeRoute(routePattern);
  return createHmac('sha256', secretKey).update(canonical).digest('hex');
}

function loadLocalTelemetry(workspaceRoot: string): {
  map: Map<string, number>;
  env: string;
  days: number;
} {
  const candidates = [
    path.join(workspaceRoot, '.stelfid-local.json'),
    path.join(workspaceRoot, '.aegis-local.json'),
    path.join(workspaceRoot, 'apps', 'test-service', '.aegis-local.json')
  ];
  const map = new Map<string, number>();
  let env = 'local';
  let days = 0;

  const found = candidates.find(p => fs.existsSync(p));
  if (!found) {
    return { map, env, days };
  }

  try {
    const raw = JSON.parse(fs.readFileSync(found, 'utf8').replace(/^\uFEFF/, ''));
    if (raw._meta) {
      env = raw._meta.environment || 'local';
      if (raw._meta.observationStartedAt) {
        days = Math.max(0, (Date.now() - new Date(raw._meta.observationStartedAt).getTime()) / 86400000);
      }
    }
    const entries = raw.routes || raw;
    for (const [hash, info] of Object.entries(entries as Record<string, any>)) {
      if (hash === '_meta') continue;
      map.set(hash, Number(info && info.calls ? info.calls : 1));
    }
  } catch {
    // Ignore parse error
  }
  return { map, env, days };
}

function parseDocumentRoutes(doc: vscode.TextDocument, secretKey: string, telemetry: Map<string, number>): ScannedRoute[] {
  const content = doc.getText();
  const lines = content.split(/\r?\n/);
  const routes: ScannedRoute[] = [];

  const prefixCommentMatch = content.match(/\/\/\s*@(?:stelfid|aegis)-prefix\s+([^\s]+)/i);
  const activePrefix = prefixCommentMatch ? prefixCommentMatch[1].trim() : '';

  const globalFileAuth: string[] = [];
  const globalUseRegex = /\b(?:app|router)\.use\s*\(\s*([a-zA-Z_][a-zA-Z0-9_.]*)\s*(?:\(ert{},ert{}\))/g;
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

    const fullRoute = activePrefix
      ? activePrefix.replace(/\/$/, '') + '/' + rawRoute.replace(/^\//, '')
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

    const prevLine = i > 0 ? lines[i - 1] : '';
    const snippetText = prevLine + '\n' + lines.slice(i, endLine + 1).join('\n');

    const keepMatch = snippetText.match(/\/\/\s*@(?:stelfid-keep|keep-route|aegis-keep)(?:\s*[:=]?\s*(.*))?$/im);
    const isKeepExempt = Boolean(keepMatch);
    const keepReason = keepMatch ? (keepMatch[1]?.trim() || 'Intentional route') : null;

    const detectedAuth = new Set<string>(globalFileAuth);
    if (/\/\/\s*@(?:stelfid|aegis)-auth/i.test(snippetText)) {
      detectedAuth.add('@stelfid-auth');
    }

    const bodySnippet = lines.slice(i, endLine + 1).join('\n');
    const headerMatch = bodySnippet.match(/\b(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"`][^'"`]+['"`]\s*,([\s\S]*)/i);
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
    routes.push({
      method,
      rawRoute,
      fullRoute,
      startLine: i,
      endLine,
      hash,
      isAuthenticated: authList.length > 0,
      authMiddlewares: authList,
      isKeepExempt,
      keepReason,
      hits: telemetry.get(hash) || 0
    });

    i = endLine;
  }

  return routes;
}

class StelfidCodeLensProvider implements vscode.CodeLensProvider {
  private _onDidChangeCodeLenses = new vscode.EventEmitter<void>();
  public readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;

  public refresh(): void {
    this._onDidChangeCodeLenses.fire();
  }

  public provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
    const rootPath = workspaceFolder ? workspaceFolder.uri.fsPath : process.cwd();
    const config = vscode.workspace.getConfiguration('aegisTrace');
    const secretKey = config.get<string>('secretKey') || 'sec_secretkey_test987';

    const { map, env, days } = loadLocalTelemetry(rootPath);
    const routes = parseDocumentRoutes(document, secretKey, map);
    const lenses: vscode.CodeLens[] = [];

    for (const r of routes) {
      const range = new vscode.Range(r.startLine, 0, r.startLine, 0);

      if (r.hits > 0) {
        const authBadge = r.isAuthenticated ? '[AUTH: ' + r.authMiddlewares.join(',') + ']' : '[PUBLIC]';
        lenses.push(new vscode.CodeLens(range, {
          title: 'Maiestor Stelfid: ACTIVE (' + r.hits + ' hits) ' + authBadge,
          command: ''
        }));
      } else if (r.isKeepExempt) {
        lenses.push(new vscode.CodeLens(range, {
          title: 'Maiestor Stelfid: EXEMPT / INTENTIONAL (' + (r.keepReason || 'Keep Route') + ')',
          command: ''
        }));
      } else {
        const windowTag = env + ' / ' + days.toFixed(1) + 'd observed';
        const statusTitle = r.isAuthenticated
          ? 'Maiestor Stelfid: UNOBSERVED ROUTE (0 hits in ' + windowTag + ' - Auth: ' + r.authMiddlewares.join(',') + ')'
          : 'Maiestor Stelfid: UNAUTHENTICATED & UNOBSERVED (0 hits in ' + windowTag + ' - Review OWASP API9)';

        lenses.push(new vscode.CodeLens(range, {
          title: statusTitle,
          command: ''
        }));

        lenses.push(new vscode.CodeLens(range, {
          title: 'Safe Prune (Comment Out)',
          command: 'aegisTrace.pruneRoute',
          arguments: [document.uri, r.startLine, r.endLine, r.method + ' ' + r.fullRoute]
        }));

        lenses.push(new vscode.CodeLens(range, {
          title: 'Keep Route (Mark as Intentional/Annual)',
          command: 'aegisTrace.keepRoute',
          arguments: [document.uri, r.startLine, r.method + ' ' + r.fullRoute]
        }));
      }
    }

    return lenses;
  }
}

export function activate(context: vscode.ExtensionContext) {
  const diagnosticCollection = vscode.languages.createDiagnosticCollection('maiestorStelfid');
  const codeLensProvider = new StelfidCodeLensProvider();
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.command = 'aegisTrace.activateCloud';
  statusBar.show();

  const updateDiagnostics = (doc: vscode.TextDocument) => {
    if (!['typescript', 'javascript'].includes(doc.languageId)) return;
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(doc.uri);
    const rootPath = workspaceFolder ? workspaceFolder.uri.fsPath : process.cwd();
    const config = vscode.workspace.getConfiguration('aegisTrace');
    const secretKey = config.get<string>('secretKey') || 'sec_secretkey_test987';

    const { map, env, days } = loadLocalTelemetry(rootPath);
    const routes = parseDocumentRoutes(doc, secretKey, map);
    const diags: vscode.Diagnostic[] = [];

    let unobserved = 0;
    let unauthZero = 0;

    for (const r of routes) {
      if (r.hits === 0 && !r.isKeepExempt) {
        unobserved++;
        if (!r.isAuthenticated) unauthZero++;
        const range = new vscode.Range(r.startLine, 0, r.endLine, 100);
        const msg = r.isAuthenticated
          ? '[Maiestor Stelfid] Unobserved Route (' + r.method + ' ' + r.fullRoute + '): 0 hits in ' + env + ' (' + days.toFixed(1) + 'd window). Verify coverage or mark with // @stelfid-keep before pruning.'
          : '[Maiestor Stelfid] Unauthenticated & Unobserved Route (' + r.method + ' ' + r.fullRoute + '): 0 hits in ' + env + ' & no Auth middleware detected (OWASP API9:2023).';
        const severity = r.isAuthenticated ? vscode.DiagnosticSeverity.Information : vscode.DiagnosticSeverity.Warning;
        const diag = new vscode.Diagnostic(range, msg, severity);
        diag.source = 'Maiestor Stelfid';
        diags.push(diag);
      }
    }

    diagnosticCollection.set(doc.uri, diags);
    statusBar.text = unobserved > 0
      ? '$(shield) Maiestor Stelfid: ' + unobserved + ' Unobserved (' + unauthZero + ' Unauth)'
      : '$(shield) Maiestor Stelfid: All Routes Verified';
    codeLensProvider.refresh();
  };

  context.subscriptions.push(
    vscode.languages.registerCodeLensProvider(['typescript', 'javascript'], codeLensProvider),
    diagnosticCollection,
    statusBar,
    vscode.workspace.onDidOpenTextDocument(updateDiagnostics),
    vscode.workspace.onDidSaveTextDocument(updateDiagnostics),
    vscode.workspace.onDidChangeTextDocument(e => updateDiagnostics(e.document))
  );

  vscode.commands.registerCommand('aegisTrace.pruneRoute', async (uri: vscode.Uri, startLine: number, endLine: number, label: string) => {
    const doc = await vscode.workspace.openTextDocument(uri);
    const edit = new vscode.WorkspaceEdit();
    const timestamp = new Date().toISOString();
    edit.insert(uri, new vscode.Position(startLine, 0), '/* [Maiestor Stelfid Safe-Retirement: ' + label + ' - ' + timestamp + ']\n');
    const lastLineText = doc.lineAt(endLine).text;
    edit.insert(uri, new vscode.Position(endLine, lastLineText.length), '\n*/');
    await vscode.workspace.applyEdit(edit);
    await doc.save();
    vscode.window.showInformationMessage('Maiestor Stelfid: Safely commented out route ' + label);
  });

  vscode.commands.registerCommand('aegisTrace.keepRoute', async (uri: vscode.Uri, startLine: number, label: string) => {
    const reason = await vscode.window.showInputBox({
      prompt: 'Why should this low-frequency route be kept? (e.g. annual-webhook, emergency-recovery, partner-integration)',
      value: 'intentional-low-frequency-route'
    });
    if (!reason) return;
    const edit = new vscode.WorkspaceEdit();
    edit.insert(uri, new vscode.Position(startLine, 0), '// @stelfid-keep: ' + reason + '\n');
    await vscode.workspace.applyEdit(edit);
    const doc = await vscode.workspace.openTextDocument(uri);
    await doc.save();
    vscode.window.showInformationMessage('Maiestor Stelfid: Marked ' + label + ' as intentional (@stelfid-keep).');
  });

  vscode.commands.registerCommand('aegisTrace.activateCloud', async () => {
    vscode.window.showInformationMessage('Maiestor Stelfid Cloud: Multi-node telemetry sync configuration.');
  });

  vscode.commands.registerCommand('aegisTrace.scanWorkspace', () => {
    if (vscode.window.activeTextEditor) {
      updateDiagnostics(vscode.window.activeTextEditor.document);
    }
  });

  if (vscode.window.activeTextEditor) {
    updateDiagnostics(vscode.window.activeTextEditor.document);
  }
}

export function deactivate() {}
