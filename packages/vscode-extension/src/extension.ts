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
  hits: number;
}

const AUTH_KEYWORD_REGEX = /(?:auth|jwt|token|guard|protect|session|admin|role|permission|passport|clerk|supabase|bearer|verify|private|secure|logged|requireAuth|isAuthenticated|checkRole|apiKeyAuth)/i;

const IGNORED_IDENTIFIERS = new Set([
  'req', 'res', 'next', 'async', 'await', 'err', 'request', 'response', 'app', 'router',
  'aegisTrace', 'aegisTraceMiddleware', 'apiKey', 'secretKey', 'express', 'json', 'urlencoded',
  'cors', 'helmet', 'morgan', 'compression', 'cookieParser', 'rateLimit', 'true', 'false', 'null'
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

function loadLocalTelemetry(workspaceRoot: string): Map<string, number> {
  const candidates = [
    path.join(workspaceRoot, '.aegis-local.json'),
    path.join(workspaceRoot, 'apps', 'test-service', '.aegis-local.json')
  ];
  const map = new Map<string, number>();
  const found = candidates.find(p => fs.existsSync(p));
  if (!found) {
    return map;
  }

  try {
    const raw = JSON.parse(fs.readFileSync(found, 'utf8').replace(/^\uFEFF/, ''));
    for (const [hash, info] of Object.entries(raw as Record<string, any>)) {
      map.set(hash, Number(info && info.calls ? info.calls : 1));
    }
  } catch {
    // Ignore parse error
  }
  return map;
}

function parseDocumentRoutes(doc: vscode.TextDocument, secretKey: string, telemetry: Map<string, number>): ScannedRoute[] {
  const content = doc.getText();
  const lines = content.split(/\r?\n/);
  const routes: ScannedRoute[] = [];

  const prefixCommentMatch = content.match(/\/\/\s*@aegis-prefix\s+([^\s]+)/);
  const activePrefix = prefixCommentMatch ? prefixCommentMatch[1].trim() : '';

  const globalFileAuth: string[] = [];
  const globalUseRegex = /\b(?:app|router)\.use\s*\(\s*([a-zA-Z_][a-zA-Z0-9_.]*)\s*(?:\(|,|\))/g;
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
    if (!methodMatch) {
      continue;
    }

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
    if (!rawRoute) {
      continue;
    }

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

    const snippetText = lines.slice(i, endLine + 1).join('\n');
    const detectedAuth = new Set<string>(globalFileAuth);
    if (/\/\/\s*@aegis-auth/i.test(snippetText)) {
      detectedAuth.add('@aegis-auth');
    }

    const headerMatch = snippetText.match(/\b(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"`][^'"`]+['"`]\s*,([\s\S]*)/i);
    if (headerMatch) {
      const beforeArrow = headerMatch[1].split('=>')[0] || headerMatch[1];
      const beforeFn = beforeArrow.split(/\bfunction\b/)[0] || beforeArrow;
      const mwZone = beforeFn.replace(/\(\s*(?:req\vert{}request)\b[^)]*\)\s*$/i, '');
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
      hits: telemetry.get(hash) || 0
    });

    i = endLine;
  }

  return routes;
}

class AegisCodeLensProvider implements vscode.CodeLensProvider {
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
    const apiKey = config.get<string>('apiKey') || '';

    const telemetry = loadLocalTelemetry(rootPath);
    const routes = parseDocumentRoutes(document, secretKey, telemetry);
    const lenses: vscode.CodeLens[] = [];

    for (const r of routes) {
      const range = new vscode.Range(r.startLine, 0, r.startLine, 0);

      if (r.hits > 0) {
        const authBadge = r.isAuthenticated ? '[AUTH: ' + r.authMiddlewares.join(',') + ']' : '[PUBLIC]';
        lenses.push(new vscode.CodeLens(range, {
          title: 'AegisTrace: ACTIVE (' + r.hits + ' hits) ' + authBadge,
          command: ''
        }));
      } else {
        const riskTitle = r.isAuthenticated
          ? 'AegisTrace: ZOMBIE ROUTE (0 hits - Protected by ' + r.authMiddlewares.join(',') + ')'
          : 'AegisTrace: CRITICAL UNAUTHENTICATED ZOMBIE (0 hits - OWASP API9)';

        lenses.push(new vscode.CodeLens(range, {
          title: riskTitle,
          command: ''
        }));

        lenses.push(new vscode.CodeLens(range, {
          title: 'Safe Prune (Comment Out)',
          command: 'aegisTrace.pruneRoute',
          arguments: [document.uri, r.startLine, r.endLine, r.method + ' ' + r.fullRoute]
        }));

        if (!apiKey) {
          lenses.push(new vscode.CodeLens(range, {
            title: 'Connect Cloud Telemetry (7-Day Free Trial)',
            command: 'aegisTrace.activateCloud'
          }));
        }
      }
    }

    return lenses;
  }
}

export function activate(context: vscode.ExtensionContext) {
  const diagnosticCollection = vscode.languages.createDiagnosticCollection('aegisTrace');
  const codeLensProvider = new AegisCodeLensProvider();
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.command = 'aegisTrace.activateCloud';
  statusBar.show();

  const updateDiagnostics = (doc: vscode.TextDocument) => {
    if (!['typescript', 'javascript'].includes(doc.languageId)) {
      return;
    }
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(doc.uri);
    const rootPath = workspaceFolder ? workspaceFolder.uri.fsPath : process.cwd();
    const config = vscode.workspace.getConfiguration('aegisTrace');
    const secretKey = config.get<string>('secretKey') || 'sec_secretkey_test987';

    const telemetry = loadLocalTelemetry(rootPath);
    const routes = parseDocumentRoutes(doc, secretKey, telemetry);
    const diags: vscode.Diagnostic[] = [];

    let zombies = 0;
    let criticals = 0;

    for (const r of routes) {
      if (r.hits === 0) {
        zombies++;
        if (!r.isAuthenticated) {
          criticals++;
        }
        const range = new vscode.Range(r.startLine, 0, r.endLine, 100);
        const msg = r.isAuthenticated
          ? '[AegisTrace] Zombie Endpoint (' + r.method + ' ' + r.fullRoute + '): 0 runtime hits observed.'
          : '[AegisTrace CRITICAL] Unauthenticated Zombie Endpoint (' + r.method + ' ' + r.fullRoute + '): 0 hits & no Auth middleware (OWASP API9:2023).';
        const severity = r.isAuthenticated ? vscode.DiagnosticSeverity.Warning : vscode.DiagnosticSeverity.Error;
        const diag = new vscode.Diagnostic(range, msg, severity);
        diag.source = 'AegisTrace SecOps';
        diags.push(diag);
      }
    }

    diagnosticCollection.set(doc.uri, diags);
    statusBar.text = zombies > 0
      ? '$(shield) AegisTrace: ' + zombies + ' Zombies (' + criticals + ' CRITICAL)'
      : '$(shield) AegisTrace: Protected';
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
    edit.insert(uri, new vscode.Position(startLine, 0), '/* [AegisTrace Auto-Prune: ' + label + ' - ' + timestamp + ']\n');
    const lastLineText = doc.lineAt(endLine).text;
    edit.insert(uri, new vscode.Position(endLine, lastLineText.length), '\n*/');
    await vscode.workspace.applyEdit(edit);
    await doc.save();
    vscode.window.showInformationMessage('AegisTrace: Safely commented out zombie route ' + label);
  });

  vscode.commands.registerCommand('aegisTrace.activateCloud', async () => {
    const choice = await vscode.window.showQuickPick(
      [
        { label: 'Enter existing AegisTrace Cloud API Key', id: 'key' },
        { label: 'Start 7-Day Free Trial - Pro ($49/mo) / Team ($149/mo) / Business ($399/mo)', id: 'trial' }
      ],
      { placeHolder: 'AegisTrace SecOps Cloud - Multi-Node Telemetry & Automated PR Pruning' }
    );

    if (choice && choice.id === 'key') {
      const key = await vscode.window.showInputBox({
        prompt: 'Paste your AEGIS_API_KEY (starts with aegis_live_...)',
        placeHolder: 'aegis_live_xxxxxxxxxxxxxxxx'
      });
      if (key) {
        await vscode.workspace.getConfiguration('aegisTrace').update('apiKey', key, vscode.ConfigurationTarget.Global);
        vscode.window.showInformationMessage('AegisTrace Cloud API Key activated!');
        codeLensProvider.refresh();
      }
    } else if (choice && choice.id === 'trial') {
      vscode.env.openExternal(vscode.Uri.parse('https://github.com/PapiPain/aegis-trace#readme'));
    }
  });

  vscode.commands.registerCommand('aegisTrace.scanWorkspace', () => {
    if (vscode.window.activeTextEditor) {
      updateDiagnostics(vscode.window.activeTextEditor.document);
      vscode.window.showInformationMessage('AegisTrace: Workspace audit updated.');
    }
  });

  if (vscode.window.activeTextEditor) {
    updateDiagnostics(vscode.window.activeTextEditor.document);
  }
}

export function deactivate() {}