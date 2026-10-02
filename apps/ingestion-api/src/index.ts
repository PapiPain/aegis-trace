import express, { Response } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { verifyAegisSignature } from './verify';
import { upsertTelemetryEvent, getActiveHashes, getAllTelemetry } from './db';

const app = express();
const PORT = process.env.PORT || 4000;

// Configuración de Helmet permitiendo scripts locales para el dashboard
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"]
    }
  }
}));

app.use(cors({ origin: '*' }));

app.use(express.json({
  verify: (req: any, _res, buf) => {
    req.rawBody = buf.toString('utf8');
  }
}));

const CLIENT_KEYS: Record<string, string> = {
  'aegis_live_test123': 'sec_secretkey_test987'
};

// Ingesta persistida en SQLite
app.post('/v1/telemetry', (req: any, res: Response): void => {
  const apiKey = req.header('X-Aegis-Key');
  const timestamp = req.header('X-Aegis-Timestamp');
  const signature = req.header('X-Aegis-Signature');

  if (!apiKey || !CLIENT_KEYS[apiKey]) {
    res.status(401).json({ error: 'Credenciales invalidas' });
    return;
  }

  const clientSecret = CLIENT_KEYS[apiKey];
  const verification = verifyAegisSignature(req.rawBody || '', timestamp, signature, clientSecret);
  if (!verification.isValid) {
    res.status(403).json({ error: verification.error });
    return;
  }

  const { events } = req.body;
  if (!Array.isArray(events)) {
    res.status(400).json({ error: 'Estructura de datos invalida' });
    return;
  }

  const now = Date.now();
  for (const event of events) {
    upsertTelemetryEvent(apiKey, event.routeHash, event.method, event.count || 1, now);
  }

  console.log(`\n[AegisTrace] Telemetria guardada en SQLite para ${apiKey}: ${events.length} evento(s)`);
  res.status(202).json({ status: 'accepted' });
});

// Consulta de hashes guardados para el CLI
app.get('/v1/telemetry/hashes', (req: any, res: Response): void => {
  const apiKey = req.header('X-Aegis-Key');

  if (!apiKey || !CLIENT_KEYS[apiKey]) {
    res.status(401).json({ error: 'Credenciales invalidas' });
    return;
  }

  const hashes = getActiveHashes(apiKey);

  res.json({
    apiKey,
    totalObserved: hashes.length,
    hashes
  });
});

// Endpoint JSON para consumo del dashboard
app.get('/api/dashboard/stats', (req: any, res: Response): void => {
  const apiKey = (req.query.apiKey as string) || 'aegis_live_test123';
  const data = getAllTelemetry(apiKey);
  res.json({ apiKey, totalEvents: data.length, records: data });
});

// UI Web minimalista
app.get('/dashboard', (_req, res: Response): void => {
  res.send(`
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>AegisTrace — Live Telemetry</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 2rem; }
    .container { max-width: 960px; margin: 0 auto; }
    h1 { color: #58a6ff; font-size: 1.5rem; border-bottom: 1px solid #21262d; padding-bottom: 0.5rem; }
    .stats-card { display: flex; gap: 1rem; margin-bottom: 1.5rem; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1rem; flex: 1; }
    .card-num { font-size: 1.8rem; font-weight: bold; color: #3fb950; }
    table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 6px; overflow: hidden; border: 1px solid #30363d; margin-top: 1rem; }
    th, td { text-align: left; padding: 0.75rem 1rem; border-bottom: 1px solid #21262d; font-size: 0.85rem; }
    th { background: #21262d; color: #8b949e; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }
    .method { font-weight: bold; padding: 2px 6px; border-radius: 4px; font-size: 0.75rem; display: inline-block; }
    .get { background: rgba(31, 111, 235, 0.15); color: #58a6ff; border: 1px solid #1f6feb; }
    .post { background: rgba(63, 185, 80, 0.15); color: #3fb950; border: 1px solid #238636; }
    .other { background: rgba(139, 148, 158, 0.15); color: #8b949e; border: 1px solid #30363d; }
    .hash { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; color: #f0883e; word-break: break-all; }
  </style>
</head>
<body>
  <div class="container">
    <h1>AegisTrace &mdash; Monitor Criptográfico de Telemetría</h1>
    <div class="stats-card">
      <div class="card">
        <div>Endpoints Únicos Telemetrados</div>
        <div class="card-num" id="totalHashes">0</div>
      </div>
      <div class="card">
        <div>Total Invocaciones Acumuladas</div>
        <div class="card-num" id="totalCalls">0</div>
      </div>
    </div>
    <table>
      <thead>
        <tr>
          <th>Método</th>
          <th>Blind Hash (Zero-Knowledge)</th>
          <th>Invocaciones</th>
          <th>Último Evento</th>
        </tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
  <script>
    async function loadStats() {
      try {
        const res = await fetch('/api/dashboard/stats?apiKey=aegis_live_test123');
        const data = await res.json();
        document.getElementById('totalHashes').innerText = data.records.length;
        const totalCalls = data.records.reduce((acc, r) => acc + r.call_count, 0);
        document.getElementById('totalCalls').innerText = totalCalls;

        const tbody = document.getElementById('rows');
        tbody.innerHTML = data.records.map(r => {
          const m = (r.method || 'GET').toUpperCase();
          const badgeClass = m === 'GET' ? 'get' : (m === 'POST' ? 'post' : 'other');
          const dateStr = new Date(r.last_seen).toLocaleTimeString();
          return '<tr>' +
            '<td><span class="method ' + badgeClass + '">' + m + '</span></td>' +
            '<td class="hash">' + r.route_hash + '</td>' +
            '<td>' + r.call_count + '</td>' +
            '<td>' + dateStr + '</td>' +
            '</tr>';
        }).join('');
      } catch (err) {
        console.error('Error actualizando dashboard:', err);
      }
    }
    loadStats();
    setInterval(loadStats, 3000);
  </script>
</body>
</html>
  `);
});

app.listen(PORT, () => {
  console.log(`[AegisTrace] Ingestion API activa con SQLite en http://localhost:${PORT}`);
});