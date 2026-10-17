import express from 'express';
import { aegisTrace } from '@aegis-trace/node-sdk';

const app = express();
const PORT = 3000;

app.use(express.json());

// Middleware de telemetría Zero-Knowledge
app.use(aegisTrace({
  apiKey: 'aegis_live_test123',
  clientSecret: 'sec_secretkey_test987',
  ingestionUrl: 'http://localhost:4000/v1/telemetry',
  flushIntervalMs: 2000
}));

// ==========================================
// RUTAS ACTIVAS (Recibirán tráfico de prueba)
// ==========================================

app.get('/api/users', (_req, res) => {
  res.json({ message: 'Listado general de usuarios' });
});

app.get('/api/users/:id', (req, res) => {
  res.json({ userId: req.params.id, status: 'active' });
});

app.post('/api/users', (req, res) => {
  res.status(201).json({ message: 'Usuario creado', data: req.body });
});

// ==========================================
// RUTAS ZOMBI (Nunca recibirán peticiones)
// Deben ser detectadas por AegisTrace CLI
// ==========================================

app.get('/api/legacy/export-v1', (_req, res) => {
  res.json({ deprecated: true, warning: 'Migrar a v2' });
});

app.delete('/api/admin/purge-cache', (_req, res) => {
  res.json({ status: 'purged' });
});

app.listen(PORT, () => {
  console.log(`[Host App] Servidor corriendo en http://localhost:${PORT}`);
});