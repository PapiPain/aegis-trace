import express from 'express';
import { aegisTrace } from '@aegistrace/node-sdk';

const app = express();
const PORT = 3000;

app.use(aegisTrace({
  apiKey: 'aegis_live_test123',
  clientSecret: 'sec_secretkey_test987',
  ingestionUrl: 'http://localhost:4000/v1/telemetry',
  flushIntervalMs: 3000
}));

// Endpoints de prueba
app.get('/api/users', (_req, res) => {
  res.json({ message: 'Listado general de usuarios' });
});

// Ruta dinámica con parámetro :id
app.get('/api/users/:id', (req, res) => {
  res.json({ userId: req.params.id, status: 'active' });
});


app.listen(PORT, () => {
  console.log(`[Host App] Servidor corriendo en http://localhost:${PORT}`);
});