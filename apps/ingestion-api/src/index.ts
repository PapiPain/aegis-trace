import express from 'express';
import * as fs from 'fs';
import * as path from 'path';
import { TransactionalBatchIngestor } from './transactionalIngestor';

const app = express();
app.use(express.json({ limit: '1mb' }));

const CLUSTER_DB_FILE = path.join(process.cwd(), '.stelfid-cluster-store.json');
const ingestor = new TransactionalBatchIngestor(CLUSTER_DB_FILE);

app.post('/v1/telemetry/deltas', (req, res) => {
  try {
    const result = ingestor.processBatchTransactionally(req.body);
    return res.status(200).json(result);
  } catch (err: any) {
    return res.status(400).json({ ok: false, error: err?.message || 'Invalid batch' });
  }
});

app.get('/v1/telemetry/cluster-summary', (_req, res) => {
  if (fs.existsSync(CLUSTER_DB_FILE)) {
    return res.json(JSON.parse(fs.readFileSync(CLUSTER_DB_FILE, 'utf8')));
  }
  return res.json({ _meta: { nodeCount: 0 }, routes: {} });
});

const PORT = process.env.PORT || 4000;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log('Maiestor Stelfid Transactional Ingestion API (v1.6.4) listening on port ' + PORT);
  });
}
export { app, ingestor };
