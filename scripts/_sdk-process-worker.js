const fs = require('fs');
const { stelfidTelemetry } = require('../packages/sdk-node/dist/index');
(async () => {
  const mw = stelfidTelemetry({
    secretKey: process.env.W_SECRET,
    nodeId: 'pid-' + process.pid,
    environment: 'production',
    ingestUrl: process.env.W_URL,
    localFilePath: process.env.W_FILE,
    flushIntervalMs: 600000
  });
  const bootStats = mw.getSyncStats();
  const hits = Number(process.env.W_HITS || 0);
  for (let i = 0; i < hits; i++) {
    let fin = null;
    mw({ baseUrl: '', route: { path: process.env.W_ROUTE }, path: process.env.W_ROUTE, url: process.env.W_ROUTE, method: 'GET' },
       { statusCode: 200, setHeader: () => {}, on: (e, cb) => { if (e === 'finish') fin = cb; } }, () => {});
    if (fin) fin();
  }
  const flushOk = await mw.flushNow();
  const endStats = mw.getSyncStats();
  const disk = JSON.parse(fs.readFileSync(process.env.W_FILE, 'utf8'));
  console.log(JSON.stringify({
    pid: process.pid,
    reconstructedOnBoot: bootStats.queued_batch_ids,
    flushOk,
    ackedIds: endStats.acked_batch_ids,
    queuedOnDisk: (disk._meta?.sealedBatchQueue || []).map(b => ({ batchId: b.batchId, deltaCalls: b.deltas?.[0]?.deltaCalls })),
    unsealedOnDisk: Object.values(disk.routes || {}).reduce((a, r) => a + Number(r.pendingDeltaCalls || 0), 0)
  }));
  process.exit(0);
})();
