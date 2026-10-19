import * as fs from 'fs';
import * as path from 'path';

export interface NodeObservationSlice {
  calls: number;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface AggregatedRouteTelemetry {
  calls: number;
  firstSeenAt: string;
  lastSeen: string;
  statusCodes: Record<string, number>;
  nodeBreakdown: Record<string, NodeObservationSlice>;
}

export interface ClusterStateStore {
  processedBatchIds: Record<string, { processedAt: string; nodeId: string; deltaCount: number }>;
  activeNodes: string[];
  environment: string;
  observationStartedAt: string;
  lastFlushedAt: string;
  routes: Record<string, AggregatedRouteTelemetry>;
}

export class TransactionalBatchIngestor {
  private storePath: string;
  private state: ClusterStateStore;

  constructor(storePath?: string) {
    this.storePath = storePath || path.join(process.cwd(), '.stelfid-cluster-store.json');
    this.state = {
      processedBatchIds: {},
      activeNodes: [],
      environment: 'production',
      observationStartedAt: new Date().toISOString(),
      lastFlushedAt: new Date().toISOString(),
      routes: {}
    };
    this.loadFromDisk();
  }

  private loadFromDisk(): void {
    if (!fs.existsSync(this.storePath)) return;
    try {
      const raw = JSON.parse(fs.readFileSync(this.storePath, 'utf8'));
      if (raw && raw._txState) {
        this.state = raw._txState;
      }
    } catch {}
  }

  public processBatchTransactionally(payload: any): {
    ok: boolean;
    ackedBatchId: string;
    idempotentReplay: boolean;
    appliedDeltas: number;
  } {
    const batchId = String(payload?.batchId || '').trim();
    if (!batchId || !Array.isArray(payload?.deltas)) {
      throw new Error('Missing batchId or deltas array');
    }

    if (this.state.processedBatchIds[batchId]) {
      return {
        ok: true,
        ackedBatchId: batchId,
        idempotentReplay: true,
        appliedDeltas: 0
      };
    }

    const nextState: ClusterStateStore = JSON.parse(JSON.stringify(this.state));
    const nowIso = new Date().toISOString();
    const nodeId = String(payload.nodeId || 'node-unknown');

    nextState.processedBatchIds[batchId] = {
      processedAt: nowIso,
      nodeId,
      deltaCount: payload.deltas.length
    };

    if (!nextState.activeNodes.includes(nodeId)) {
      nextState.activeNodes.push(nodeId);
    }
    if (payload.environment) nextState.environment = payload.environment;
    if (payload.observationStartedAt && payload.observationStartedAt < nextState.observationStartedAt) {
      nextState.observationStartedAt = payload.observationStartedAt;
    }

    let applied = 0;
    for (const item of payload.deltas) {
      const deltaCalls = Number(item.deltaCalls || 0);
      if (deltaCalls <= 0 || !item.hash) continue;
      applied++;

      const itemFirst = item.firstSeenAt || nowIso;
      const itemLast = item.lastSeenAt || nowIso;
      const existing = nextState.routes[item.hash];
      const incomingCodes = item.deltaStatusCodes || item.statusCodes || { '200': deltaCalls };

      if (existing) {
        existing.calls += deltaCalls;
        if (itemFirst < existing.firstSeenAt) existing.firstSeenAt = itemFirst;
        if (itemLast > existing.lastSeen) existing.lastSeen = itemLast;
        for (const [code, cnt] of Object.entries(incomingCodes)) {
          existing.statusCodes[code] = (existing.statusCodes[code] || 0) + Number(cnt);
        }
        existing.nodeBreakdown = existing.nodeBreakdown || {};
        const nodeSlice = existing.nodeBreakdown[nodeId];
        if (nodeSlice) {
          nodeSlice.calls += deltaCalls;
          if (itemFirst < nodeSlice.firstSeenAt) nodeSlice.firstSeenAt = itemFirst;
          if (itemLast > nodeSlice.lastSeenAt) nodeSlice.lastSeenAt = itemLast;
        } else {
          existing.nodeBreakdown[nodeId] = {
            calls: deltaCalls,
            firstSeenAt: itemFirst,
            lastSeenAt: itemLast
          };
        }
      } else {
        nextState.routes[item.hash] = {
          calls: deltaCalls,
          firstSeenAt: itemFirst,
          lastSeen: itemLast,
          statusCodes: { ...incomingCodes },
          nodeBreakdown: {
            [nodeId]: {
              calls: deltaCalls,
              firstSeenAt: itemFirst,
              lastSeenAt: itemLast
            }
          }
        };
      }
    }

    nextState.lastFlushedAt = nowIso;
    const tmpFile = this.storePath + '.' + process.pid + '.' + Date.now() + '.tmp';
    const persisted = {
      _meta: {
        vendor: 'Maiestor Stelfid Cluster Aggregator',
        schemaVersion: '1.7.0-rc.1',
        environment: nextState.environment,
        nodeCount: Math.max(1, nextState.activeNodes.length),
        activeNodes: nextState.activeNodes,
        observationStartedAt: nextState.observationStartedAt,
        lastFlushedAt: nextState.lastFlushedAt,
        uniqueBatchesProcessed: Object.keys(nextState.processedBatchIds).length
      },
      routes: nextState.routes,
      _txState: nextState
    };
    const content = JSON.stringify(persisted, null, 2) + '\n';
    fs.writeFileSync(tmpFile, content, 'utf8');
    try {
      fs.renameSync(tmpFile, this.storePath);
    } catch {
      fs.copyFileSync(tmpFile, this.storePath);
      try { fs.unlinkSync(tmpFile); } catch {}
    }
    this.state = nextState;

    return {
      ok: true,
      ackedBatchId: batchId,
      idempotentReplay: false,
      appliedDeltas: applied
    };
  }
}
