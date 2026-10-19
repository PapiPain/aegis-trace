-- ============================================================================
-- MAIESTOR STELFID (v1.6.4) — Idempotent Transactional Batch Ingestion Schema
-- Garantiza que si el servidor recibe el mismo lote 5 veces, los contadores
-- se incrementan UNA SOLA VEZ dentro de la misma transaccion ACID.
-- ============================================================================

CREATE TABLE IF NOT EXISTS stelfid_processed_batches (
  batch_id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  environment TEXT NOT NULL,
  delta_count INTEGER NOT NULL DEFAULT 0,
  processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS stelfid_route_counters (
  route_hash TEXT PRIMARY KEY,
  environment TEXT NOT NULL,
  calls BIGINT NOT NULL DEFAULT 0,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  status_codes JSONB NOT NULL DEFAULT '{}'::jsonb,
  is_matched_express_route BOOLEAN NOT NULL DEFAULT TRUE
);

-- Funcion RPC Transaccional: inserta el lote con restriccion unica y actualiza contadores atomicamente
CREATE OR REPLACE FUNCTION ingest_stelfid_delta_batch(
  p_batch_id TEXT,
  p_node_id TEXT,
  p_environment TEXT,
  p_deltas JSONB
) RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
  v_inserted_batch TEXT;
  v_item JSONB;
BEGIN
  -- 1. Intentar registrar el batch_id con restriccion unica (ON CONFLICT DO NOTHING)
  INSERT INTO stelfid_processed_batches (batch_id, node_id, environment, delta_count)
  VALUES (p_batch_id, p_node_id, p_environment, jsonb_array_length(p_deltas))
  ON CONFLICT (batch_id) DO NOTHING
  RETURNING batch_id INTO v_inserted_batch;

  -- 2. Si v_inserted_batch es NULL, este lote YA fue procesado previamente -> No incrementar nada
  IF v_inserted_batch IS NULL THEN
    RETURN jsonb_build_object(
      'ok', true,
      'ackedBatchId', p_batch_id,
      'idempotentReplay', true,
      'appliedDeltas', 0
    );
  END IF;

  -- 3. Misma transaccion: aplicar incrementos atomicos por cada ruta del lote
  FOR v_item IN SELECT * FROM jsonb_array_elements(p_deltas)
  LOOP
    INSERT INTO stelfid_route_counters (
      route_hash, environment, calls, first_seen_at, last_seen_at, status_codes, is_matched_express_route
    ) VALUES (
      v_item->>'hash',
      p_environment,
      (v_item->>'deltaCalls')::BIGINT,
      COALESCE((v_item->>'firstSeenAt')::TIMESTAMPTZ, NOW()),
      COALESCE((v_item->>'lastSeenAt')::TIMESTAMPTZ, NOW()),
      COALESCE(v_item->'deltaStatusCodes', '{}'::jsonb),
      COALESCE((v_item->>'isMatchedExpressRoute')::BOOLEAN, true)
    )
    ON CONFLICT (route_hash) DO UPDATE SET
      calls = stelfid_route_counters.calls + EXCLUDED.calls,
      last_seen_at = GREATEST(stelfid_route_counters.last_seen_at, EXCLUDED.last_seen_at),
      is_matched_express_route = stelfid_route_counters.is_matched_express_route OR EXCLUDED.is_matched_express_route;
  END LOOP;

  RETURN jsonb_build_object(
    'ok', true,
    'ackedBatchId', p_batch_id,
    'idempotentReplay', false,
    'appliedDeltas', jsonb_array_length(p_deltas)
  );
END;
$$;
