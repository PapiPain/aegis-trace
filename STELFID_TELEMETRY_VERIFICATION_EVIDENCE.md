# Maiestor Stelfid (v1.6.2) - Reproducible Telemetry & Idempotency Verification Evidence

- **Executed At:** `2026-10-19T21:38:29.893Z`
- **Initial Route Counter:** `0`
- **Final Route Counter:** `22` (10 from Test 1 + 5 from Test 2A + 7 from Test 2B = 22 exact hits)

## 1. Batch Processing & Idempotency Ledger (Zero PII / Blind Batch IDs Only)

| Metric | Value |
| :--- | :--- |
| **Server Batches Received** | `11` |
| **Server Batches Applied (Committed)** | `5` |
| **Server Batches Rejected (HTTP 500)** | `2` |
| **Server Idempotent Replays Blocked** | `5` |
| **SDK Retry Flushes Executed** | `4` |
| **Committed Batch IDs** | `batch_repro_test1_idempotency_5x`, `batch_7a304c59-e66e-4401-98ef-6f62f9760205`, `batch_8627ad8a-6868-41da-854b-02a364b30d8a`, `batch_10d7b655-6459-44a4-9095-1df6fe62fb1c`, `batch_e6724a30-1aa1-4e14-9499-1fa177f0dec4` |
| **Replayed Batch IDs (Deduplicated)** | `batch_repro_test1_idempotency_5x`, `batch_repro_test1_idempotency_5x`, `batch_repro_test1_idempotency_5x`, `batch_repro_test1_idempotency_5x`, `batch_10d7b655-6459-44a4-9095-1df6fe62fb1c` |
| **Rejected Batch IDs (HTTP 500)** | `batch_7a304c59-e66e-4401-98ef-6f62f9760205`, `batch_10d7b655-6459-44a4-9095-1df6fe62fb1c` |

## 2. Test 2B Precision: Post-Commit HTTP 500 Recovery (No Double Counting)

- **Initial Counter:** `15`
- **Counter After Server Committed (+4) Then Returned HTTP 500:** `19`
- **New Hits Arriving While Batch Was Queued for Retry:** `+3 hits`
- **Final Counter After Retry (Idempotent 0 + New 3):** `22` (Expected: `22`, Prevented Double-Count Value: `26`)

## 3. AbortController Timeout Evidence

- **Configured Timeout:** `120 ms`
- **Measured Cancellation Duration:** `126 ms`
- **Cancellation Confirmed (`abortedByTimeout`):** `true`

## 4. Zero-Delta Request Savings (Reproducible Formula)

$$\text{Ahorro (\%)} = \frac{\text{flush\_skipped\_zero\_delta}}{\text{flush\_skipped\_zero\_delta} + \text{flush\_sent\_http}} \times 100$$

- **`flush_attempts`:** `16`
- **`flush_sent_http`:** `4`
- **`flush_skipped_zero_delta`:** `12`
- **`http_requests_sent`:** `6`
- **Measured Savings (%):** `75%` (`12 / (12 + 4) * 100`)
