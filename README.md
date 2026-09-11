<h1 align="center">leanVM-b</h1>

<p align="center">
  <img src="./doc/images/banner-b.svg" alt="leanVM-b">
</p>

<p align="center">
  <a href="https://github.com/leanEthereum/leanVM-b/releases/download/doc-latest/leanVM-b.pdf"><img src="https://img.shields.io/badge/Documentation-PDF-blue?style=for-the-badge&logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xNCAySDZjLTEuMSAwLTIgLjktMiAydjE2YzAgMS4xLjg5IDIgMS45OSAySDE4YzEuMSAwIDItLjkgMi0yVjhsLTYtNnpNOC41IDE0LjVoMS4yNWMuOTcgMCAxLjc1LS43OCAxLjc1LTEuNzVTMTAuNzIgMTEgOS43NSAxMUg3LjV2Nmgxdi0yLjV6bTAtMVYxMmgxLjI1Yy40MSAwIC43NS4zNC43NS43NXMtLjM0Ljc1LS43NS43NUg4LjV6bTUuNSAzLjVoMnYtMWgtMnYtMWgydi0xaC0ydi0xLjVjMC0uMjguMjItLjUuNS0uNUgxN3YtMWgtMmMtLjgzIDAtMS41LjY3LTEuNSAxLjVWMTd6TTEzIDlWMy41TDE4LjUgOUgxM3oiLz48L3N2Zz4=" alt="Documentation"></a>
</p>

<p align="center">
  <a href="#xmss-aggregation"><img src="https://img.shields.io/badge/Aggregation-780%20XMSS%2Fs-brightgreen?style=for-the-badge" alt="Aggregation: 780 XMSS/s"></a>
  <a href="#recursion"><img src="https://img.shields.io/badge/2%20to%201%20recursion-0.6s-orange?style=for-the-badge" alt="2 to 1 recursion: 0.6s"></a>
</p>

Warning: highly experimental.

# Benchmarks

Machine: Mac M4 Max

### Recursive aggregation

`rec_aggregation` contains two independent self-recursive guests: XMSS aggregation and Privacy Pool withdrawal aggregation. XMSS uses schema 1 continuous arrival rate queries. Privacy Pool screening uses schema 2 with discrete withdrawals per root, six independent 12-second block bursts, and BLAKE2s-256 withdrawal fixtures.

### XMSS aggregation

Our XMSS is specified in [XMSS.pdf](https://github.com/leanEthereum/leanVM-b/releases/download/doc-latest/XMSS.pdf).

```bash
cargo run --release -- xmss --n-signatures 900 --log-inv-rate 1 --repeat 3
```

```
XMSS aggregation, 900 signatures
  cycles (VM steps)           : 1,542,704 = 2^20.557
    proven rows               : 1,967,104 = 2^20.908  (filled to powers of two)
    details                   : DEREF 2^18.988 (33.7%)  SET 2^18.402 (22.4%)  MUL 2^18.198 (19.5%)  BLAKE2S 2^16.996 (8.5%)  XOR 2^16.96 (8.3%)  JUMP 2^16.831 (7.6%)  PACK64X2 2^9.938 (0.1%)  MEMORY 2^21.725  TOTAL_COMMITTED 2^26.195
  signers                     : 900
  proof size                  : 356.5 KiB
  aggregating                 : 1.155 s ± 3.3%      peak memory 20.705 GiB
  per signature               : 779.378 XMSS/s
  verifying                   : 0.0128 s
```

### Recursion


```bash
cargo run --release -- recursion --n 2 --log-inv-rate 2 --repeat 3
```

```
recursion 2→1, over leaves of 900 signatures
  cycles (VM steps)           : 830,516 = 2^19.664
    proven rows               : 1,196,032 = 2^20.19  (filled to powers of two)
    details                   : DEREF 2^18.21 (36.5%)  MUL 2^17.928 (30.0%)  XOR 2^17.424 (21.2%)  SET 2^15.553 (5.8%)  BLAKE2S 2^14.462 (2.7%)  PACK64X2 2^14.384 (2.6%)  JUMP 2^13.279 (1.2%)  MEMORY 2^19.989  TOTAL_COMMITTED 2^24.863
  signers                     : 1,800
  proof size                  : 220.9 KiB
  aggregating                 : 0.604 s ± 4.3%      peak memory 26.097 GiB
  verifying                   : 0.0148 s
```

### Application-constrained recursive benchmark

The query benchmark searches the supplied thread, memory, deadline, and proof-bandwidth limits and reports the tested configuration with the greatest passing input rate. Child-proof generation finishes before timed arrivals begin, so input-to-root latency starts when a child proof becomes available. Schema-2 results use exact six-root observations and the largest observed serialized latency; they do not claim a percentile from those six samples.

The runner requires Python 3 and the Rust toolchain. It builds `leanvm-b` in release mode with native CPU instructions. A schema 1 XMSS run starts from the example query:

```bash
cp scripts/recursion-benchmark-example.json target/recursion-query.json

python3 scripts/run_recursion_benchmark.py \
  --spec target/recursion-query.json \
  --tier screening \
  --output target/recursion-query-screening
```

For schema 1, `screening` measures three samples per parent proof configuration and six completed roots per arrival rate candidate. `standard` measures ten parent samples and 30 roots and reports the observed 99th percentile latency. `publication` runs three fresh measurements of 100 roots and compares the one-sided 95% upper confidence bound for the 99th percentile with the deadline.

The example query restricts the number of child proofs per parent to 2, 3, and 4; WHIR rates to 1/4 and 1/8; and the machine allocation to at most two performance threads. These bounds keep the first measurement set limited. Its 100-second deadlines, 40 GiB RAM limit, and 1 GB/s proof-bandwidth budgets are permissive example values, not application recommendations. Replace them with the intended deployment limits before interpreting pass or fail results.

The checked-in schema 2 query fixes the Privacy Pool workload to two depth-32 Merkle paths, BLAKE2s-256, six roots spaced 12 seconds apart, the required input counts and WHIR rates, and selected measurements at 8, 4, 2, and 1 performance threads. Run the 12-hour campaign with:

```bash
python3 scripts/run_recursion_benchmark.py \
  --spec scripts/privacy-pool-withdrawal-screening.json \
  --tier screening \
  --output target/privacy-pool-withdrawal-screening \
  --time-budget-seconds 43200 \
  --finish-reserve-seconds 1800 \
  --case-timeout-seconds 3600 \
  --performance-worker-counts 8,4,2,1
```

Before the campaign, this one-root command checks compilation, proving, serialization, parsing, exact public-statement verification, and report generation:

```bash
python3 scripts/run_recursion_benchmark.py \
  --spec scripts/privacy-pool-withdrawal-screening.json \
  --tier screening \
  --output target/privacy-pool-withdrawal-smoke \
  --smoke \
  --performance-worker-counts 1 \
  --time-budget-seconds 1800 \
  --finish-reserve-seconds 60 \
  --case-timeout-seconds 1200
```

- `hardware_limits.performance_workers`, `efficiency_workers`, and `proving_processes` set the maximum available worker and process counts. By default, the runner tests powers of two and the supplied maximum. Use `--performance-worker-counts 1,2,4` to request exact performance-thread totals within that maximum.
- `hardware_limits.prover_ram_bytes` sets the combined resident-memory limit for all proving processes.
- `root_policy` selects a fixed input count, periodic root interval, or batching timeout.
- `deadlines` sets the input-to-root and root-interval limits in seconds.
- `network.connected_peers` records the node's peer count. `root_proof_recipients` and `intermediate_proof_recipients` specify how many recipients receive each proof. Ingress and egress budgets are bytes per second.
- `search.arities` accepts 2 through 16 child proofs per parent. `workload.leaf_log_inv_rates` and `search.parent_log_inv_rates` use `1`, `2`, `3`, and `4` for WHIR rates 1/2, 1/4, 1/8, and 1/16.
- `search.min_arrival_rate` and `max_arrival_rate` bound the offered child proofs per second. `rate_precision_fraction` controls how closely the runner narrows the passing-rate boundary.

To continue an interrupted run using verified completed artifacts, supply the same query and output directory with `--resume`. Resume checks the query, source fingerprint, adapter configuration, release binary, plan digest, and complete verified root records before reusing work:

```bash
python3 scripts/run_recursion_benchmark.py \
  --spec target/recursion-query.json \
  --tier screening \
  --output target/recursion-query-screening \
  --resume
```

The output directory contains:

- `summary.md` and `summary.json`: the run status, selected rate, required comparison tables, provenance, and missing points.
- `coverage.json`: every required candidate and parent geometry point with its completion state.
- `candidates.json` and `candidates.csv`: measurements and limits for every candidate.
- `roots.csv`: each completed root, scheduled burst, serialized completion time, latency, proof size, and verification receipts.
- `capacity.json` and `capacity.csv`: measured parent proof shapes and service times used by the planner.
- `raw.jsonl`, `parent-checkpoint.jsonl`, and `candidate-checkpoint.jsonl`: append-only measurements and resumable checkpoints.
- `query.json`: the exact query used for the run.

Proof bandwidth is calculated from serialized proof sizes and the configured recipient counts. It does not send packets through a network interface. Generate the standalone [interactive report](doc/recursive-benchmark-results.html) from a completed Privacy Pool screening directory, then open it in the default browser:

```bash
python3 scripts/generate_privacy_pool_report.py \
  --input privacy-pool-withdrawal-screening-bench \
  --output doc/recursive-benchmark-results.html \
  --hardware-description "Apple M4 Pro with 8 performance cores, 4 efficiency cores, and 48 GiB physical RAM"

open doc/recursive-benchmark-results.html
```

### Fibonacci


```bash
cargo run --release -- fibonacci --n 2000000 --log-inv-rate 1 --repeat 3
```

```
Fibonacci (in the exponent, i.e. modulo 2^64 - 1), N = 2,000,000
  cycles (VM steps)           : 2,127,881
    details                   : MUL 2^20.937 (98.7%)  DEREF 2^13.967 (0.8%)  SET 2^12.552 (0.3%)  JUMP 2^10.968 (0.1%)  XOR 2^10.966 (0.1%)  MEMORY 2^20.964  TOTAL_COMMITTED 2^25.263
  proof size                  : 332.5 KiB
  proving                     : 0.608 s ± 6.6%   3,499,102 cycles/s      peak memory 12.112 GiB
  verifying                   : 0.00372 s
```

## Security

- 128-bit (LDR Johnson, no proximity gaps conjecture)

## Snark machinery

- Binary field of 192 bits
- PCS: [WHIR](https://eprint.iacr.org/2024/1586) (aka [Ligerito](https://eprint.iacr.org/2025/1187))

## Credits

- [flock](https://github.com/succinctlabs/flock/tree/main)
- [binius](https://github.com/IrreducibleOSS/binius)
- [binius64](https://github.com/binius-zk/binius64)
