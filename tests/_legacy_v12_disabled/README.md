# Disabled legacy v12 integration tests

These 14 files target the **pre-fork v12 engine API** (`percolator::Account`,
`percolator::RiskEngine`, the `oracle`/`policy`/`zc`/`units` wrapper modules,
`MarketConfig`, `TestEnv`, `encode_init_market_with_limits`, …). The v17
convergence dropped runtime-vec for the zero-copy/sparse layout and removed
those types/modules, so these files no longer compile (489 errors in
`test_security.rs` alone).

They live in this subdirectory — **not** directly under `tests/` — so Cargo does
not pick them up as integration-test targets. That keeps a bare `cargo test`
green and running the real v17-native suite.

## What replaced them

The v17-native LiteSVM suite under `tests/v16_*.rs`:
`v16_wrapper.rs` (201 tests), `v16_five_program_crosscut.rs`,
`v16_fork_adversarial.rs`, `v16_nft_e2e.rs`, `v16_fork_b3_nft_cpi.rs`,
`v16_fork_envelope_gate.rs`, `v16_fork_bundles.rs`, the `v16_fork_lp_vault_*`
files, `v16_cu.rs`, and `v16_baseline_smoke.rs`.

## Disposition (decide before audit-package freeze)

- **Delete** if the v17-native suite is judged to fully cover the surface, or
- **Port** specific scenarios (e.g. oracle/insurance edge cases in
  `test_oracle.rs` / `test_insurance.rs`) to the v17 API if any coverage gap is
  identified.

Recovered via `git mv` — full history is preserved.
