# RustDefend Ground Truth — v0.5.0

Generated: 2026-02-18

Total repos scanned: 22

Total findings: 2649


## Scan Results by Repository

| Repository | Ecosystem | Findings | Critical | High | Medium | Low |
|------------|-----------|----------|----------|------|--------|-----|
| anchor-framework | Solana | 140 | 47 | 83 | 10 | 0 |
| astroport | CosmWasm | 256 | 0 | 56 | 8 | 192 |
| aurora | NEAR | 8 | 0 | 7 | 1 | 0 |
| cosmwasm-core | CosmWasm | 44 | 1 | 32 | 5 | 6 |
| cw-plus | CosmWasm | 23 | 0 | 9 | 1 | 13 |
| dao-dao | CosmWasm | 115 | 1 | 54 | 2 | 58 |
| drift | Solana | 211 | 76 | 124 | 11 | 0 |
| jito | Solana | 31 | 5 | 23 | 2 | 1 |
| linear | NEAR | 27 | 24 | 3 | 0 | 0 |
| marinade | Solana | 23 | 21 | 2 | 0 | 0 |
| mars-red-bank | CosmWasm | 92 | 2 | 36 | 14 | 40 |
| metaplex | Solana | 126 | 41 | 59 | 26 | 0 |
| near-core-contracts | NEAR | 38 | 18 | 20 | 0 | 0 |
| near-sdk | NEAR | 25 | 6 | 12 | 7 | 0 |
| orca-whirlpools | Solana | 225 | 133 | 87 | 5 | 0 |
| osmosis | CosmWasm | 18 | 0 | 11 | 2 | 5 |
| raydium | Solana | 20 | 16 | 4 | 0 | 0 |
| ref-finance | NEAR | 22 | 3 | 19 | 0 | 0 |
| spl | Solana | 280 | 131 | 121 | 28 | 0 |
| test-contracts | Mixed | 571 | 171 | 285 | 94 | 21 |
| test-fixtures | Mixed | 165 | 45 | 81 | 32 | 7 |
| wynddex | CosmWasm | 189 | 1 | 46 | 20 | 122 |

## Detector Summary

| Detector | Name | Severity | Confidence | Count |
|----------|------|----------|------------|-------|
| CW-001 | cosmwasm-integer-overflow | low | low | 407 |
| SOL-003 | integer-overflow | critical | medium | 402 |
| SOL-004 | account-confusion | high | medium | 192 |
| SOL-002 | missing-owner-check | critical | high | 190 |
| CW-006 | improper-error-handling | high | high | 142 |
| SOL-012 | token-2022-extension-safety | high | medium | 124 |
| SOL-013 | unsafe-remaining-accounts | high | medium | 93 |
| SOL-017 | account-data-matching | high | medium | 86 |
| SOL-010 | unsafe-pda-seeds | high | medium | 66 |
| SOL-009 | cpi-reentrancy | medium | low | 63 |
| SOL-005 | insecure-account-close | high | medium | 57 |
| CW-005 | unchecked-query-response | high | low | 56 |
| CW-002 | cosmwasm-reentrancy | low | low | 52 |
| NEAR-006 | missing-private-callback | critical | high | 51 |
| SOL-020 | checked-arithmetic-unwrap | medium | high | 46 |
| SOL-001 | missing-signer-check | critical | high | 41 |
| DEP-001 | outdated-dependencies | high | high | 40 |
| INK-007 | ink-panic-usage | high | high | 39 |
| DEP-002 | supply-chain-risk | high | high | 37 |
| CW-013 | cw2-migration-issues | medium | low | 37 |
| SOL-006 | arbitrary-cpi | critical | medium | 34 |
| CW-009 | cosmwasm-missing-addr-validation | high | medium | 34 |
| INK-003 | ink-missing-caller-check | high | medium | 29 |
| SOL-019 | duplicate-mutable-accounts | high | medium | 23 |
| NEAR-010 | missing-deposit-check | high | high | 23 |
| CW-010 | unguarded-migrate-entry | medium | medium | 22 |
| DEP-004 | proc-macro-supply-chain | high | low | 19 |
| SOL-011 | missing-rent-exempt | medium | medium | 17 |
| SOL-007 | pda-bump-misuse | high | high | 17 |
| INK-005 | ink-unbounded-storage | medium | medium | 17 |
| CW-008 | unsafe-ibc-entry-points | high | medium | 16 |
| NEAR-012 | missing-gas-for-callbacks | medium | medium | 12 |
| INK-008 | ink-result-suppression | medium | medium | 12 |
| NEAR-003 | storage-staking-auth | high | medium | 11 |
| CW-004 | storage-collision | high | high | 11 |
| CW-007 | unbounded-iteration | high | medium | 11 |
| SOL-021 | unvalidated-sysvar | medium | medium | 11 |
| SOL-008 | unchecked-cpi-return | high | high | 11 |
| INK-011 | unguarded-set-code-hash | medium | medium | 10 |
| INK-006 | ink-cross-contract | high | high | 9 |
| SOL-018 | unsafe-account-reallocation | high | medium | 8 |
| NEAR-001 | promise-reentrancy | critical | medium | 8 |
| NEAR-004 | callback-unwrap-usage | high | high | 8 |
| INK-010 | ink-missing-payable-check | medium | medium | 8 |
| NEAR-008 | frontrunning-risk | high | low | 7 |
| CW-011 | missing-reply-id-validation | medium | medium | 6 |
| CW-003 | missing-sender-check | critical | medium | 5 |
| INK-002 | ink-integer-overflow | low | medium | 5 |
| SOL-014 | init-if-needed-reinitialization | high | medium | 4 |
| NEAR-002 | signer-vs-predecessor | high | high | 4 |
| INK-004 | ink-timestamp-dependence | medium | medium | 3 |
| NEAR-011 | unguarded-storage-unregister | medium | medium | 2 |
| NEAR-005 | near-wrapping-arithmetic | critical | medium | 2 |
| INK-009 | ink-unsafe-delegate-call | critical | high | 2 |
| INK-001 | ink-reentrancy | critical | high | 2 |
| NEAR-007 | self-callback-state | high | medium | 2 |
| NEAR-009 | unsafe-storage-keys | medium | medium | 2 |
| SOL-016 | missing-priority-fee | low | low | 1 |

## False Positive Improvements (v0.5.0)

| Detector | FPs Eliminated | Method |
|----------|---------------|--------|
| CW-006 | 159 | Skip test helper files, `helpers.rs`, `instantiate_with_*` patterns |
| NEAR-010 | 84 | Skip admin methods (pause/resume/set_owner), `assert_one_yocto` |
| CW-005 | 75 | Skip test functions and test directories |
| SOL-006 | 19 | Skip anchor-spl/anchor-lang CPI wrapper modules |
| SOL-002 | 6 | Skip framework source files (anchor-spl, spl-token) |
| SOL-004 | 4 | Skip framework source and codegen files |
| **Total** | **347** | **11.6% overall reduction** |
