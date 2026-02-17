# Test Fixtures

Intentionally vulnerable smart contract code for testing RustDefend detectors.

These fixtures are **not compilable contracts** — they are syntactically valid Rust files that trigger specific detector patterns via AST analysis.

## Sources

- **Original fixtures**: Minimal pattern triggers for detectors with zero findings in the main test corpus
- **vulnerable-smart-contract-examples**: Real-world vulnerable Solana patterns from [BlockSecOps/vulnerable-smart-contract-examples](https://github.com/BlockSecOps/vulnerable-smart-contract-examples)

## Coverage

### Solana Fixtures

| Fixture | Primary Detectors | Pattern |
|---------|-------------------|---------|
| `solana/arithmetic_errors.rs` | SOL-003, SOL-004, SOL-002, SOL-005 | Unchecked arithmetic, missing discriminator, missing owner check |
| `solana/missing_signer_check.rs` | SOL-003, SOL-005 | Missing `is_signer` check, insecure account close |
| `solana/missing_owner_check.rs` | SOL-002, SOL-003, SOL-004, SOL-005 | Missing `account.owner == program_id`, unchecked arithmetic |
| `solana/type_confusion.rs` | SOL-003, SOL-004 | Missing account discriminator, type confusion |
| `solana/arbitrary_cpi.rs` | SOL-006 | User-controlled CPI target without program ID validation |
| `solana/pda_issues.rs` | SOL-003, SOL-004, SOL-007 | User-provided bump seeds, missing PDA validation |
| `solana/reinitialization.rs` | SOL-003, SOL-004, SOL-005 | Missing initialization check, account reinitialization |
| `solana/rent_exemption.rs` | SOL-003, SOL-004, SOL-005 | Missing rent exemption check |
| `solana/account_data_matching.rs` | SOL-002, SOL-003, SOL-004, SOL-005 | Missing account relationship validation |
| `solana/unchecked_cpi.rs` | SOL-008 | `let _ = invoke(...)` without error handling |
| `solana/token2022_unsafe.rs` | SOL-012 | Token-2022 `InterfaceAccount`/`transfer_checked` without extension check |
| `solana/remaining_accounts_unsafe.rs` | SOL-013 | `ctx.remaining_accounts` without owner/type validation |
| `solana/init_if_needed_unsafe.rs` | SOL-014 | `init_if_needed` without reinitialization guard |

### CosmWasm Fixtures

| Fixture | Primary Detectors | Pattern |
|---------|-------------------|---------|
| `cosmwasm/missing_sender.rs` | CW-003 | `execute_*` mutates storage without `info.sender` check |
| `cosmwasm/storage_collision.rs` | CW-004 | Duplicate `Map::new("config")` / `Item::new("config")` |
| `cosmwasm/unbounded_iteration.rs` | CW-007 | `.range()` without `.take()` in execute handler |
| `cosmwasm/unsafe_ibc.rs` | CW-008 | IBC handlers without channel validation or timeout rollback |
| `cosmwasm/unguarded_migrate.rs` | CW-010 | `migrate` handler without admin/sender check or version validation |
| `cosmwasm/missing_reply_id.rs` | CW-011 | `reply` handler not matching on `msg.id` |

### NEAR Fixtures

| Fixture | Primary Detectors | Pattern |
|---------|-------------------|---------|
| `near/storage_no_auth.rs` | NEAR-003, NEAR-012 | `storage_deposit` without `predecessor_account_id`, missing gas |
| `near/unguarded_pending.rs` | NEAR-001, NEAR-007 | `self.pending_*` write before `ext_self::` without guard |
| `near/unsafe_storage_key.rs` | NEAR-009 | `format!()` key with `storage_write`/`storage_read` |
| `near/unguarded_storage_unregister.rs` | NEAR-011 | `storage_unregister` without balance/force checks |
| `near/missing_gas_callback.rs` | NEAR-012 | Cross-contract calls without explicit gas specification |

### ink! Fixtures

| Fixture | Primary Detectors | Pattern |
|---------|-------------------|---------|
| `ink/allow_reentry.rs` | INK-001, INK-005, INK-010 | `set_allow_reentry(true)`, unbounded storage |
| `ink/timestamp_compare.rs` | INK-004, INK-007 | `block_timestamp()` in comparison, panic in message |
| `ink/unsafe_delegate.rs` | INK-009 | `delegate(code_hash)` with user-controlled `Hash` param |
| `ink/unguarded_set_code_hash.rs` | INK-011 | `set_code_hash` without admin/owner verification |

### Cross-chain Fixtures

| Fixture | Primary Detectors | Pattern |
|---------|-------------------|---------|
| `Cargo.toml` | DEP-001, DEP-002 | Outdated dependency versions, wildcard versions, malicious crate names |

## Baseline Finding Counts

```
Chain       Total  Detectors Triggered
────────────────────────────────────────────────────────
Solana        56   SOL-002:6  SOL-003:22  SOL-004:10  SOL-005:8
                   SOL-006:1  SOL-007:1   SOL-008:2   SOL-012:2
                   SOL-013:2  SOL-014:2
CosmWasm      13   CW-001:1   CW-003:1    CW-004:2    CW-006:1
                   CW-007:2   CW-008:3    CW-010:2    CW-011:1
NEAR          13   NEAR-001:2 NEAR-003:3  NEAR-007:2  NEAR-009:2
                   NEAR-011:1 NEAR-012:3
ink!          15   INK-001:2  INK-004:3   INK-005:2   INK-007:3
                   INK-009:2  INK-010:1   INK-011:2
DEP            9   DEP-001:6  DEP-002:3
────────────────────────────────────────────────────────
TOTAL        106
```

## Running

```bash
# Scan all fixtures
rustdefend scan test-fixtures/solana --chain solana
rustdefend scan test-fixtures/cosmwasm --chain cosmwasm
rustdefend scan test-fixtures/near --chain near
rustdefend scan test-fixtures/ink --chain ink
rustdefend scan test-fixtures --chain solana  # triggers DEP-001 and DEP-002 via Cargo.toml
```
