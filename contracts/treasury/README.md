# astroid-treasury

Treasury contract — custody for organizational funds with policy + budget gates
on every outflow.

## Responsibilities

- `initialize(org, admin)` — DCP deploys the treasury for an org.
- `deposit(from, asset, amount)` — anyone can fund the pot.
- `withdraw(admin, asset, to, amount)` — policy + budget verified, then assets move.
- `set_policy(policy)` / `set_budget(budget)` — wire enforcement contracts.
- `freeze` / `unfreeze` — emergency stop on outflows (multisig only).
- `pause` / `unpause` — circuit breaker: guardian or multisig stops all
  outflows (`Error::TreasuryPaused`) while deposits keep flowing in. A pause
  lapses automatically after `MAX_PAUSE_DURATION` (one month) so a lost
  guardian key cannot strand the treasury forever; indefinite stops must go
  through `freeze`.
- `set_guardian(guardian)` — rotate the account that may pause / unpause.
- `allocate_budget(asset, budget_id)` — attach an envelope to an asset.

## Invariants

A withdrawal can only succeed when:
1. The caller is the recorded admin (`require_auth` gated).
2. The circuit breaker is not paused (`Error::TreasuryPaused`).
3. The treasury is not frozen.
4. The policy contract's `check_transfer` passes (when wired).
5. The budget's `consume` does not return `BudgetExceeded` (when wired).
6. The treasury's tracked balance for the asset covers the request.

Deposits are exempt from 2 and 3: inbound funding stays available during an
emergency so the treasury can be replenished while paused or frozen.

A pause older than `MAX_PAUSE_DURATION` no longer blocks outflows (2 stops
applying on its own); the stale flag is cleared by the next `pause` cycle and
`unpause` on a lapsed breaker fails with `InvalidState`.

## Events

- `("treasury", "deposited")` on every deposit.
- `("transfer", "executed")` on successful withdrawals (shared standard).
- `("treasury", "policy")` / `("treasury", "budget")` when enforcement contracts are wired.
- `("treasury", "paused")` / `("treasury", "unpaused")` when the circuit breaker
  is engaged or released.

## Cross-contract flow

```text
Treasury.withdraw ──► PolicyClient (Policy contract)
                  ──► BudgetClient (Budget contract)
                  ──► events::transfer_executed
```

Both dependencies use the typed interfaces in `astroid-interfaces` so the
workspace graph stays acyclic.
