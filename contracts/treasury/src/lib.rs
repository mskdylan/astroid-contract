#![no_std]
#![allow(clippy::too_many_arguments)]
//! # Astroid Treasury Contract
//!
//! Custodies organizational funds and enforces governance on every outbound
//! movement (PRD Doc 7 §Treasury). Every `withdraw` / `transfer` resolves the
//! organization's Policy and Budget contracts and calls them BEFORE debiting
//! the ledger, so a spend must satisfy:
//!
//! ```text
//! admin auth → policy.check_transfer → budget.consume → assets move
//! ```
//!
//! Cross-contract calls go through the typed clients generated from
//! [`astroid_interfaces`], keeping the graph acyclic: `Treasury → {Policy, Budget}`.
//!
//! ## Asset whitelist
//!
//! Policy and budget gates constrain *how much* may move and *to whom*, but
//! neither says anything about *which token contract* is being invoked. An
//! agent that can name an arbitrary `Address` as the asset can point the
//! treasury at a hostile Stellar asset contract, whose `transfer` is arbitrary
//! code running with the treasury as the authorizer.
//!
//! Every routing decision is therefore checked against a persistent whitelist
//! of approved token contracts before any value moves:
//!
//! ```text
//! asset whitelisted → admin auth → policy.check_transfer → budget.consume → assets move
//! ```
//!
//! The whitelist is governance-managed (`add_approved_asset` /
//! `remove_approved_asset`, both admin-gated — point `admin` at the
//! organization's multisig to require a threshold of signers) and unapproved
//! assets are refused deterministically with [`Error::AssetNotAuthorized`] on
//! both inflows and outflows.
//!
//! [`TreasuryContract::batch_transfer`] applies the same gate chain to a whole
//! vector of payouts in a single, atomic invocation: the cumulative amount is
//! accumulated with checked math and validated against the treasury balance
//! before any value moves, so autonomous agents can pay many contributors for
//! the fee of one transaction. If any leg fails, the host reverts the entire
//! invocation and no recipient is paid.
//!
//! ## Emergency circuit breaker (pause)
//!
//! Alongside the multisig-only `freeze`, the treasury carries a dedicated
//! `paused: bool` flag and an authorized `guardian: Address` in its instance
//! storage. `pause` / `unpause` may only be called by that guardian or by the
//! organization's multisig, and they flip nothing but the flag - structural
//! ownership and configuration stay untouched:
//!
//! ```text
//! paused ── withdraw / batch_transfer / release_next_milestone ──▶ Error::TreasuryPaused
//! paused ── deposit ─────────────────────────────────────────────▶ still accepted
//! ```
//!
//! Inbound deposits are deliberately left open while the breaker is engaged,
//! so an organization can keep receiving recovery funding during an incident;
//! only value leaving the treasury is refused, with the dedicated
//! [`Error::TreasuryPaused`] code so off-chain monitors can distinguish "we
//! paused on purpose" from a generic state failure.
//!
//! The breaker is deliberately temporary: it is stamped with the engagement
//! ledger timestamp and lapses automatically once [`MAX_PAUSE_DURATION`] has
//! elapsed, so a lost guardian key cannot strand an organization behind a
//! paused treasury forever. Outflows resume on their own after the cap while
//! the stale flag stays recorded until `unpause` clears it or `pause`
//! re-engages over it; an indefinite stop must go through the multisig-only
//! `freeze` instead.
//!
//! ## Multi-token accounting
//!
//! The treasury custodies any number of approved Soroban token contracts side
//! by side (up to [`MAX_TREASURY_ASSETS`]). Each asset keeps its own
//! [`Holding`] record and the approved set is enumerable, so
//! [`TreasuryContract::portfolio`] reports every asset's live custody balance,
//! recorded balance and `decimals` in one call. Amounts are always in the
//! token's own base units; the treasury never normalizes across decimals.
//!
//! Token contracts are not trusted to move exactly what they are asked to:
//!
//! - `deposit` credits the amount that *actually arrived* (the custody balance
//!   delta), so a fee-on-transfer token cannot inflate the books, and a
//!   transfer that delivers nothing is rejected with [`Error::InvalidAmount`].
//! - Every outflow checks the live custody balance first
//!   ([`Error::InsufficientFunds`] instead of a token-level panic) and then
//!   verifies the balance fell by exactly the amount paid, reverting with
//!   [`Error::InvalidState`] otherwise.
//!
//! All token math goes through the shared checked helpers.
//!
//! Functions: `initialize`, `set_policy`, `set_budget`, `set_multisig`,
//! `set_guardian`, `add_approved_asset`, `remove_approved_asset`, `freeze`,
//! `unfreeze`, `pause`, `unpause`, `deposit`, `withdraw`, `batch_transfer`,
//! `allocate_budget`, `set_allowance`, `remove_allowance`, `allowance`,
//! `init_milestone_disbursement`, `release_next_milestone`, `get`, `holding`,
//! `is_paused`, `guardian`, `is_approved_asset`, `approved_asset_count`,
//! `approved_assets`, `portfolio`.

use astroid_interfaces::{PolicyClient, TreasuryInterface, UpgradeableInterface};
use astroid_shared::constants::{
    INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, MAX_BATCH_PAYMENTS, MAX_PAUSE_DURATION,
    PERSISTENT_BUMP_AMOUNT, PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::errors::Error;
use astroid_shared::events;
use astroid_shared::math::{checked_add, checked_div, checked_mul, checked_sub};
use astroid_shared::types::{Payment, ResourceState};
use astroid_shared::validation::{require_non_empty, require_positive_amount};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, Address, Env, String, Symbol, Vec,
};

/// Maximum number of token contracts a treasury may have approved at once.
/// Bounds every per-asset iteration (e.g. [`TreasuryContract::portfolio`]).
pub const MAX_TREASURY_ASSETS: u32 = 32;
const MAX_BALANCE_ASSETS: u32 = MAX_TREASURY_ASSETS;

/// Stored treasury record.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Treasury {
    pub org: String,
    pub admin: Address,
    /// Organization's multisig contract — authorized for emergency freeze/unfreeze.
    pub multisig: Option<Address>,
    /// Organization's Policy contract — consulted on every spend.
    pub policy: Option<Address>,
    /// Organization's Budget contract root.
    pub budget: Option<Address>,
    /// Lifecycle state shared with wallets.
    pub state: ResourceState,
    /// Emergency circuit-breaker guardian: may engage or release the pause
    /// alongside the multisig. Bootstrapped to `admin` at `initialize` and
    /// rotated through [`TreasuryContract::set_guardian`].
    pub guardian: Address,
    /// Whether the emergency circuit breaker is currently engaged. While
    /// `true`, every outbound disbursement or transfer is refused with
    /// [`Error::TreasuryPaused`]; inbound deposits stay open so recovery
    /// funding can still arrive.
    pub paused: bool,
    /// Ledger timestamp at which the breaker was engaged, or `0` while
    /// disengaged. Every pause lapses automatically after
    /// [`MAX_PAUSE_DURATION`]; see [`TreasuryContract::pause`].
    pub paused_at: u64,
}

/// Per-asset accounting within the treasury.

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MilestoneDisbursement {
    pub total_amount: i128,
    pub milestones: u32,
    pub disbursed: u32,
    pub amount_per_milestone: i128,
    pub asset: Address,
    pub to: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Holding {
    pub asset: Address,
    pub total_in: i128,
    pub total_out: i128,
    /// Budget envelope backing this asset, if any.
    pub budget_id: Option<String>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetBalance {
    pub asset: Address,
    pub balance: i128,
}

/// One approved asset's position, as reported by
/// [`TreasuryContract::portfolio`]. All amounts are in the token's base units.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetPosition {
    pub asset: Address,
    /// The token contract's own `decimals()`.
    pub decimals: u32,
    /// Live balance held by the treasury contract on the token ledger.
    pub balance: i128,
    /// Balance according to the treasury's internal accounting.
    pub recorded: i128,
    /// Cumulative amount paid out of the treasury in this asset.
    pub total_out: i128,
}

/// Composite key identifying a withdrawal allowance scoped to a specific agent
/// (the caller that may spend), recipient and asset.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowanceId {
    pub agent: Address,
    pub recipient: Address,
    pub asset: Address,
}

/// Active withdrawal allowance restricting agent-driven expenditures against a
/// specific recipient/asset to a pre-approved `limit` over a time window.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Allowance {
    pub agent: Address,
    pub recipient: Address,
    pub asset: Address,
    /// Maximum cumulative amount that may be withdrawn under this allowance.
    pub limit: i128,
    /// Amount already consumed against the allowance.
    pub spent: i128,
    /// Unix timestamp after which the allowance can no longer be used (0 = never).
    pub expires_at: u64,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Treasury,
    Holding(Address),
    /// Whitelist membership: token contract address -> approved (persistent).
    ApprovedAsset(Address),
    /// Number of currently approved assets (instance).
    ApprovedAssetCount,
    /// Enumerable list of currently approved assets (instance).
    ApprovedAssetList,
    ReentrancyLock,
    /// Emergency circuit breaker freeze flag (persistent).
    Frozen,
    Milestone(u64),
    MilestoneCount,
    Allowance(AllowanceId),
}

#[contract]
pub struct TreasuryContract;

#[contractimpl]
impl TreasuryContract {
    /// Create a treasury for `org`, gated on the admin's signature.
    ///
    /// The circuit breaker starts disengaged (`paused == false`) and the
    /// deployer admin is recorded as the initial guardian, so a freshly
    /// created treasury always has at least one account that can pause it;
    /// rotate the guardian afterwards with [`Self::set_guardian`].
    pub fn initialize(env: Env, org: String, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Treasury) {
            return Err(Error::AlreadyInitialized);
        }
        require_non_empty(&org)?;
        env.storage().instance().set(
            &DataKey::Treasury,
            &Treasury {
                org: org.clone(),
                admin: admin.clone(),
                multisig: None,
                policy: None,
                budget: None,
                state: ResourceState::Active,
                guardian: admin.clone(),
                paused: false,
                paused_at: 0,
            },
        );
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
        events::treasury_created(&env, &org, &admin);
        Self::unlock(&env);
        Ok(())
    }

    /// Wire the policy-enforcement contract consulted before every spend.
    pub fn set_policy(env: Env, caller: Address, policy: Address) -> Result<(), Error> {
        let mut t = Self::require_admin(&env, &caller)?;
        t.policy = Some(policy);
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("policy"),
            },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("policy")), ());
        Self::unlock(&env);
        Ok(())
    }

    /// Wire the budget-tracking contract backing this treasury.
    pub fn set_budget(env: Env, caller: Address, budget: Address) -> Result<(), Error> {
        let mut t = Self::require_admin(&env, &caller)?;
        t.budget = Some(budget);
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("budget"),
            },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("budget")), ());
        Self::unlock(&env);
        Ok(())
    }

    /// Approve a token contract for use by this treasury (governance-gated).
    ///
    /// Only whitelisted assets may be deposited, withdrawn or bound to a budget
    /// envelope, so this is the single point at which an organization decides
    /// which token contracts its funds are ever routed through.
    pub fn add_approved_asset(env: Env, caller: Address, asset: Address) -> Result<(), Error> {
        let t = Self::require_admin(&env, &caller)?;
        let key = DataKey::ApprovedAsset(asset.clone());
        if env.storage().persistent().get(&key).unwrap_or(false) {
            return Err(Error::AlreadyExists);
        }
        let mut list = Self::approved_list(&env);
        if list.len() >= MAX_TREASURY_ASSETS {
            return Err(Error::InvalidInput);
        }
        list.push_back(asset.clone());
        Self::store_approved_list(&env, &list);
        env.storage().persistent().set(&key, &true);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        let count = checked_add(Self::approved_count(&env) as i128, 1)? as u32;
        Self::store_approved_count(&env, count);
        Self::emit_asset_change(&env, &t, &asset, symbol_short!("asset_add"));
        Ok(())
    }

    /// Revoke a token contract's approval (governance-gated).
    ///
    /// Existing internal accounting for the asset is deliberately left intact
    /// so a revoked holding stays inspectable; what stops is any further
    /// routing through it.
    pub fn remove_approved_asset(env: Env, caller: Address, asset: Address) -> Result<(), Error> {
        let t = Self::require_admin(&env, &caller)?;
        let key = DataKey::ApprovedAsset(asset.clone());
        if !env.storage().persistent().get(&key).unwrap_or(false) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        let mut list = Self::approved_list(&env);
        if let Some(i) = list.first_index_of(&asset) {
            list.remove(i);
            Self::store_approved_list(&env, &list);
        }
        let count = Self::approved_count(&env).saturating_sub(1);
        Self::store_approved_count(&env, count);
        Self::emit_asset_change(&env, &t, &asset, symbol_short!("asset_rm"));
        Ok(())
    }

    /// Wire the multisig contract authorized for emergency freeze/unfreeze.
    pub fn set_multisig(env: Env, caller: Address, multisig: Address) -> Result<(), Error> {
        let mut t = Self::require_admin(&env, &caller)?;
        t.multisig = Some(multisig);
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("multisig"),
            },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("multisig")), ());
        Self::unlock(&env);
        Ok(())
    }

    /// Emergency freeze — only the registry-verified multisig can freeze.
    /// Sets a dedicated frozen flag in persistent storage that blocks all outbound transfers.
    pub fn freeze(env: Env, caller: Address) -> Result<(), Error> {
        let t = Self::require_multisig(&env, &caller)?;
        env.storage().persistent().set(&DataKey::Frozen, &true);
        Self::bump_frozen(&env);
        events::publish(
            &env,
            events::ContractEvent::TreasuryFrozen { org: t.org.clone() },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("frozen")), ());
        Self::unlock(&env);
        Ok(())
    }

    /// Emergency unfreeze — only the registry-verified multisig can unfreeze.
    /// Clears the frozen flag to restore outbound transfers.
    pub fn unfreeze(env: Env, caller: Address) -> Result<(), Error> {
        let t = Self::require_multisig(&env, &caller)?;
        let frozen: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Frozen)
            .unwrap_or(false);
        if !frozen {
            return Err(Error::InvalidState);
        }
        env.storage().persistent().set(&DataKey::Frozen, &false);
        Self::bump_frozen(&env);
        events::publish(
            &env,
            events::ContractEvent::TreasuryUnfrozen { org: t.org.clone() },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("unfrozen")), ());
        Self::unlock(&env);
        Ok(())
    }

    /// Rotate the emergency circuit-breaker guardian (admin-gated).
    ///
    /// The guardian is a dedicated key whose only powers are
    /// [`Self::pause`] / [`Self::unpause`]; pointing it at a hot
    /// monitoring key (or at another multisig) lets an organization decouple
    /// "who can stop the treasury" from "who can spend from it".
    pub fn set_guardian(env: Env, caller: Address, guardian: Address) -> Result<(), Error> {
        let mut t = Self::require_admin(&env, &caller)?;
        t.guardian = guardian;
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("guardian"),
            },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("guardian")), ());
        Self::unlock(&env);
        Ok(())
    }

    /// Engage the emergency circuit breaker.
    ///
    /// Restricted to the recorded guardian or the organization's multisig
    /// (both checked against instance storage, then authorized with
    /// `require_auth`). While engaged, every outbound value movement
    /// ([`Self::withdraw`], [`Self::batch_transfer`],
    /// [`Self::release_next_milestone`]) short-circuits with
    /// [`Error::TreasuryPaused`]; inbound deposits stay open so recovery
    /// funding can still arrive. Unlike [`Self::freeze`] this does not change
    /// any structural ownership or configuration - only the pause flag moves.
    ///
    /// The breaker is temporary by construction: it engages with the ledger
    /// timestamp stamped into [`Treasury::paused_at`] and lapses automatically
    /// once [`MAX_PAUSE_DURATION`] has elapsed, after which outflows resume on
    /// their own while the stale flag stays recorded until it is cleared. An
    /// indefinite stop must go through the multisig-only [`Self::freeze`].
    pub fn pause(env: Env, caller: Address) -> Result<(), Error> {
        let mut t = Self::require_guardian(&env, &caller)?;
        // Re-engaging over a breaker that has merely lapsed is fine; only a
        // pause still inside its window is rejected as a double-toggle.
        if Self::pause_is_active(&t, &env) {
            return Err(Error::InvalidState);
        }
        t.paused = true;
        t.paused_at = env.ledger().timestamp();
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("pause"),
            },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("paused")), ());
        Self::unlock(&env);
        Ok(())
    }

    /// Release the emergency circuit breaker and restore outbound transfers.
    ///
    /// Same guardian/multisig gate as [`Self::pause`], and symmetric: an
    /// attempt to unpause a treasury that is not paused fails with
    /// [`Error::InvalidState`] rather than silently doing nothing. Clearing
    /// the breaker also resets [`Treasury::paused_at`], so the next
    /// [`Self::pause`] gets a fresh [`MAX_PAUSE_DURATION`] window.
    ///
    /// Releasing a breaker whose window has already lapsed also succeeds: the
    /// stale flag and [`Treasury::paused_at`] are cleared so the breaker can
    /// be re-engaged cleanly later.
    pub fn unpause(env: Env, caller: Address) -> Result<(), Error> {
        let mut t = Self::require_guardian(&env, &caller)?;
        if !t.paused {
            return Err(Error::InvalidState);
        }
        t.paused = false;
        t.paused_at = 0;
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("unpause"),
            },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("unpaused")), ());
        Self::unlock(&env);
        Ok(())
    }

    /// Deposit assets into the treasury (any funder may authorize). Moves real
    /// tokens from `from` into the treasury's custody, then credits the
    /// internal per-asset accounting with the amount that actually arrived.
    ///
    /// The custody balance is measured before and after the transfer, so a
    /// token that delivers less than `amount` (e.g. fee-on-transfer) is only
    /// credited what it delivered; one that delivers nothing, or claims to
    /// deliver more than was sent, is rejected.
    pub fn deposit(env: Env, from: Address, asset: Address, amount: i128) -> Result<(), Error> {
        require_positive_amount(amount)?;
        from.require_auth();
        let t = Self::load(&env);
        Self::require_active(&t)?;
        // Inbound routing is validated too: an unapproved token contract is
        // never invoked, not even to pull funds in.
        Self::require_approved_asset(&env, &asset)?;
        Self::lock(&env)?;
        // Pull tokens into the contract's own custody and measure the delta.
        let token_client = token::TokenClient::new(&env, &asset);
        let custody = env.current_contract_address();
        let before = token_client.balance(&custody);
        token_client.transfer(&from, &custody, &amount);
        let received = checked_sub(token_client.balance(&custody), before)?;
        if received <= 0 {
            return Err(Error::InvalidAmount);
        }
        if received > amount {
            return Err(Error::InvalidState);
        }
        let mut h = Self::load_holding(&env, &asset);
        h.total_in = checked_add(h.total_in, received)?;
        Self::store_holding(&env, &asset, &h);
        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("deposited")),
            (asset.clone(), received),
        );
        Self::unlock(&env);
        Self::unlock(&env);
        Ok(())
    }

    /// Attach a budget envelope to an asset (admin).
    pub fn allocate_budget(
        env: Env,
        admin: Address,
        asset: Address,
        budget_id: String,
    ) -> Result<(), Error> {
        let _t = Self::require_admin(&env, &admin)?;
        require_non_empty(&budget_id)?;
        Self::require_approved_asset(&env, &asset)?;
        let mut h = Self::load_holding(&env, &asset);
        h.budget_id = Some(budget_id);
        Self::store_holding(&env, &asset, &h);
        Self::unlock(&env);
        Ok(())
    }

    /// Create or update a withdrawal allowance capping how much `agent` may send
    /// to `recipient` in `asset`. `limit` is the cumulative ceiling; `expires_at`
    /// is an optional unix expiry (0 = no expiry). Admin only.
    pub fn set_allowance(
        env: Env,
        admin: Address,
        agent: Address,
        recipient: Address,
        asset: Address,
        limit: i128,
        expires_at: u64,
    ) -> Result<(), Error> {
        let _t = Self::require_admin(&env, &admin)?;
        require_positive_amount(limit)?;
        if agent == recipient {
            return Err(Error::InvalidInput);
        }
        let id = AllowanceId {
            agent,
            recipient,
            asset,
        };
        let allowance = Allowance {
            agent: id.agent.clone(),
            recipient: id.recipient.clone(),
            asset: id.asset.clone(),
            limit,
            spent: 0,
            expires_at,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Allowance(id), &allowance);
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("allow")), ());
        Self::unlock(&env);
        Ok(())
    }

    /// Remove an active withdrawal allowance (admin only).
    pub fn remove_allowance(
        env: Env,
        admin: Address,
        agent: Address,
        recipient: Address,
        asset: Address,
    ) -> Result<(), Error> {
        let _t = Self::require_admin(&env, &admin)?;
        let id = AllowanceId {
            agent,
            recipient,
            asset,
        };
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Allowance(id.clone()))
        {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&DataKey::Allowance(id));
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("allowrm")), ());
        Self::unlock(&env);
        Ok(())
    }

    /// Read the current state of a withdrawal allowance.
    pub fn allowance(
        env: Env,
        agent: Address,
        recipient: Address,
        asset: Address,
    ) -> Result<Allowance, Error> {
        let id = AllowanceId {
            agent,
            recipient,
            asset,
        };
        env.storage()
            .persistent()
            .get(&DataKey::Allowance(id))
            .ok_or(Error::NotFound)
    }

    /// Withdraw assets to a recipient. Only the admin may call, and the spend
    /// must clear policy and budget gates before the ledger is debited.
    ///
    /// While the circuit breaker is engaged this short-circuits with
    /// [`Error::TreasuryPaused`] before any other gate is consulted.
    pub fn withdraw(
        env: Env,
        caller: Address,
        asset: Address,
        to: Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        Self::require_not_paused(&env)?;
        Self::check_frozen(&env)?;
        let t = Self::load(&env);
        Self::require_active(&t)?;
        if t.admin != caller {
            return Err(Error::Unauthorized);
        }
        caller.require_auth();

        // 1. Routing validation — refuse to invoke a token contract the
        //    organization has not approved, before any gate is consulted.
        Self::require_approved_asset(&env, &asset)?;

        // 2. Policy verification — the policy contract evaluates the spend.
        if let Some(policy_addr) = &t.policy {
            PolicyClient::new(&env, policy_addr).check_transfer(
                &String::from_str(&env, "active"),
                &asset,
                &to,
                &amount,
            );
        }

        // 3. Budget consumption — aborts if the envelope lacks headroom.
        let mut holding = Self::load_holding(&env, &asset);
        if let (Some(budget_addr), Some(budget_id)) = (&t.budget, &holding.budget_id) {
            astroid_interfaces::BudgetClient::new(&env, budget_addr)
                .consume(&caller, budget_id, &amount);
        }

        // 3. Withdrawal allowance enforcement — restrict agent-driven spends to
        //    pre-approved periodic ceilings per (agent, recipient, asset).
        Self::lock(&env)?;

        let allowance_id = AllowanceId {
            agent: caller.clone(),
            recipient: to.clone(),
            asset: asset.clone(),
        };
        if let Some(mut al) = env
            .storage()
            .persistent()
            .get::<DataKey, Allowance>(&DataKey::Allowance(allowance_id.clone()))
        {
            if al.expires_at != 0 && env.ledger().timestamp() >= al.expires_at {
                Self::unlock(&env);
                return Err(Error::AllowanceExpired);
            }
            let remaining = checked_sub(al.limit, al.spent)?;
            if amount > remaining {
                Self::unlock(&env);
                return Err(Error::AllowanceExceeded);
            }
            al.spent = checked_add(al.spent, amount)?;
            env.storage()
                .persistent()
                .set(&DataKey::Allowance(allowance_id), &al);
        }

        // 4. Debit the internal ledger, then move real tokens out of custody.
        if holding.total_in < amount {
            Self::unlock(&env);
            return Err(Error::InsufficientFunds);
        }
        holding.total_in = checked_sub(holding.total_in, amount)?;
        holding.total_out = checked_add(holding.total_out, amount)?;
        Self::store_holding(&env, &asset, &holding);
        events::transfer_executed(&env, &t.admin, &to, &asset, amount);
        Self::transfer_out(&env, &asset, &to, amount)?;
        events::transfer_executed(&env, &t.admin, &to, &asset, amount);
        events::publish(
            &env,
            events::ContractEvent::TransferExecuted {
                from: t.admin.clone(),
                to: to.clone(),
                asset: asset.clone(),
                amount,
            },
        );
        Self::unlock(&env);
        Ok(())
    }

    /// Disburse `payments` of a single `asset` to many recipients in one atomic
    /// transaction. Only the admin may call, and the batch clears exactly the
    /// same gates as [`TreasuryContract::withdraw`] — policy per leg, budget for
    /// the aggregate — before the ledger is debited.
    ///
    /// The payout total is accumulated with the shared checked-math helpers and
    /// verified against the treasury's recorded balance up front, so an
    /// over-drawing batch is rejected before any token moves. Beyond that,
    /// atomicity is guaranteed by the host: returning an error (or a failing
    /// sub-call, such as a policy denial or a token transfer) rolls back every
    /// storage write and every transfer made earlier in the invocation, so a
    /// batch either pays every recipient or none of them.
    ///
    /// Like every other outflow it is refused with [`Error::TreasuryPaused`]
    /// while the emergency circuit breaker is engaged - a batch payout is a
    /// disbursement like any other.
    pub fn batch_transfer(
        env: Env,
        caller: Address,
        asset: Address,
        payments: Vec<Payment>,
    ) -> Result<(), Error> {
        if payments.is_empty() || payments.len() > MAX_BATCH_PAYMENTS {
            return Err(Error::InvalidInput);
        }
        Self::require_not_paused(&env)?;
        Self::check_frozen(&env)?;
        let t = Self::load(&env);
        Self::require_active(&t)?;
        if t.admin != caller {
            return Err(Error::Unauthorized);
        }
        caller.require_auth();

        // 1. Validate every leg and accumulate the payout with checked math, so
        //    a malformed or overflowing batch is rejected before anything moves.
        let mut total: i128 = 0;
        for payment in payments.iter() {
            require_positive_amount(payment.amount)?;
            total = checked_add(total, payment.amount)?;
        }

        // 2. Cumulative balance check against the recorded holding.
        let mut holding = Self::load_holding(&env, &asset);
        if holding.total_in < total {
            return Err(Error::InsufficientFunds);
        }

        // 3. Policy verification — each leg is evaluated on its own, because
        //    per-recipient and per-amount gates are what the policy encodes.
        if let Some(policy_addr) = &t.policy {
            let policy = PolicyClient::new(&env, policy_addr);
            let policy_id = String::from_str(&env, "active");
            for payment in payments.iter() {
                policy.check_transfer(&policy_id, &asset, &payment.recipient, &payment.amount);
            }
        }

        // 4. Budget consumption — one debit for the aggregate rather than one
        //    cross-contract call per recipient.
        if let (Some(budget_addr), Some(budget_id)) = (&t.budget, &holding.budget_id) {
            astroid_interfaces::BudgetClient::new(&env, budget_addr)
                .consume(&caller, budget_id, &total);
        }

        // 5. Debit the internal ledger once, then move real tokens per recipient.
        Self::lock(&env)?;
        holding.total_in = checked_sub(holding.total_in, total)?;
        holding.total_out = checked_add(holding.total_out, total)?;
        Self::store_holding(&env, &asset, &holding);

        let token_client = token::TokenClient::new(&env, &asset);
        let custody = env.current_contract_address();
        let before = token_client.balance(&custody);
        if before < total {
            return Err(Error::InsufficientFunds);
        }
        for payment in payments.iter() {
            token_client.transfer(&custody, &payment.recipient, &payment.amount);
        }
        // The token must have debited exactly the batch total from custody.
        if checked_sub(before, token_client.balance(&custody))? != total {
            return Err(Error::InvalidState);
        }

        // A single summary event keeps the log concise; the per-recipient moves
        // are already observable as the asset contract's own transfer events.
        events::publish(
            &env,
            events::ContractEvent::BatchTransferExecuted {
                from: t.admin.clone(),
                asset: asset.clone(),
                count: payments.len(),
                total,
            },
        );
        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("batchpay")),
            (asset, payments.len(), total),
        );

        Self::unlock(&env);
        Self::unlock(&env);
        Ok(())
    }

    // --- views ---

    /// The address currently authorized to pause / unpause this treasury
    /// (alongside the multisig).
    pub fn guardian(env: Env) -> Address {
        Self::load(&env).guardian
    }

    /// Initialize a milestone-based disbursement.
    pub fn init_milestone_disbursement(
        env: Env,
        caller: Address,
        asset: Address,
        to: Address,
        total_amount: i128,
        milestones: u32,
    ) -> Result<u64, Error> {
        let _t = Self::require_admin(&env, &caller)?;
        require_positive_amount(total_amount)?;
        Self::require_approved_asset(&env, &asset)?;
        if milestones == 0 {
            return Err(Error::InvalidInput);
        }

        let amount_per_milestone = checked_div(total_amount, milestones as i128)?;
        // Fewer base units than milestones would schedule zero-value payouts.
        if amount_per_milestone == 0 {
            return Err(Error::InvalidAmount);
        }

        let count_key = DataKey::MilestoneCount;
        let count: u64 = env.storage().instance().get(&count_key).unwrap_or(0);
        let count = count.checked_add(1).ok_or(Error::Overflow)?;

        let disbursement = MilestoneDisbursement {
            total_amount,
            milestones,
            disbursed: 0,
            amount_per_milestone,
            asset,
            to,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Milestone(count), &disbursement);
        env.storage().persistent().extend_ttl(
            &DataKey::Milestone(count),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        env.storage().instance().set(&count_key, &count);
        env.events().publish(
            (symbol_short!("milestone"), symbol_short!("init")),
            (count, total_amount, milestones),
        );
        Ok(count)
    }

    /// Release the next milestone payout.
    ///
    /// An outflow like any other: refused with [`Error::TreasuryPaused`] while
    /// the emergency circuit breaker is engaged.
    pub fn release_next_milestone(
        env: Env,
        caller: Address,
        milestone_id: u64,
    ) -> Result<(), Error> {
        Self::require_not_paused(&env)?;
        let t = Self::require_admin(&env, &caller)?;
        let key = DataKey::Milestone(milestone_id);
        let mut d: MilestoneDisbursement = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;

        if d.disbursed >= d.milestones {
            return Err(Error::InvalidState);
        }

        Self::require_approved_asset(&env, &d.asset)?;

        let mut amount = d.amount_per_milestone;
        let last = d.milestones - 1; // milestones > 0, checked at init
        if d.disbursed == last {
            // The final payout absorbs the rounding remainder.
            let disbursed_so_far = checked_mul(d.amount_per_milestone, last as i128)?;
            amount = checked_sub(d.total_amount, disbursed_so_far)?;
        }

        d.disbursed = d.disbursed.checked_add(1).ok_or(Error::Overflow)?;
        env.storage().persistent().set(&key, &d);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );

        // Execute withdrawal logic
        let mut holding = Self::load_holding(&env, &d.asset);
        if let (Some(budget_addr), Some(budget_id)) = (&t.budget, &holding.budget_id) {
            astroid_interfaces::BudgetClient::new(&env, budget_addr)
                .consume(&caller, budget_id, &amount);
        }

        if holding.total_in < amount {
            return Err(Error::InsufficientFunds);
        }
        holding.total_in = checked_sub(holding.total_in, amount)?;
        holding.total_out = checked_add(holding.total_out, amount)?;
        Self::store_holding(&env, &d.asset, &holding);

        Self::transfer_out(&env, &d.asset, &d.to, amount)?;
        env.events().publish(
            (symbol_short!("milestone"), symbol_short!("disbursed")),
            (milestone_id, d.disbursed, amount),
        );
        Self::unlock(&env);
        Ok(())
    }

    pub fn get(env: Env) -> Treasury {
        Self::load(&env)
    }

    pub fn holding(env: Env, asset: Address) -> Holding {
        Self::load_holding(&env, &asset)
    }

    pub fn balances(env: Env, assets: Vec<Address>) -> Result<Vec<AssetBalance>, Error> {
        if assets.len() > MAX_BALANCE_ASSETS {
            return Err(Error::InvalidInput);
        }
        for i in 0..assets.len() {
            let asset = assets.get_unchecked(i);
            for j in (i + 1)..assets.len() {
                if assets.get_unchecked(j) == asset {
                    return Err(Error::InvalidInput);
                }
            }
        }

        let mut report = Vec::new(&env);
        for asset in assets.iter() {
            let balance = Self::read_token_balance(&env, &asset)?;
            report.push_back(AssetBalance { asset, balance });
        }
        Ok(report)
    }

    /// Live balances for every approved token, bounded by `MAX_TREASURY_ASSETS`.
    pub fn get_all_balances(env: Env) -> Result<Vec<(Address, i128)>, Error> {
        let mut report = Vec::new(&env);
        for asset in Self::approved_list(&env).iter() {
            report.push_back((asset.clone(), Self::read_token_balance(&env, &asset)?));
        }
        Ok(report)
    }

    /// Number of token contracts currently on the whitelist.
    pub fn approved_asset_count(env: Env) -> u32 {
        Self::approved_count(&env)
    }

    /// Every token contract currently on the whitelist, in approval order.
    pub fn approved_assets(env: Env) -> Vec<Address> {
        Self::approved_list(&env)
    }

    /// Position of every approved asset: live custody balance, recorded
    /// balance, cumulative outflow and the token's `decimals`. Bounded by
    /// [`MAX_TREASURY_ASSETS`]. Assets never deposited report zero balances.
    pub fn portfolio(env: Env) -> Vec<AssetPosition> {
        let custody = env.current_contract_address();
        let mut report = Vec::new(&env);
        for asset in Self::approved_list(&env).iter() {
            let token_client = token::TokenClient::new(&env, &asset);
            let holding = Self::load_holding(&env, &asset);
            report.push_back(AssetPosition {
                decimals: token_client.decimals(),
                balance: token_client.balance(&custody),
                recorded: holding.total_in,
                total_out: holding.total_out,
                asset,
            });
        }
        report
    }

    // --- internals ---

    fn load(env: &Env) -> Treasury {
        env.storage()
            .instance()
            .get(&DataKey::Treasury)
            .expect("treasury not initialized")
    }

    fn store(env: &Env, t: &Treasury) {
        env.storage().instance().set(&DataKey::Treasury, t);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }

    fn require_admin(env: &Env, caller: &Address) -> Result<Treasury, Error> {
        let t = Self::load(env);
        if t.admin != *caller {
            return Err(Error::Unauthorized);
        }
        caller.require_auth();
        Ok(t)
    }

    fn is_asset_approved(env: &Env, asset: &Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::ApprovedAsset(asset.clone()))
            .unwrap_or(false)
    }

    fn read_token_balance(env: &Env, asset: &Address) -> Result<i128, Error> {
        if !Self::is_asset_approved(env, asset) {
            return Err(Error::AssetNotAuthorized);
        }
        Ok(token::TokenClient::new(env, asset).balance(&env.current_contract_address()))
    }

    /// Reject any routing through a token contract that governance has not
    /// approved. The whitelist starts empty, so a freshly initialized treasury
    /// moves nothing until an asset is explicitly approved.
    fn require_approved_asset(env: &Env, asset: &Address) -> Result<(), Error> {
        if !Self::is_asset_approved(env, asset) {
            return Err(Error::AssetNotAuthorized);
        }
        env.storage().persistent().extend_ttl(
            &DataKey::ApprovedAsset(asset.clone()),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        Ok(())
    }

    /// Pay `amount` of `asset` out of custody to `to`, checking the live
    /// custody balance first and verifying afterwards that it fell by exactly
    /// `amount`.
    fn transfer_out(env: &Env, asset: &Address, to: &Address, amount: i128) -> Result<(), Error> {
        let token_client = token::TokenClient::new(env, asset);
        let custody = env.current_contract_address();
        let before = token_client.balance(&custody);
        if before < amount {
            return Err(Error::InsufficientFunds);
        }
        token_client.transfer(&custody, to, &amount);
        if checked_sub(before, token_client.balance(&custody))? != amount {
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    fn approved_list(env: &Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::ApprovedAssetList)
            .unwrap_or_else(|| Vec::new(env))
    }

    fn store_approved_list(env: &Env, list: &Vec<Address>) {
        env.storage()
            .instance()
            .set(&DataKey::ApprovedAssetList, list);
    }

    fn approved_count(env: &Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::ApprovedAssetCount)
            .unwrap_or(0)
    }

    fn store_approved_count(env: &Env, count: u32) {
        env.storage()
            .instance()
            .set(&DataKey::ApprovedAssetCount, &count);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }

    /// Publish a whitelist change under both the contract-local tuple topic and
    /// the canonical cross-cutting schema.
    fn emit_asset_change(env: &Env, t: &Treasury, asset: &Address, action: Symbol) {
        env.events()
            .publish((symbol_short!("treasury"), action.clone()), asset.clone());
        events::publish(
            env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action,
            },
        );
    }

    fn require_multisig(env: &Env, caller: &Address) -> Result<Treasury, Error> {
        let t = Self::load(env);
        match &t.multisig {
            Some(multisig) if multisig == caller => {
                caller.require_auth();
                Ok(t)
            }
            _ => Err(Error::Unauthorized),
        }
    }

    /// Authorize a circuit-breaker operation: the caller must be either the
    /// recorded guardian or the organization's multisig, verified against
    /// instance storage before `require_auth` is demanded.
    fn require_guardian(env: &Env, caller: &Address) -> Result<Treasury, Error> {
        let t = Self::load(env);
        let is_multisig = matches!(&t.multisig, Some(multisig) if multisig == caller);
        if t.guardian != *caller && !is_multisig {
            return Err(Error::Unauthorized);
        }
        caller.require_auth();
        Ok(t)
    }

    /// Short-circuit an outbound value movement while the emergency circuit
    /// breaker is engaged, with the dedicated [`Error::TreasuryPaused`] code.
    ///
    /// Reads the flag from instance storage on every call rather than caching
    /// it, and is never called on inbound paths: deposits must keep working
    /// during a pause so recovery funding can arrive.
    ///
    /// The breaker also lapses here: once [`MAX_PAUSE_DURATION`] has passed
    /// since [`Treasury::paused_at`], a still-set flag no longer blocks
    /// outflows. This bounds the blast radius of the breaker without trusting
    /// any external keeper to release it — if the guardian disappears mid
    /// incident, the treasury unblocks itself after the cap. A pause that
    /// must outlive the cap is the multisig-only [`Self::freeze`].
    /// Whether an engaged breaker is still inside its [`MAX_PAUSE_DURATION`]
    /// window. A lapsed pause stops blocking outflows but keeps its stale
    /// flag stored until [`Self::unpause`] clears it or [`Self::pause`]
    /// re-engages over it.
    fn pause_is_active(t: &Treasury, env: &Env) -> bool {
        t.paused && env.ledger().timestamp() < t.paused_at.saturating_add(MAX_PAUSE_DURATION)
    }

    fn require_not_paused(env: &Env) -> Result<(), Error> {
        if Self::pause_is_active(&Self::load(env), env) {
            return Err(Error::TreasuryPaused);
        }
        Ok(())
    }

    fn check_frozen(env: &Env) -> Result<(), Error> {
        let frozen: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Frozen)
            .unwrap_or(false);
        if frozen {
            return Err(Error::InvalidState);
        }
        Self::unlock(env);
        Ok(())
    }

    fn bump_frozen(env: &Env) {
        env.storage().persistent().extend_ttl(
            &DataKey::Frozen,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }

    fn require_active(t: &Treasury) -> Result<(), Error> {
        match t.state {
            ResourceState::Active => Ok(()),
            _ => Err(Error::InvalidState),
        }
    }

    fn lock(env: &Env) -> Result<(), Error> {
        let is_locked: bool = env
            .storage()
            .instance()
            .get(&DataKey::ReentrancyLock)
            .unwrap_or(false);
        if is_locked {
            return Err(Error::InvalidState);
        }
        env.storage()
            .instance()
            .set(&DataKey::ReentrancyLock, &true);
        Self::unlock(env);
        Ok(())
    }

    fn unlock(env: &Env) {
        env.storage()
            .instance()
            .set(&DataKey::ReentrancyLock, &false);
    }

    fn load_holding(env: &Env, asset: &Address) -> Holding {
        env.storage()
            .persistent()
            .get(&DataKey::Holding(asset.clone()))
            .unwrap_or(Holding {
                asset: asset.clone(),
                total_in: 0,
                total_out: 0,
                budget_id: None,
            })
    }

    fn store_holding(env: &Env, asset: &Address, h: &Holding) {
        env.storage()
            .persistent()
            .set(&DataKey::Holding(asset.clone()), h);
        env.storage().persistent().extend_ttl(
            &DataKey::Holding(asset.clone()),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }
}

// ---------------------------------------------------------------------------
// Shared read surface, exposed through `TreasuryInterface`.
// ---------------------------------------------------------------------------
#[contractimpl]
impl TreasuryInterface for TreasuryContract {
    fn balance(env: Env, asset: Address) -> Result<i128, Error> {
        Self::read_token_balance(&env, &asset)
    }

    /// Whether `asset` is currently approved for routing.
    fn is_approved_asset(env: Env, asset: Address) -> bool {
        Self::is_asset_approved(&env, &asset)
    }

    /// Whether the emergency circuit breaker is currently engaged — that is,
    /// a pause is stored *and* still inside its [`MAX_PAUSE_DURATION`] window.
    /// A breaker left past its window reads `false` here even before the
    /// stale flag is cleared, matching when outflows actually resume.
    fn is_paused(env: Env) -> bool {
        let t = Self::load(&env);
        Self::pause_is_active(&t, &env)
    }
}

// ---------------------------------------------------------------------------
// Registry-gated upgrades, exposed through the shared `UpgradeableInterface`.
// ---------------------------------------------------------------------------
#[contractimpl]
impl UpgradeableInterface for TreasuryContract {
    /// Record (or rotate) who may upgrade this contract and which registry
    /// authorizes the new code. Bootstrapped by the deployer alongside
    /// `initialize`; afterwards only the current upgrade admin may rotate it.
    fn set_upgrade_authority(
        env: Env,
        caller: Address,
        admin: Address,
        registry: Address,
    ) -> Result<(), Error> {
        astroid_interfaces::upgrade::set_authority(&env, &caller, &admin, &registry)
    }

    /// Read the recorded upgrade authority.
    fn get_upgrade_authority(
        env: Env,
    ) -> Result<astroid_interfaces::upgrade::UpgradeAuthority, Error> {
        astroid_interfaces::upgrade::get_authority(&env)
    }

    /// Replace this contract's code with `wasm_hash`.
    ///
    /// Two gates must pass: `caller` must be the recorded upgrade admin, and
    /// `wasm_hash` must be approved for `ModuleKind::Treasury` in the registry.
    /// Any other outcome leaves the contract running its current code.
    fn upgrade(env: Env, caller: Address, wasm_hash: soroban_sdk::BytesN<32>) -> Result<(), Error> {
        astroid_interfaces::upgrade::perform(
            &env,
            &caller,
            astroid_shared::types::ModuleKind::Treasury,
            wasm_hash,
        )
    }
}

#[cfg(test)]
mod test;
