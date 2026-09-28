#![cfg(test)]
extern crate std;

use soroban_sdk::{
    testutils::{Address as _, Events, Ledger},
    token, vec, Address, Env, IntoVal, String, Symbol, Val, Vec,
};

use astroid_shared::constants::{MAX_BATCH_PAYMENTS, MAX_PAUSE_DURATION};
use astroid_shared::errors::Error;
use astroid_shared::types::Payment;

use crate::{TreasuryContract, TreasuryContractClient};

/// Assert that the canonical `ContractEvent` with the given variant symbol was
/// published during the test (single-topic event = the variant name).
fn assert_event(env: &Env, variant: &str) {
    let want: Val = Symbol::new(env, variant).into_val(env);
    let found = env
        .events()
        .all()
        .iter()
        .any(|(_contract_id, topics, _data)| topics.contains(want));
    assert!(found, "expected ContractEvent::{} to be emitted", variant);
}

struct Harness<'a> {
    env: Env,
    client: TreasuryContractClient<'a>,
    admin: Address,
    multisig: Address,
    asset: Address,
}

/// Register a treasury plus a test SAC token, approve that token for routing,
/// and mint `funded` of the asset to the admin so deposits move real value.
fn setup(org: &str, funded: i128) -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let multisig = Address::generate(&env);

    let id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &id);
    client.initialize(&String::from_str(&env, org), &admin);
    client.set_multisig(&admin, &multisig);

    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();

    if funded > 0 {
        token::StellarAssetClient::new(&env, &asset).mint(&admin, &funded);
    }
    client.add_approved_asset(&admin, &asset);

    Harness {
        env,
        client,
        admin,
        multisig,
        asset,
    }
}

fn token_balance(h: &Harness, who: &Address) -> i128 {
    token::TokenClient::new(&h.env, &h.asset).balance(who)
}

#[test]
fn full_flow_deposit_allocate_withdraw() {
    let h = setup("vault", 1_000);
    let recipient = Address::generate(&h.env);

    h.client.deposit(&h.admin, &h.asset, &1_000);
    // Internal accounting and real custody both reflect the deposit.
    assert_eq!(h.client.holding(&h.asset).total_in, 1_000);
    assert_eq!(token_balance(&h, &h.admin), 0);
    assert_eq!(token_balance(&h, &h.client.address), 1_000);

    h.client
        .allocate_budget(&h.admin, &h.asset, &String::from_str(&h.env, "maint"));

    h.client.withdraw(&h.admin, &h.asset, &recipient, &400);
    let holding = h.client.holding(&h.asset);
    assert_eq!(holding.total_in, 600);
    assert_eq!(holding.total_out, 400);
    // Real tokens left custody and reached the recipient.
    assert_eq!(token_balance(&h, &recipient), 400);
    assert_eq!(token_balance(&h, &h.client.address), 600);
}

#[test]
fn withdraw_rejected_when_not_admin() {
    let h = setup("vault", 500);
    let intruder = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &500);

    // intruder is not the admin — refused before any value moves.
    let res = h
        .client
        .try_withdraw(&intruder, &h.asset, &Address::generate(&h.env), &100);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(token_balance(&h, &h.client.address), 500);
}

#[test]
fn withdraw_overdraws() {
    let h = setup("vault", 50);
    h.client.deposit(&h.admin, &h.asset, &50);

    let res = h
        .client
        .try_withdraw(&h.admin, &h.asset, &Address::generate(&h.env), &100);
    assert_eq!(res, Err(Ok(Error::InsufficientFunds)));
    assert_eq!(token_balance(&h, &h.client.address), 50);
}

#[test]
fn frozen_treasury_rejects_withdrawals() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.freeze(&h.multisig);

    let res = h
        .client
        .try_withdraw(&h.admin, &h.asset, &Address::generate(&h.env), &10);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
}

#[test]
fn deposit_into_frozen_treasury_allowed() {
    let h = setup("vault", 1_000);
    h.client.freeze(&h.multisig);
    // Deposits should be allowed even when frozen (only outbound transfers are blocked)
    h.client.deposit(&h.admin, &h.asset, &100);
    // Value moved into the treasury despite being frozen.
    assert_eq!(token_balance(&h, &h.admin), 900);
    assert_eq!(token_balance(&h, &h.client.address), 100);
}

#[test]
fn prepare_holds_state() {
    let h = setup("vault", 0);
    let state = h.client.get();
    assert_eq!(state.org, String::from_str(&h.env, "vault"));
}

#[test]
fn allowance_caps_withdrawal_and_accumulates() {
    let h = setup("vault", 1_000);
    let recipient = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    // Approve a 500 ceiling for admin -> recipient in this asset.
    h.client
        .set_allowance(&h.admin, &h.admin, &recipient, &h.asset, &500, &0);

    // First withdrawal within the ceiling succeeds and is deducted.
    h.client.withdraw(&h.admin, &h.asset, &recipient, &400);
    let al = h.client.allowance(&h.admin, &recipient, &h.asset);
    assert_eq!(al.spent, 400);
    assert_eq!(token_balance(&h, &recipient), 400);

    // Second withdrawal exceeds the remaining 100 -> rejected at the allowance gate.
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &200);
    assert_eq!(res, Err(Ok(Error::AllowanceExceeded)));
    assert_eq!(token_balance(&h, &recipient), 400);

    // A different recipient is not under the allowance, so it is allowed.
    let other = Address::generate(&h.env);
    h.client.withdraw(&h.admin, &h.asset, &other, &100);
    assert_eq!(token_balance(&h, &other), 100);
}

#[test]
fn expired_allowance_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(10_000);
    let admin = Address::generate(&env);
    let id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &id);
    client.initialize(&String::from_str(&env, "vault"), &admin);
    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    token::StellarAssetClient::new(&env, &asset).mint(&admin, &1_000);
    client.add_approved_asset(&admin, &asset);
    client.deposit(&admin, &asset, &1_000);

    // Allowance already expired (expires_at in the past).
    let recipient = Address::generate(&env);
    client.set_allowance(&admin, &admin, &recipient, &asset, &500, &5_000);
    let res = client.try_withdraw(&admin, &asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::AllowanceExpired)));
}

#[test]
fn remove_allowance_clears_cap() {
    let h = setup("vault", 1_000);
    let recipient = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client
        .set_allowance(&h.admin, &h.admin, &recipient, &h.asset, &100, &0);
    h.client
        .remove_allowance(&h.admin, &h.admin, &recipient, &h.asset);
    // With no allowance in place the full balance may be withdrawn.
    h.client.withdraw(&h.admin, &h.asset, &recipient, &1_000);
    assert_eq!(token_balance(&h, &recipient), 1_000);
}

#[test]
fn test_milestone_releases() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &contract_id);
    client.initialize(&soroban_sdk::String::from_str(&env, "org"), &admin);

    let token = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let token_admin = token::StellarAssetClient::new(&env, &token);
    let token_client = token::TokenClient::new(&env, &token);
    client.add_approved_asset(&admin, &token);

    let to = Address::generate(&env);

    let mid = client.init_milestone_disbursement(&admin, &token, &to, &1000, &3);
    assert_eq!(mid, 1);

    // Deposit 1000 into treasury so we have funds
    token_admin.mint(&admin, &1000);
    client.deposit(&admin, &token, &1000);

    // release milestone 1
    client.release_next_milestone(&admin, &mid);
    assert_eq!(token_client.balance(&to), 333); // 1000 / 3

    // release milestone 2
    client.release_next_milestone(&admin, &mid);
    assert_eq!(token_client.balance(&to), 666);

    // release milestone 3 (final, catches remainder)
    client.release_next_milestone(&admin, &mid);
    assert_eq!(token_client.balance(&to), 1000);

    // releasing beyond fails
    let res = client.try_release_next_milestone(&admin, &mid);
    assert!(res.is_err());
}

#[test]
fn standard_events_emitted() {
    // Configuration changes publish a TreasuryConfigUpdated event. Setting a
    // (here placeholder) policy/budget address is enough to exercise the emit
    // path; we avoid a subsequent withdraw on this env because a real policy
    // gate is not wired up.
    let h = setup("vault", 0);
    h.client.set_policy(&h.admin, &h.admin);
    assert_event(&h.env, "TreasuryConfigUpdated");
    h.client.set_budget(&h.admin, &h.admin);
    assert_event(&h.env, "TreasuryConfigUpdated");

    // A successful withdraw (no policy/budget gates configured) publishes a
    // TransferExecuted event.
    let h2 = setup("vault", 1_000);
    let recipient = Address::generate(&h2.env);
    h2.client.deposit(&h2.admin, &h2.asset, &1_000);
    h2.client.withdraw(&h2.admin, &h2.asset, &recipient, &100);
    assert_event(&h2.env, "TransferExecuted");
}

// ---------------------------------------------------------------------------
// Multi-token asset whitelist and routing validation
// ---------------------------------------------------------------------------

/// Register a second SAC token that the treasury has *not* approved, minting
/// `funded` of it to the admin.
fn unapproved_token(h: &Harness, funded: i128) -> Address {
    let token_admin = Address::generate(&h.env);
    let asset = h
        .env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    if funded > 0 {
        token::StellarAssetClient::new(&h.env, &asset).mint(&h.admin, &funded);
    }
    asset
}

#[test]
fn governance_adds_and_removes_approved_assets() {
    let h = setup("vault", 100);
    // setup approved exactly one asset.
    assert!(h.client.is_approved_asset(&h.asset));
    assert_eq!(h.client.approved_asset_count(), 1);

    let other = unapproved_token(&h, 0);
    assert!(!h.client.is_approved_asset(&other));

    h.client.add_approved_asset(&h.admin, &other);
    assert!(h.client.is_approved_asset(&other));
    assert_eq!(h.client.approved_asset_count(), 2);

    h.client.remove_approved_asset(&h.admin, &other);
    assert!(!h.client.is_approved_asset(&other));
    assert_eq!(h.client.approved_asset_count(), 1);

    // With nothing approved, the treasury routes nothing at all — which is
    // also the state a freshly initialized treasury starts in.
    h.client.remove_approved_asset(&h.admin, &h.asset);
    assert_eq!(h.client.approved_asset_count(), 0);
    assert_eq!(
        h.client.try_deposit(&h.admin, &h.asset, &10),
        Err(Ok(Error::AssetNotAuthorized))
    );
}

#[test]
fn whitelist_changes_are_idempotency_checked() {
    let h = setup("vault", 0);
    assert_eq!(
        h.client.try_add_approved_asset(&h.admin, &h.asset),
        Err(Ok(Error::AlreadyExists))
    );
    let other = unapproved_token(&h, 0);
    assert_eq!(
        h.client.try_remove_approved_asset(&h.admin, &other),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn only_governance_can_change_the_whitelist() {
    let h = setup("vault", 0);
    let intruder = Address::generate(&h.env);
    let other = unapproved_token(&h, 0);

    assert_eq!(
        h.client.try_add_approved_asset(&intruder, &other),
        Err(Ok(Error::Unauthorized))
    );
    assert!(!h.client.is_approved_asset(&other));

    assert_eq!(
        h.client.try_remove_approved_asset(&intruder, &h.asset),
        Err(Ok(Error::Unauthorized))
    );
    assert!(h.client.is_approved_asset(&h.asset));
}

#[test]
fn deposit_of_an_unapproved_asset_is_refused() {
    let h = setup("vault", 0);
    let rogue = unapproved_token(&h, 1_000);

    let res = h.client.try_deposit(&h.admin, &rogue, &500);
    assert_eq!(res, Err(Ok(Error::AssetNotAuthorized)));
    // The rogue token contract was never invoked: no value moved.
    assert_eq!(
        token::TokenClient::new(&h.env, &rogue).balance(&h.admin),
        1_000
    );
    assert_eq!(h.client.holding(&rogue).total_in, 0);
}

#[test]
fn withdraw_of_an_unapproved_asset_is_refused() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    let recipient = Address::generate(&h.env);

    // Revoking approval closes the route without touching the accounting.
    h.client.remove_approved_asset(&h.admin, &h.asset);
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::AssetNotAuthorized)));
    assert_eq!(token_balance(&h, &recipient), 0);
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
    assert_eq!(h.client.holding(&h.asset).total_in, 1_000);

    // Re-approving restores it.
    h.client.add_approved_asset(&h.admin, &h.asset);
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 100);
}

#[test]
fn budget_envelopes_cannot_be_bound_to_unapproved_assets() {
    let h = setup("vault", 0);
    let rogue = unapproved_token(&h, 0);
    let res = h
        .client
        .try_allocate_budget(&h.admin, &rogue, &String::from_str(&h.env, "maint"));
    assert_eq!(res, Err(Ok(Error::AssetNotAuthorized)));
    assert_eq!(h.client.holding(&rogue).budget_id, None);
}

#[test]
fn multiple_approved_assets_route_independently() {
    let h = setup("vault", 1_000);
    let second = unapproved_token(&h, 500);
    h.client.add_approved_asset(&h.admin, &second);
    let recipient = Address::generate(&h.env);

    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.deposit(&h.admin, &second, &500);
    h.client.withdraw(&h.admin, &h.asset, &recipient, &400);
    h.client.withdraw(&h.admin, &second, &recipient, &200);

    assert_eq!(h.client.holding(&h.asset).total_out, 400);
    assert_eq!(h.client.holding(&second).total_out, 200);
    assert_eq!(token_balance(&h, &recipient), 400);
    assert_eq!(
        token::TokenClient::new(&h.env, &second).balance(&recipient),
        200
    );

    // Revoking one asset leaves the other fully usable.
    h.client.remove_approved_asset(&h.admin, &second);
    assert_eq!(
        h.client.try_withdraw(&h.admin, &second, &recipient, &10),
        Err(Ok(Error::AssetNotAuthorized))
    );
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 500);
}

#[test]
fn balance_reports_actual_custody_across_assets() {
    let h = setup("vault", 1_000);
    let second = unapproved_token(&h, 250);
    h.client.add_approved_asset(&h.admin, &second);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.deposit(&h.admin, &second, &250);
    token::StellarAssetClient::new(&h.env, &h.asset).mint(&h.client.address, &7);

    assert_eq!(h.client.balance(&h.asset), 1_007);
    assert_eq!(h.client.balance(&second), 250);

    let assets: Vec<Address> = vec![&h.env, second.clone(), h.asset.clone()];
    let report = h.client.balances(&assets);
    assert_eq!(report.len(), 2);
    assert_eq!(report.get(0).unwrap().asset, second);
    assert_eq!(report.get(0).unwrap().balance, 250);
    assert_eq!(report.get(1).unwrap().asset, h.asset);
    assert_eq!(report.get(1).unwrap().balance, 1_007);
}

#[test]
fn balance_queries_require_approved_assets() {
    let h = setup("vault", 0);
    let rogue = unapproved_token(&h, 100);

    assert_eq!(
        h.client.try_balance(&rogue),
        Err(Ok(Error::AssetNotAuthorized))
    );
    let assets: Vec<Address> = vec![&h.env, rogue];
    assert_eq!(
        h.client.try_balances(&assets),
        Err(Ok(Error::AssetNotAuthorized))
    );
}

#[test]
fn balance_report_rejects_duplicate_assets() {
    let h = setup("vault", 0);
    let assets: Vec<Address> = vec![&h.env, h.asset.clone(), h.asset.clone()];

    assert_eq!(h.client.try_balances(&assets), Err(Ok(Error::InvalidInput)));
}

#[test]
fn balance_report_rejects_oversized_asset_lists() {
    let h = setup("vault", 0);
    let mut assets: Vec<Address> = Vec::new(&h.env);
    for _ in 0..33 {
        assets.push_back(Address::generate(&h.env));
    }

    assert_eq!(h.client.try_balances(&assets), Err(Ok(Error::InvalidInput)));
}

#[test]
fn balance_report_is_empty_for_no_assets() {
    let h = setup("vault", 0);
    let assets: Vec<Address> = Vec::new(&h.env);

    assert!(h.client.balances(&assets).is_empty());
}

#[test]
fn whitelist_changes_emit_events() {
    let h = setup("vault", 0);
    let other = unapproved_token(&h, 0);
    h.client.add_approved_asset(&h.admin, &other);
    assert_event(&h.env, "TreasuryConfigUpdated");
    h.client.remove_approved_asset(&h.admin, &other);
    assert_event(&h.env, "TreasuryConfigUpdated");
}

/// Build one leg of a batch payout.
fn payment(recipient: &Address, amount: i128) -> Payment {
    Payment {
        recipient: recipient.clone(),
        amount,
    }
}

#[test]
fn batch_transfer_pays_every_recipient() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    let a = Address::generate(&h.env);
    let b = Address::generate(&h.env);
    let c = Address::generate(&h.env);
    let payments: Vec<Payment> = vec![&h.env, payment(&a, 100), payment(&b, 250), payment(&c, 50)];

    h.client.batch_transfer(&h.admin, &h.asset, &payments);

    assert_eq!(token_balance(&h, &a), 100);
    assert_eq!(token_balance(&h, &b), 250);
    assert_eq!(token_balance(&h, &c), 50);
    assert_eq!(token_balance(&h, &h.client.address), 600);

    // Internal accounting mirrors the aggregate payout exactly once.
    let holding = h.client.holding(&h.asset);
    assert_eq!(holding.total_in, 600);
    assert_eq!(holding.total_out, 400);

    assert_event(&h.env, "BatchTransferExecuted");
}

#[test]
fn batch_transfer_over_balance_pays_nobody() {
    let h = setup("vault", 300);
    h.client.deposit(&h.admin, &h.asset, &300);

    let a = Address::generate(&h.env);
    let b = Address::generate(&h.env);
    // Each leg fits on its own, but the cumulative total overdraws the treasury.
    let payments: Vec<Payment> = vec![&h.env, payment(&a, 200), payment(&b, 200)];

    let res = h.client.try_batch_transfer(&h.admin, &h.asset, &payments);
    assert_eq!(res, Err(Ok(Error::InsufficientFunds)));

    // Nothing partially executed: no recipient was paid and custody is intact.
    assert_eq!(token_balance(&h, &a), 0);
    assert_eq!(token_balance(&h, &b), 0);
    assert_eq!(token_balance(&h, &h.client.address), 300);
    let holding = h.client.holding(&h.asset);
    assert_eq!(holding.total_in, 300);
    assert_eq!(holding.total_out, 0);
}

#[test]
fn batch_transfer_rolls_back_when_one_leg_is_invalid() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    let a = Address::generate(&h.env);
    let b = Address::generate(&h.env);
    let c = Address::generate(&h.env);
    // The middle leg is a zero-amount payment, which invalidates the batch.
    let payments: Vec<Payment> = vec![&h.env, payment(&a, 100), payment(&b, 0), payment(&c, 100)];

    let res = h.client.try_batch_transfer(&h.admin, &h.asset, &payments);
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));

    // The legs preceding the bad one are rolled back with the rest of the batch.
    assert_eq!(token_balance(&h, &a), 0);
    assert_eq!(token_balance(&h, &c), 0);
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
    assert_eq!(h.client.holding(&h.asset).total_out, 0);
}

#[test]
fn batch_transfer_rejected_when_not_admin() {
    let h = setup("vault", 500);
    h.client.deposit(&h.admin, &h.asset, &500);

    let intruder = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let payments: Vec<Payment> = vec![&h.env, payment(&recipient, 10)];

    let res = h.client.try_batch_transfer(&intruder, &h.asset, &payments);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(token_balance(&h, &h.client.address), 500);
}

#[test]
fn batch_transfer_rejected_when_frozen() {
    let h = setup("vault", 500);
    h.client.deposit(&h.admin, &h.asset, &500);
    h.client.freeze(&h.multisig);

    let recipient = Address::generate(&h.env);
    let payments: Vec<Payment> = vec![&h.env, payment(&recipient, 10)];

    let res = h.client.try_batch_transfer(&h.admin, &h.asset, &payments);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(token_balance(&h, &recipient), 0);
}

#[test]
fn batch_transfer_rejects_empty_and_oversized_batches() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    let empty: Vec<Payment> = Vec::new(&h.env);
    assert_eq!(
        h.client.try_batch_transfer(&h.admin, &h.asset, &empty),
        Err(Ok(Error::InvalidInput))
    );

    let mut oversized: Vec<Payment> = Vec::new(&h.env);
    for _ in 0..(MAX_BATCH_PAYMENTS + 1) {
        let r = Address::generate(&h.env);
        oversized.push_back(payment(&r, 1));
    }
    assert_eq!(
        h.client.try_batch_transfer(&h.admin, &h.asset, &oversized),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
}

#[test]
fn batch_transfer_at_the_maximum_size_succeeds() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    let mut payments: Vec<Payment> = Vec::new(&h.env);
    let mut recipients = std::vec::Vec::new();
    for _ in 0..MAX_BATCH_PAYMENTS {
        let r = Address::generate(&h.env);
        payments.push_back(payment(&r, 5));
        recipients.push(r);
    }

    h.client.batch_transfer(&h.admin, &h.asset, &payments);

    for r in recipients.iter() {
        assert_eq!(token_balance(&h, r), 5);
    }
    let holding = h.client.holding(&h.asset);
    assert_eq!(holding.total_out, 5 * MAX_BATCH_PAYMENTS as i128);
    assert_eq!(holding.total_in, 1_000 - 5 * MAX_BATCH_PAYMENTS as i128);
}

#[test]
fn emergency_freeze_rejected_by_non_multisig() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // Admin should not be able to freeze - only multisig
    let res = h.client.try_freeze(&h.admin);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));

    // Random address should also be rejected
    let intruder = Address::generate(&h.env);
    let res = h.client.try_freeze(&intruder);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));

    // Ensure transfers still work
    let recipient = Address::generate(&h.env);
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 100);
}

#[test]
fn emergency_freeze_by_multisig_blocks_transfers() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // Multisig can freeze
    h.client.freeze(&h.multisig);

    // All outbound transfers should be blocked
    let recipient = Address::generate(&h.env);
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::InvalidState)));

    let payments: Vec<Payment> = vec![&h.env, payment(&recipient, 50)];
    let res = h.client.try_batch_transfer(&h.admin, &h.asset, &payments);
    assert_eq!(res, Err(Ok(Error::InvalidState)));

    // Verify funds are still in treasury
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
}

#[test]
fn emergency_unfreeze_restores_transfers() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // Freeze with multisig
    h.client.freeze(&h.multisig);

    // Verify frozen state blocks transfers
    let recipient = Address::generate(&h.env);
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::InvalidState)));

    // Unfreeze with multisig
    h.client.unfreeze(&h.multisig);

    // Transfers should work again
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 100);
    assert_eq!(token_balance(&h, &h.client.address), 900);
}

#[test]
fn emergency_unfreeze_rejected_by_non_multisig() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // Freeze with multisig
    h.client.freeze(&h.multisig);

    // Admin should not be able to unfreeze
    let res = h.client.try_unfreeze(&h.admin);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));

    // Random address should also be rejected
    let intruder = Address::generate(&h.env);
    let res = h.client.try_unfreeze(&intruder);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));

    // Should still be frozen
    let recipient = Address::generate(&h.env);
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
}

#[test]
fn emergency_unfreeze_without_freeze_fails() {
    let h = setup("vault", 1_000);

    // Trying to unfreeze when not frozen should fail
    let res = h.client.try_unfreeze(&h.multisig);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
}

#[test]
fn treasury_frozen_and_unfrozen_events_emitted() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // Freeze should emit TreasuryFrozen event
    h.client.freeze(&h.multisig);
    assert_event(&h.env, "TreasuryFrozen");

    // Unfreeze should emit TreasuryUnfrozen event
    h.client.unfreeze(&h.multisig);
    assert_event(&h.env, "TreasuryUnfrozen");
}

#[test]
fn freeze_without_multisig_configured_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &id);
    client.initialize(&String::from_str(&env, "vault"), &admin);

    // Try to freeze without setting multisig - should fail
    let res = client.try_freeze(&admin);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

// ---------------------------------------------------------------------------
// Emergency circuit breaker (pause / unpause)
// ---------------------------------------------------------------------------

#[test]
fn unauthorized_pause_attempts_are_rejected() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    let intruder = Address::generate(&h.env);

    // Neither direction is open to a stranger, and neither call mutates the
    // pause flag.
    assert_eq!(h.client.try_pause(&intruder), Err(Ok(Error::Unauthorized)));
    assert_eq!(
        h.client.try_unpause(&intruder),
        Err(Ok(Error::Unauthorized))
    );
    assert!(!h.client.is_paused());

    // Outflows still work, because the breaker never engaged.
    let recipient = Address::generate(&h.env);
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 100);
}

#[test]
fn guardian_can_pause_and_unpause() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // Bootstrap: the admin is recorded as the initial guardian, and a fresh
    // treasury starts with the breaker disengaged.
    assert_eq!(h.client.guardian(), h.admin);
    assert!(!h.client.is_paused());

    h.client.pause(&h.admin);
    assert!(h.client.is_paused());
    assert_event(&h.env, "TreasuryConfigUpdated");

    h.client.unpause(&h.admin);
    assert!(!h.client.is_paused());
    assert_event(&h.env, "TreasuryConfigUpdated");
}

#[test]
fn multisig_can_pause_and_unpause() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // The organization's multisig holds the authority independently of the
    // guardian slot.
    h.client.pause(&h.multisig);
    assert!(h.client.is_paused());
    h.client.unpause(&h.multisig);
    assert!(!h.client.is_paused());
}

#[test]
fn pause_blocks_outflows_and_keeps_inflows_open() {
    // 1_500 minted so 1_000 can be deposited now and 500 more during the pause.
    let h = setup("vault", 1_500);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.pause(&h.admin);

    let recipient = Address::generate(&h.env);

    // Single withdrawal refused with the dedicated code; nothing moved.
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::TreasuryPaused)));
    assert_eq!(token_balance(&h, &recipient), 0);

    // Batch payout refused with the same code; no leg is paid.
    let payments: Vec<Payment> = vec![&h.env, payment(&recipient, 50)];
    let res = h.client.try_batch_transfer(&h.admin, &h.asset, &payments);
    assert_eq!(res, Err(Ok(Error::TreasuryPaused)));
    assert_eq!(token_balance(&h, &recipient), 0);
    assert_eq!(h.client.holding(&h.asset).total_out, 0);

    // Inbound deposits stay open during a pause, so recovery funding arrives.
    h.client.deposit(&h.admin, &h.asset, &500);
    assert_eq!(token_balance(&h, &h.client.address), 1_500);
    assert_eq!(h.client.holding(&h.asset).total_in, 1_500);

    // Releasing the breaker restores every outflow.
    h.client.unpause(&h.admin);
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 100);
    assert_eq!(token_balance(&h, &h.client.address), 1_400);
}

#[test]
fn pause_blocks_milestone_disbursement() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    let to = Address::generate(&h.env);
    let mid = h
        .client
        .init_milestone_disbursement(&h.admin, &h.asset, &to, &1_000, &3);

    h.client.pause(&h.admin);
    let res = h.client.try_release_next_milestone(&h.admin, &mid);
    assert_eq!(res, Err(Ok(Error::TreasuryPaused)));
    assert_eq!(token_balance(&h, &to), 0);

    h.client.unpause(&h.admin);
    h.client.release_next_milestone(&h.admin, &mid);
    assert_eq!(token_balance(&h, &to), 333);
}

#[test]
fn pause_toggle_is_idempotency_checked() {
    let h = setup("vault", 0);
    // Unpausing a treasury that was never paused is rejected.
    assert_eq!(h.client.try_unpause(&h.admin), Err(Ok(Error::InvalidState)));
    h.client.pause(&h.admin);
    // Pausing twice is rejected rather than silently accepted.
    assert_eq!(h.client.try_pause(&h.admin), Err(Ok(Error::InvalidState)));
    assert!(h.client.is_paused());
}

#[test]
fn pause_and_freeze_report_distinct_codes() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    let recipient = Address::generate(&h.env);

    // The multisig freeze is the structural stop and reports InvalidState.
    h.client.freeze(&h.multisig);
    assert_eq!(
        h.client.try_withdraw(&h.admin, &h.asset, &recipient, &10),
        Err(Ok(Error::InvalidState))
    );
    h.client.unfreeze(&h.multisig);

    // The guardian pause is the circuit breaker and reports TreasuryPaused.
    h.client.pause(&h.admin);
    assert_eq!(
        h.client.try_withdraw(&h.admin, &h.asset, &recipient, &10),
        Err(Ok(Error::TreasuryPaused))
    );
    assert_eq!(
        h.client
            .try_batch_transfer(&h.admin, &h.asset, &vec![&h.env, payment(&recipient, 10)]),
        Err(Ok(Error::TreasuryPaused))
    );
}

#[test]
fn set_guardian_rotates_pause_authority() {
    let h = setup("vault", 1_000);
    let new_guardian = Address::generate(&h.env);

    // Only the admin may rotate the guardian.
    let intruder = Address::generate(&h.env);
    assert_eq!(
        h.client.try_set_guardian(&intruder, &new_guardian),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(h.client.guardian(), h.admin);

    h.client.set_guardian(&h.admin, &new_guardian);
    assert_eq!(h.client.guardian(), new_guardian);

    // The superseded guardian has lost the authority; the new one holds it.
    assert_eq!(h.client.try_pause(&h.admin), Err(Ok(Error::Unauthorized)));
    h.client.pause(&new_guardian);
    assert!(h.client.is_paused());

    // The multisig keeps its own, independent authority throughout.
    h.client.unpause(&h.multisig);
    assert!(!h.client.is_paused());
}

// ---------------------------------------------------------------------------
// Multi-token accounting (issue #328)
// ---------------------------------------------------------------------------

/// Minimal Soroban token with configurable `decimals` and an optional flat
/// fee burned on every transfer, to exercise non-SAC token behaviour.
#[soroban_sdk::contract]
pub struct MockToken;

#[soroban_sdk::contracttype]
#[derive(Clone)]
enum MockKey {
    Decimals,
    Fee,
    Balance(Address),
}

#[soroban_sdk::contractimpl]
impl MockToken {
    pub fn setup(env: Env, decimals: u32, fee: i128) {
        env.storage().instance().set(&MockKey::Decimals, &decimals);
        env.storage().instance().set(&MockKey::Fee, &fee);
    }

    pub fn mint(env: Env, to: Address, amount: i128) {
        let bal = Self::balance(env.clone(), to.clone());
        env.storage()
            .persistent()
            .set(&MockKey::Balance(to), &(bal + amount));
    }

    /// Remove balance without the holder's involvement (simulates a
    /// clawback or an externally drained custody account).
    pub fn burn(env: Env, from: Address, amount: i128) {
        let bal = Self::balance(env.clone(), from.clone());
        env.storage()
            .persistent()
            .set(&MockKey::Balance(from), &(bal - amount));
    }

    pub fn decimals(env: Env) -> u32 {
        env.storage().instance().get(&MockKey::Decimals).unwrap()
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&MockKey::Balance(id))
            .unwrap_or(0)
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let fee: i128 = env.storage().instance().get(&MockKey::Fee).unwrap();
        let from_bal = Self::balance(env.clone(), from.clone());
        assert!(from_bal >= amount, "insufficient balance");
        env.storage()
            .persistent()
            .set(&MockKey::Balance(from), &(from_bal - amount));
        let to_bal = Self::balance(env.clone(), to.clone());
        env.storage()
            .persistent()
            .set(&MockKey::Balance(to), &(to_bal + amount - fee));
    }
}

fn mock_token(h: &Harness, decimals: u32, fee: i128, funded: i128) -> Address {
    let id = h.env.register_contract(None, MockToken);
    let client = MockTokenClient::new(&h.env, &id);
    client.setup(&decimals, &fee);
    client.mint(&h.admin, &funded);
    id
}

#[test]
fn deposits_withdrawals_and_portfolio_across_tokens_with_different_decimals() {
    let h = setup("vault", 10_000_000_000); // SAC: 7 decimals
    let usdc6 = mock_token(&h, 6, 0, 5_000_000);
    let wbtc8 = mock_token(&h, 8, 0, 3_0000_0000);
    h.client.add_approved_asset(&h.admin, &usdc6);
    h.client.add_approved_asset(&h.admin, &wbtc8);
    let recipient = Address::generate(&h.env);

    h.client.deposit(&h.admin, &h.asset, &10_000_000_000);
    h.client.deposit(&h.admin, &usdc6, &5_000_000);
    h.client.deposit(&h.admin, &wbtc8, &2_0000_0000);

    h.client.withdraw(&h.admin, &usdc6, &recipient, &1_500_000);
    h.client.withdraw(&h.admin, &wbtc8, &recipient, &5000_0000);

    let assets = h.client.approved_assets();
    assert_eq!(
        assets,
        vec![&h.env, h.asset.clone(), usdc6.clone(), wbtc8.clone()]
    );

    let portfolio = h.client.portfolio();
    assert_eq!(portfolio.len(), 3);
    let sac = portfolio.get(0).unwrap();
    assert_eq!(
        (sac.decimals, sac.balance, sac.recorded),
        (7, 10_000_000_000, 10_000_000_000)
    );
    let usdc = portfolio.get(1).unwrap();
    assert_eq!(usdc.asset, usdc6);
    assert_eq!(
        (usdc.decimals, usdc.balance, usdc.recorded, usdc.total_out),
        (6, 3_500_000, 3_500_000, 1_500_000)
    );
    let btc = portfolio.get(2).unwrap();
    assert_eq!(
        (btc.decimals, btc.balance, btc.recorded, btc.total_out),
        (8, 1_5000_0000, 1_5000_0000, 5000_0000)
    );
    assert_eq!(
        MockTokenClient::new(&h.env, &usdc6).balance(&recipient),
        1_500_000
    );
}

#[test]
fn get_all_balances_reports_every_approved_token() {
    let h = setup("vault", 1_000);
    let funded = mock_token(&h, 6, 0, 500);
    let empty = mock_token(&h, 8, 0, 0);
    h.client.add_approved_asset(&h.admin, &funded);
    h.client.add_approved_asset(&h.admin, &empty);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.deposit(&h.admin, &funded, &500);

    let balances = h.client.get_all_balances();
    assert_eq!(balances.len(), 3);
    assert_eq!(balances.get(0).unwrap(), (h.asset.clone(), 1_000));
    assert_eq!(balances.get(1).unwrap(), (funded, 500));
    assert_eq!(balances.get(2).unwrap(), (empty, 0));
}

#[test]
fn zero_balance_assets_are_reported_and_cannot_be_withdrawn() {
    let h = setup("vault", 0);
    let empty = mock_token(&h, 2, 0, 0);
    h.client.add_approved_asset(&h.admin, &empty);

    assert_eq!(h.client.balance(&empty), 0);
    let portfolio = h.client.portfolio();
    let pos = portfolio.get(1).unwrap();
    assert_eq!(
        (pos.decimals, pos.balance, pos.recorded, pos.total_out),
        (2, 0, 0, 0)
    );

    let res = h
        .client
        .try_withdraw(&h.admin, &empty, &Address::generate(&h.env), &1);
    assert_eq!(res, Err(Ok(Error::InsufficientFunds)));
}

#[test]
fn fee_on_transfer_deposit_credits_only_what_arrived() {
    let h = setup("vault", 0);
    let taxed = mock_token(&h, 7, 10, 1_000);
    h.client.add_approved_asset(&h.admin, &taxed);

    h.client.deposit(&h.admin, &taxed, &1_000);
    // 10 was burned in transit: the books match real custody, not the request.
    assert_eq!(h.client.holding(&taxed).total_in, 990);
    assert_eq!(h.client.balance(&taxed), 990);
}

#[test]
fn deposit_that_delivers_nothing_is_rejected() {
    let h = setup("vault", 0);
    let taxed = mock_token(&h, 7, 50, 50);
    h.client.add_approved_asset(&h.admin, &taxed);

    assert_eq!(
        h.client.try_deposit(&h.admin, &taxed, &50),
        Err(Ok(Error::InvalidAmount))
    );
    assert_eq!(h.client.holding(&taxed).total_in, 0);
}

#[test]
fn withdrawal_is_verified_against_live_custody() {
    let h = setup("vault", 0);
    let taxed = mock_token(&h, 7, 5, 1_000);
    h.client.add_approved_asset(&h.admin, &taxed);
    h.client.deposit(&h.admin, &taxed, &1_000); // 995 recorded and held
    let recipient = Address::generate(&h.env);

    // The outgoing fee is charged to the recipient, custody drops by exactly
    // the amount paid, so the withdrawal verifies.
    h.client.withdraw(&h.admin, &taxed, &recipient, &500);
    assert_eq!(h.client.balance(&taxed), 495);
    assert_eq!(h.client.holding(&taxed).total_in, 495);
    assert_eq!(
        MockTokenClient::new(&h.env, &taxed).balance(&recipient),
        495
    );
}

#[test]
fn recorded_balance_above_live_custody_fails_with_insufficient_funds() {
    let h = setup("vault", 0);
    let drained = mock_token(&h, 7, 0, 1_000);
    h.client.add_approved_asset(&h.admin, &drained);
    h.client.deposit(&h.admin, &drained, &1_000);
    // Custody is drained behind the treasury's back (e.g. a clawback).
    MockTokenClient::new(&h.env, &drained).burn(&h.client.address, &600);
    let recipient = Address::generate(&h.env);

    assert_eq!(
        h.client.try_withdraw(&h.admin, &drained, &recipient, &500),
        Err(Ok(Error::InsufficientFunds))
    );
    assert_eq!(
        h.client
            .try_batch_transfer(&h.admin, &drained, &vec![&h.env, payment(&recipient, 500)]),
        Err(Ok(Error::InsufficientFunds))
    );
    // The recorded balance is untouched and the drift is visible.
    let pos = h.client.portfolio().get(1).unwrap();
    assert_eq!((pos.recorded, pos.balance), (1_000, 400));
}

#[test]
fn approved_asset_list_tracks_removals_and_is_bounded() {
    let h = setup("vault", 0);
    let second = mock_token(&h, 6, 0, 0);
    h.client.add_approved_asset(&h.admin, &second);
    h.client.remove_approved_asset(&h.admin, &h.asset);
    assert_eq!(h.client.approved_assets(), vec![&h.env, second.clone()]);
    assert_eq!(h.client.portfolio().len(), 1);

    // Fill the whitelist to capacity; one more is refused.
    while h.client.approved_asset_count() < crate::MAX_TREASURY_ASSETS {
        h.client
            .add_approved_asset(&h.admin, &Address::generate(&h.env));
    }
    assert_eq!(
        h.client
            .try_add_approved_asset(&h.admin, &Address::generate(&h.env)),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(h.client.approved_assets().len(), crate::MAX_TREASURY_ASSETS);
}

#[test]
fn milestones_reject_zero_value_payouts_and_unapproved_assets() {
    let h = setup("vault", 0);
    let to = Address::generate(&h.env);
    // 2 base units over 3 milestones would schedule zero-value payouts.
    assert_eq!(
        h.client
            .try_init_milestone_disbursement(&h.admin, &h.asset, &to, &2, &3),
        Err(Ok(Error::InvalidAmount))
    );
    let rogue = Address::generate(&h.env);
    assert_eq!(
        h.client
            .try_init_milestone_disbursement(&h.admin, &rogue, &to, &300, &3),
        Err(Ok(Error::AssetNotAuthorized))
    );
}

#[test]
fn milestone_math_is_overflow_safe_at_i128_max() {
    let h = setup("vault", i128::MAX);
    h.client.deposit(&h.admin, &h.asset, &i128::MAX);
    let to = Address::generate(&h.env);
    let id = h
        .client
        .init_milestone_disbursement(&h.admin, &h.asset, &to, &i128::MAX, &2);
    h.client.release_next_milestone(&h.admin, &id);
    h.client.release_next_milestone(&h.admin, &id);
    assert_eq!(token_balance(&h, &to), i128::MAX);
    assert_eq!(h.client.holding(&h.asset).total_in, 0);
}

// ---------------------------------------------------------------------------
// Pause window: MAX_PAUSE_DURATION auto-lapse (issue #297)
// ---------------------------------------------------------------------------

/// The breaker blocks outflows for exactly `MAX_PAUSE_DURATION` and then
/// lapses on its own: outflows resume without any guardian action while the
/// stale flag stays recorded.
#[test]
fn pause_lapses_after_max_duration_and_unblocks_outflows() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    let recipient = Address::generate(&h.env);

    h.client.pause(&h.admin);
    assert!(h.client.is_paused());

    // One second before the cap the breaker still blocks every outflow.
    h.env
        .ledger()
        .with_mut(|l| l.timestamp += MAX_PAUSE_DURATION - 1);
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::TreasuryPaused)));
    assert!(h.client.is_paused());
    assert_eq!(token_balance(&h, &h.client.address), 1_000);

    // At exactly MAX_PAUSE_DURATION the window closes: outflows resume on
    // their own without any guardian action, while the stale flag stays
    // recorded.
    h.env.ledger().with_mut(|l| l.timestamp += 1);
    assert!(!h.client.is_paused());
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 100);
    assert_eq!(token_balance(&h, &h.client.address), 900);
}

#[test]
fn lapsed_pause_keeps_inflows_open_and_is_permanently_harmless() {
    let h = setup("vault", 1_500);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.pause(&h.admin);

    h.env
        .ledger()
        .with_mut(|l| l.timestamp += MAX_PAUSE_DURATION);
    assert!(!h.client.is_paused());

    // The whole outflow surface is open again after the lapse.
    let recipient = Address::generate(&h.env);
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    let payments: Vec<Payment> = vec![&h.env, payment(&recipient, 50)];
    h.client.batch_transfer(&h.admin, &h.asset, &payments);
    assert_eq!(token_balance(&h, &recipient), 150);

    // Deposits stay open across the pause and the lapse, as always.
    h.client.deposit(&h.admin, &h.asset, &500);
    assert_eq!(token_balance(&h, &h.client.address), 1_350);
    // Internal books match: 1_500 in, 150 out.
    let holding = h.client.holding(&h.asset);
    assert_eq!(holding.total_in, 1_350);
    assert_eq!(holding.total_out, 150);
}

#[test]
fn lapsed_breaker_can_be_reengaged_with_a_fresh_window() {
    let h = setup("vault", 0);

    h.client.pause(&h.admin);
    h.env
        .ledger()
        .with_mut(|l| l.timestamp += MAX_PAUSE_DURATION);
    assert!(!h.client.is_paused());

    // The flag is stale, so the guardian can re-engage the breaker directly:
    // the new pause opens a fresh full window without a separate unpause.
    h.client.pause(&h.admin);
    assert!(h.client.is_paused());
    let recipient = Address::generate(&h.env);
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &1);
    assert_eq!(res, Err(Ok(Error::TreasuryPaused)));

    // Near the end of the fresh window the breaker is still blocking.
    h.env
        .ledger()
        .with_mut(|l| l.timestamp += MAX_PAUSE_DURATION - 1);
    assert!(h.client.is_paused());
}

#[test]
fn unpause_still_fails_when_breaker_never_engaged() {
    let h = setup("vault", 0);
    // Long past any window could have started — the treasury was never
    // paused, so the raw-flag guard keeps unpause rejected.
    h.env
        .ledger()
        .with_mut(|l| l.timestamp += MAX_PAUSE_DURATION + 1);
    assert_eq!(h.client.try_unpause(&h.admin), Err(Ok(Error::InvalidState)));
}

#[test]
fn active_pause_still_blocks_milestones_until_lapse() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    let to = Address::generate(&h.env);
    let mid = h
        .client
        .init_milestone_disbursement(&h.admin, &h.asset, &to, &1_000, &3);

    h.client.pause(&h.admin);
    h.env
        .ledger()
        .with_mut(|l| l.timestamp += MAX_PAUSE_DURATION);
    assert!(!h.client.is_paused());

    // The milestone disbursement resumes as soon as the window closes.
    h.client.release_next_milestone(&h.admin, &mid);
    assert_eq!(token_balance(&h, &to), 333);
}
