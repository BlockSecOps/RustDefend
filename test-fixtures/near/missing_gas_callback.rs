// Test fixture for NEAR-012: missing-gas-for-callbacks
// Cross-contract calls without explicit gas specification

fn transfer_and_call(receiver_id: AccountId, amount: U128) {
    self.internal_transfer(&env::predecessor_account_id(), &receiver_id, amount.0);
    Promise::new(receiver_id).function_call(
        "on_transfer".to_string(),
        json!({ "amount": amount }).to_string().into_bytes(),
        0,
        DEFAULT_GAS,
    );
    ext_self::on_transfer_complete(env::current_account_id());
}

fn execute_swap(pool_id: u64, token_in: AccountId, amount: U128) {
    ext_contract::swap(
        pool_id,
        token_in.clone(),
        amount,
        env::current_account_id(),
    );
}
