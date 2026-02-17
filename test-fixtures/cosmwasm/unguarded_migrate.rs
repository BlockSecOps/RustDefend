// Test fixture for CW-010: unguarded-migrate-entry
// Migrate handler without admin/sender check or version validation

fn migrate(deps: DepsMut, env: Env, msg: MigrateMsg) -> StdResult<Response> {
    CONFIG.save(deps.storage, &Config { new_field: msg.new_field })?;
    STATE.update(deps.storage, |mut s| -> StdResult<_> {
        s.migrated = true;
        Ok(s)
    })?;
    Ok(Response::new().add_attribute("action", "migrate"))
}

fn migrate_v2(deps: DepsMut, env: Env, msg: MigrateMsg) -> StdResult<Response> {
    let new_config = Config {
        param_a: msg.param_a,
        param_b: msg.param_b,
        enabled: true,
    };
    CONFIG.save(deps.storage, &new_config)?;
    COUNTER.save(deps.storage, &0u64)?;
    Ok(Response::new().add_attribute("action", "migrate_v2"))
}
