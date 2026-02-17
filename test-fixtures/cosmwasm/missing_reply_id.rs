// Test fixture for CW-011: missing-reply-id-validation
// Reply handler not matching on msg.id

fn reply(deps: DepsMut, env: Env, msg: Reply) -> StdResult<Response> {
    let result = msg.result.into_result().map_err(StdError::generic_err)?;
    let event = result.events.iter().find(|e| e.ty == "instantiate").unwrap();
    let addr = &event.attributes[0].value;
    CHILD_CONTRACT.save(deps.storage, &deps.api.addr_validate(addr)?)?;
    Ok(Response::new())
}
