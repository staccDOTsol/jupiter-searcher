use switchboard_solana_macros::switchboard_function;

// SWITCHBOARD_FUNCTION_SIMULATION=1 cargo run --example simulation

#[switchboard_function]
pub async fn my_function_logic(
    _runner: FunctionRunner,
    _params: Vec<u8>,
) -> Result<Vec<Instruction>, SbFunctionError> {
    Ok(vec![])
}
