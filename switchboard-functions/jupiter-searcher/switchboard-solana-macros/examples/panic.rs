use switchboard_solana_macros::switchboard_function;

#[switchboard_function]
pub async fn my_function_logic(
    _runner: FunctionRunner,
    _params: Vec<u8>,
) -> Result<Vec<Instruction>, SbFunctionError> {
    panic!("This should not happen but we'll recover");
}
