use switchboard_solana_macros::switchboard_function;

#[switchboard_function(encoding = Bytes, timeout_seconds = 10)]
pub async fn my_function_logic(
    runner: FunctionRunner,
    params: Vec<u8>,
) -> Result<Vec<Instruction>, SbFunctionError> {
    // Build an array of instructions targetted toward your program
    let ixs = vec![Instruction {
        program_id: Pubkey::default(),
        accounts: vec![],
        data: vec![],
    }];

    // Emit the instructions for the oracle to validate and relay on-chain
    Ok(ixs)
}
