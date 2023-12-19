<div align="center">

![Switchboard Logo](https://github.com/switchboard-xyz/switchboard/raw/main/website/static/img/icons/switchboard/avatar.png)

# switchboard-solana-macros

> Proc macros for creating Switchboard Functions on Solana

[![Crates.io Badge](https://img.shields.io/crates/v/switchboard-solana?label=switchboard-solana-macros&logo=rust)](https://crates.io/crates/switchboard-solana-macros)

[![Discord Badge](https://img.shields.io/discord/841525135311634443?color=blueviolet&logo=discord&logoColor=white)](https://discord.gg/switchboardxyz)

[![Twitter Badge](https://img.shields.io/twitter/follow/switchboardxyz?label=Follow+Switchboard)](https://twitter.com/switchboardxyz)

  <h4>
    <strong>Switchboard Documentation: </strong><a href="https://docs.switchboard.xyz">docs.switchboard.xyz</a>
  </h4>
</div>

## Install

Run the following Cargo command in your project directory:

```bash
cargo add switchboard-solana-macros
```

Or add the following line to your Cargo.toml:

```toml
[dependencies]
switchboard-solana-macros = "0.2.0"
```

## Usage

```rust
use switchboard_solana_macros::switchboard_function;

#[switchboard_function]
pub async fn my_function_logic(
    runner: FunctionRunner,
    params: Vec<u8>
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
```
