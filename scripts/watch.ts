import { SwitchboardProgram, loadKeypair } from "@switchboard-xyz/solana.js";
import * as anchor from "@coral-xyz/anchor";
import { UsdyUsdOracle } from "../target/types/usdy_usd_oracle";
import dotenv from "dotenv";
import { sleep } from "@switchboard-xyz/common";
import { PublicKey } from "@solana/web3.js";
import fs from 'fs'
dotenv.config();

(async () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  let program = new anchor.Program(
    JSON.parse(
      fs.readFileSync(
        "./target/idl/superior_randomness.json",
        "utf8"
      ).toString()
    ),
    new PublicKey("Gyb6RKsLsZa1UCJkCmKYHtEJQF15wF6ZeEqMUSCneh9d"),
    provider
  );
  console.log(`PROGRAM: ${program.programId}`);

  const [programStatePubkey] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("USDY_USDC_ORACLE_V3")],
    program.programId
  );
  console.log(`PROGRAM_STATE: ${programStatePubkey}`);
  const programState = await program.account.myProgramState.fetch(
    programStatePubkey
  );

  const [oraclePubkey] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("ORACLE_USDY_SEED_V3")],
    program.programId
  );
  console.log(`ORACLE_PUBKEY: ${oraclePubkey}`);

  let oracleState = await program.account.myOracleState.fetch(
    oraclePubkey
  );
  console.log(oracleState)
  console.log(programState)
  displayOracleState(oraclePubkey, oracleState as any); // apparently doesnt like _# syntax

  let lastFetched: number = Date.now();
  while (true) {
    await sleep(5000);
    console.clear();
    oracleState = await program.account.myOracleState.fetch(oraclePubkey);
    console.log(oracleState)
    displayOracleState(oraclePubkey, oracleState as any); // apparently doesnt like _# syntax
  }
})();

interface OracleState {
  bump: number;
  jitosolSol: OracleData;
  bsolSol: OracleData;
}
interface OracleData {
  oracleTimestamp: anchor.BN;
  mean: anchor.BN;
  median: anchor.BN;
  std: anchor.BN;
}
function displayOracleState(pubkey: PublicKey, oracleState: OracleState) {
  console.log(`## Oracle (${pubkey})`);
  displaySymbol(oracleState.jitosolSol, "jitosolSol");
  displaySymbol(oracleState.bsolSol, "bsolSol");
}

function displaySymbol(data: OracleData, symbol: string) {
  console.log(` > ${symbol.toUpperCase()} / USD`);
  console.log(`\Mean: $${data.mean.toString() } lamports`);
  console.log(`\Median: $${data.median.toString()  } lamports`);
  console.log(`\Population Variance: 0%`);
}
