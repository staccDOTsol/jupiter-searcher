import { SwitchboardProgram, loadKeypair } from "@switchboard-xyz/solana.js";
import * as anchor from "@coral-xyz/anchor";
import dotenv from "dotenv";
import * as mplMetadata from '@metaplex-foundation/mpl-token-metadata'
import { loadDefaultQueue } from "./utils";
import fs from 'fs'
import { Keypair, PublicKey } from "@solana/web3.js";
import { TOKEN_PROGRAM_ID } from "@coral-xyz/anchor/dist/cjs/utils/token";
dotenv.config();

(async () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(
    process.argv.length > 2
      ? new anchor.AnchorProvider(
          provider.connection,
          new anchor.Wallet(loadKeypair(process.argv[2])),
          {}
        )
      : provider
  );

  const payer = (provider.wallet as anchor.Wallet).payer;
  console.log(`PAYER: ${payer.publicKey}`);

  let program = new anchor.Program(
    await anchor.Program.fetchIdl(
      new PublicKey("EkdhhKgVtPowVseBcuRZsS2FhAeupqLxZ54xYrQEdo7q"),
      provider
    ) as anchor.Idl,
    new PublicKey("EkdhhKgVtPowVseBcuRZsS2FhAeupqLxZ54xYrQEdo7q"),
    provider
  );
  console.log(`PROGRAM: ${program.programId}`);

  const switchboardProgram = await SwitchboardProgram.fromProvider(provider);

  const [programStatePubkey, bump] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("jarezi_arb"),
    payer.publicKey.toBuffer()],
    program.programId
  );
  console.log(`PROGRAM_STATE: ${programStatePubkey}`);

  const attestationQueueAccount = await loadDefaultQueue(switchboardProgram);
  console.log(`ATTESTATION_QUEUE: ${attestationQueueAccount.publicKey}`);

  // Create the instructions to initialize our Switchboard Function
  const [functionAccount, functionInit] =
    await attestationQueueAccount.createFunctionInstruction(payer.publicKey, {
      container: `${process.env.DOCKERHUB_ORGANIZATION ?? "switchboardlabs"}/${
        process.env.DOCKERHUB_CONTAINER_NAME ?? "jupiter-searcher"
      }`,
      version: `${process.env.DOCKERHUB_CONTAINER_VERSION ?? "latest"}`, // TODO: set to 'latest' after testing
    });
  console.log(`SWITCHBOARD_FUNCTION: ${functionAccount.publicKey}`);
  

  const signature = await program.methods
    .initialize(bump)
    .accounts({
      pda: programStatePubkey,
      jareziArber: payer.publicKey,
      jupiterProgram: new PublicKey("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"),
      systemProgram : anchor.web3.SystemProgram.programId,
      rent: anchor.web3.SYSVAR_RENT_PUBKEY,
    })
    .rpc();
  console.log(`INITIALIZE: ${signature}`);
})();