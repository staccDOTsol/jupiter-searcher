
mod cli_args;
use clap::Parser;
use cli_args::CliArgs;
use reqwest::header::HeaderMap;
use solana_program::program_pack::Pack;
use solana_program::address_lookup_table::{AddressLookupTableAccount};
use switchboard_solana::{Transaction};
use std::collections::{HashMap, HashSet};
use std::{str::FromStr};
use rand::{seq::SliceRandom};
use rand::Rng;
use solana_client::rpc_client::RpcClient;

use solana_program::message::{VersionedMessage, v0};
use serde::{Serialize, Deserialize};

use solana_sdk::{pubkey::Pubkey,
    instruction::Instruction,
    signer::{keypair::read_keypair_file, Signer, keypair::Keypair},
    transaction::{ VersionedTransaction}, commitment_config::CommitmentConfig, account::Account,
};


use std::{sync::Arc};
use spl_associated_token_account::{get_associated_token_address_with_program_id};

// create type of hashmap!{String => Instruction}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HashedAccount{

    pub is_signer: bool,
    pub is_writable: bool,
    pub pubkey: String,
}
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HashedIx{
    pub program_id: String,
    pub accounts: Vec<HashedAccount>,
    pub data: String
}
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SwapInstructions{
    //"swapInstruction\":{\"programId\":\"JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4\",\"accounts\":[{\"
    pub token_ledger_instruction: Option<HashedIx>,
    pub setup_instructions:Option<Vec<HashedIx>>,
    pub swap_instruction: HashedIx,
    pub cleanup_instruction: Option<HashedIx>,
    pub address_lookup_table_addresses: Vec<String>
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LiquidityTokenJson {
    pub mint: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub logo: String,
    pub volume24h: String
}
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReserveConfigJson {
    pub liquidity_token: LiquidityTokenJson,
    pub pyth_oracle: String,
    pub switchboard_oracle: String,
    pub address: String,
    pub collateral_mint_address: String,
    pub collateral_supply_address: String,
    pub liquidity_address: String,
    pub liquidity_fee_receiver_address: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MarketConfigJson {
    pub name: String,
    pub is_primary: bool,
    pub description: String,
    pub creator: String,
    pub address: String,
    pub hidden: bool,
    pub is_permissionless: bool,
    pub authority_address: String,
    pub owner: String,
    pub reserves: Vec<ReserveConfigJson>,
    pub lookup_table_address: Option<String>
}
fn deserialize_instruction (instruction: HashedIx) -> Instruction {
    let mut accounts = instruction.accounts.clone();
    for i in 0..accounts.len() {
        accounts[i].pubkey = Pubkey::from_str(&accounts[i].pubkey).unwrap().to_string();
    }
    let data = base64::decode(&instruction.data).unwrap();
    let program_id = Pubkey::from_str(&instruction.program_id).unwrap();
    let instruction = Instruction {
        program_id,
        accounts: accounts.iter().map(|account| {
            solana_sdk::instruction::AccountMeta {
                pubkey: Pubkey::from_str(&account.pubkey).unwrap(),
                is_signer: account.is_signer,
                is_writable: account.is_writable,
            }
        }).collect::<Vec<solana_sdk::instruction::AccountMeta>>(),
        data,
    };
    instruction
}
fn get_address_lookup_table_accounts(client: &RpcClient, keys: Vec<String>) -> Vec<AddressLookupTableAccount> {
    let keys = &keys.iter().
    map(|key| {
        Pubkey::from_str(key).unwrap()
    })
    .collect::<Vec<Pubkey>>();
    let mut luts: Vec<AddressLookupTableAccount> = Vec::new();
    // do in chunks of 100
    let  keys = keys.clone();
    let  chunks= keys.chunks(100);
    
    for chunk in chunks {
            let raw_accounts = client.get_multiple_accounts(&chunk).unwrap();

            for i in 0..raw_accounts.len() {
                if raw_accounts[i].is_some() {
                    let raw_account = raw_accounts[i].as_ref().unwrap();
                    let address_lookup_table = solana_sdk::address_lookup_table::state::AddressLookupTable::deserialize(&raw_account.data).unwrap();
                    let address_lookup_table_account = AddressLookupTableAccount {
                        key: chunk[i],
                        addresses: address_lookup_table.addresses.to_vec(),
                    };
                    luts.push(address_lookup_table_account);
                }
            }
        }
    
    luts 
}

// from https://github.com/solana-labs/solana/blob/10d677a0927b2ca450b784f750477f05ff6afffe/sdk/program/src/message/versions/v0/mod.rs#L209
fn create_tx_with_address_table_lookup(
    client: &RpcClient,
    instructions: &[Instruction],
    luts: &[AddressLookupTableAccount],
    payer: &Keypair,
) -> VersionedTransaction {

    let blockhash = client.get_latest_blockhash().unwrap();
    VersionedTransaction::try_new(
        VersionedMessage::V0(v0::Message::try_compile(
            &payer.pubkey(),
            instructions,
            &luts,
            blockhash,
        ).unwrap()),
        &[payer],
    ).unwrap()
}

async fn doit(input: String, output: String, configs: &Vec<MarketConfigJson>
    , payer_wallet: &Arc<Keypair>,
    rpc_client: &Arc<RpcClient>, triton: &Arc<RpcClient>,
amount: u64,
mut lutties: Vec<AddressLookupTableAccount>

)  {
        let input_mint = Pubkey::from_str(&input).unwrap();
        let output_mint = Pubkey::from_str(&output).unwrap();
        let pda = payer_wallet.pubkey();
        let decimals_input = configs.
        into_iter()
        .map(|config| {
            for reserve in config.reserves.clone().into_iter() {
                if reserve.liquidity_token.mint == input {
                    return reserve.liquidity_token.decimals as u32;
                }
            }
            0 as u32
        })
        .collect::<Vec<u32>>()[0];
    
        

       // let out_ata = get_associated_token_address_with_program_id(&pda, &output_mint, &token_program_output_mint);

        let amount = amount * 10u64.pow(decimals_input);
       

        let mut ixs: Vec<Instruction> = Vec::new();
    let url = "http://127.0.0.1:8081/quote?slippageBps=10000&asLegacyTransaction=true&inputMint="
    .to_owned()
    +&input+"&outputMint="
    +&output+"&amount=" + &amount.to_string();
    let quote= (&reqwest::get(url.clone()).await.unwrap().text().await.unwrap());
    let quote = serde_json::from_str::<serde_json::Value>(&quote).unwrap();
    let input_amount = quote["inAmount"].to_string();
    let output_amount: String = quote["outAmount"].to_string();
    let input_amount = input_amount[1..input_amount.len()-1].parse::<u64>().unwrap_or_default();
    let output_amount = (output_amount[1..output_amount.len()-1].parse::<u64>().unwrap_or_default());
    let reverse_url = "http://127.0.0.1:8081/quote?asLegacyTransaction=true&slippageBps=10000&inputMint=".to_owned()+&output+"&outputMint="+&input+"&amount=" + output_amount.to_string().as_str();
    let reverse_quote=  (&reqwest::get(reverse_url.clone()).await.unwrap().text().await.unwrap());
    let reverse_quote = serde_json::from_str::<serde_json::Value>(&reverse_quote).unwrap();
    let reverse_output_amount:String = reverse_quote["outAmount"].to_string();
    let reverse_output_amount = reverse_output_amount[1..reverse_output_amount.len()-1].parse::<u64>().unwrap_or_default();
    let reverse_input_amount:String = reverse_quote["inAmount"].to_string();
    let reverse_input_amount = reverse_input_amount[1..reverse_input_amount.len()-1].parse::<u64>().unwrap_or_default();
    if reverse_output_amount as f64 > input_amount as f64 * 1.0 {
        let token_program_input_mint = triton.get_account(&input_mint).unwrap().owner;
        

        let ata = get_associated_token_address_with_program_id(&pda, &input_mint, &token_program_input_mint);
        println!("input mint: {:?}", input_mint);
        println!("output mint: {:?}", output_mint);
        println!("token program input mint: {:?}", token_program_input_mint);
        let mut market_addr = Pubkey::default();
        println!("Arb: {} {} {} {}", input_amount, reverse_output_amount, output, input);
        let mut market_addrs = HashMap::new();
        let mut reserves_maybe = 
        configs.iter()
            .map(|config| {
                for reserve in config.reserves.iter() {
                    if reserve.liquidity_token.mint == input {
                        market_addr = Pubkey::from_str(&config.address).unwrap();
                        market_addrs.insert(reserve.clone().address, (config.lookup_table_address.clone(), market_addr.clone()));
                        return Some(reserve.clone());
                    }
                }
                None
            })
            .collect::<Vec<Option<ReserveConfigJson>>>();
        reserves_maybe.shuffle(&mut rand::thread_rng());
        let mut done = false;
        for reserve in reserves_maybe {
            if done {
                break;
            }
            if reserve.is_none() {
                continue;
            }
            else {
                done = true;
            }
            let reserve = reserve.unwrap();
            market_addr = market_addrs[reserve.address.as_str()].1.clone();

            //let out_ata = get_associated_token_address_with_program_id(&pda, &output_mint, &token_program_output_mint);
                let reqclient = reqwest::Client::new();
            let request_body: reqwest::Body = reqwest::Body::from(serde_json::json!({
                "quoteResponse": quote,
                "userPublicKey": pda.to_string(),
                "restrictIntermediateTokens": true,
                "useSharedAccounts": true,
                "useTokenLedger": false,
                "asLegacyTransaction": true
            }).to_string());
            let mut headers = HeaderMap::new();
            headers.insert("Content-Type", "application/json".parse().unwrap());
            headers.insert("Accept", "application/json".parse().unwrap());
            let swap_transaction = reqclient.post("http://127.0.0.1:8081/swap-instructions")
            .body(request_body
            ).
            headers(headers
            ).

            send().await.unwrap().text().await.unwrap();
            // replace instances of / with nothing
            let swap_transaction = swap_transaction.replace("\\", "");
            let swap_transaction = serde_json::from_str::<SwapInstructions>(&swap_transaction).unwrap();
            
            let maybe_setup_ixs: Vec<Instruction>;

            if swap_transaction.setup_instructions.is_some() {
                 maybe_setup_ixs = swap_transaction.setup_instructions.clone().unwrap().iter().map(|instruction| {
                    deserialize_instruction(instruction.clone())
                }).collect::<Vec<Instruction>>();
            } else {
                 maybe_setup_ixs = vec![];
            }
            
        if maybe_setup_ixs.len() > 0 {
            let tx = create_tx_with_address_table_lookup(
                &rpc_client,
                &maybe_setup_ixs,
                &[],
                &payer_wallet);            
                let signature = rpc_client
                    .send_transaction(
                        &tx,/*
                        RpcSendTransactionConfig {
                            skip_preflight: false,
                            ..RpcSendTransactionConfig::default()
                        }, */
                    )
                    ;
                    if !signature.is_err() {
                        //println!("winner winner chickum dinner: {:?}", signature.unwrap());
                    }
                    else {
                        println!("error: {:?}", signature.err().unwrap());
                    }
        }/*

        if maybe_cleanup_ix.is_some() {
                let maybe_cleanup_ix = deserialize_instruction(maybe_cleanup_ix.unwrap());
            if maybe_cleanup_ix.accounts.len() > 0 {
                swap_transaction_ixs.push(maybe_cleanup_ix);
            } 
        }
    */
            // reverse lol

            let request_body: reqwest::Body = reqwest::Body::from(serde_json::json!({
                "quoteResponse": reverse_quote,
                "userPublicKey": pda.to_string(),
                "restrictIntermediateTokens": true,
                "useSharedAccounts": true,
                "useTokenLedger": false,
                "asLegacyTransaction": true
            }).to_string());
            let swap_transaction_reverse = serde_json::from_str::<SwapInstructions>(&reqclient.post("http://127.0.0.1:8081/swap-instructions")
            .body(request_body
            ).send().await.unwrap().text().await.unwrap()).unwrap();


            
        println!("ata {:?}", ata);

    ixs.push(solend_sdk::instruction::flash_borrow_reserve_liquidity(
        solend_sdk::solend_mainnet::ID,
        input_amount,
        Pubkey::from_str(&reserve.liquidity_address).unwrap(),
        ata,
        Pubkey::from_str(&reserve.address).unwrap(),
        market_addr
    ));
        for ix in vec![deserialize_instruction(swap_transaction.swap_instruction.clone()),
        deserialize_instruction(swap_transaction_reverse.swap_instruction.clone())] {


        ixs.push(ix);

    }
    /*
                *token_lending_info.key,
                liquidity_amount,
                borrow_instruction_index,
                *source_liquidity_info.key,
                *destination_liquidity_info.key,
                *reserve_liquidity_fee_receiver_info.key,
                *host_fee_receiver_info.key,
                *reserve_info.key,
                *lending_market_info.key,
                *user_transfer_authority_info.key, */
                let mut bororw_ix_index = 0;
                for ix in &ixs {
                    if ix.program_id != solend_sdk::solend_mainnet::ID {

                        bororw_ix_index += 1;
                    }
                    else {
                        break;
                    }
                    
                }

    ixs.push(solend_sdk::instruction::flash_repay_reserve_liquidity(
        solend_sdk::solend_mainnet::ID,
        input_amount,
        bororw_ix_index,
        ata,
        Pubkey::from_str(&reserve.liquidity_address).unwrap(),
        Pubkey::from_str(&reserve.liquidity_fee_receiver_address).unwrap(),
        ata,
        Pubkey::from_str(&reserve.address).unwrap(),
        market_addr,
        pda
    ));
    let balance_ata = rpc_client.get_account(&ata).unwrap();
    let balance_ata = spl_token::state::Account::unpack(&balance_ata.data).unwrap().amount;
    println!("balance ata: {:?}", balance_ata);
            ixs.push(spl_token::instruction::transfer(
                &spl_token::id(),
                &ata,
                &ata,
                &pda,
                &[
                ],
                balance_ata as u64,
            ).unwrap());

                     
    let recent_fees = calculate_recent_fee(ixs.
        iter()
        .map(|ix| ix.accounts.iter().map(|acc| 
            if acc.is_writable { acc.pubkey } else { Pubkey::default() })
            .collect::<Vec<Pubkey>>()
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<Pubkey>>()
            .iter()
            .filter(|pubkey| **pubkey != Pubkey::default())
            .cloned()
            .collect::<Vec<Pubkey>>())
        .flatten()
        .collect::<Vec<Pubkey>>().as_slice(),
        &triton);
        println!("recent fees: {:?}", recent_fees);

            let mut  needed_keys = ixs.
            iter()
            .map(|ix| ix.accounts.iter().map(|acc| 
                acc.pubkey.to_string()
                )
                .collect::<Vec<String>>())
            .flatten()
            .collect::<Vec<String>>();

            // find the top 4 luts with the most needed keys
            let mut usized_lutties = lutties.
            iter()
            .map(|lut| {
                let mut num_keys = 0;
                for key in &needed_keys {
                    if lut.addresses.contains(&Pubkey::from_str(key).unwrap()) {
                        num_keys += 1;
                    }
                }
                (lut.clone(), num_keys)
            })
            .collect::<Vec<(AddressLookupTableAccount, usize)>>();
        usized_lutties.sort_by(|a, b| a.1.cmp(&b.1));
        usized_lutties.reverse();
        usized_lutties.truncate(4);
        lutties = usized_lutties.iter().map(|lut| lut.0.clone()).collect::<Vec<AddressLookupTableAccount>>();

        println!("lutties: {:?}", lutties.len());


                
            if market_addrs[reserve.address.as_str()].0.is_some() {
                let lookuptable = market_addrs[reserve.address.as_str()].0.clone().unwrap();
                let lookuptable = Pubkey::from_str(&lookuptable).unwrap();
                let account = rpc_client.get_account(&lookuptable).unwrap();
                let account = AddressLookupTable::deserialize(&account.data).unwrap();
                let lookup_table_address_account = AddressLookupTableAccount {
                    key: lookuptable,
                    addresses: account.addresses.to_vec(),
                };
                lutties.push(lookup_table_address_account);
            }
            
            if swap_transaction.address_lookup_table_addresses.len() > 0 {
                for lut in swap_transaction.address_lookup_table_addresses.clone() {
                    let lut = Pubkey::from_str(&lut).unwrap();
                    let account = rpc_client.get_account(&lut).unwrap();
                    let account = AddressLookupTable::deserialize(&account.data).unwrap();
                    let lookup_table_address_account = AddressLookupTableAccount {
                        key: lut,
                        addresses: account.addresses.to_vec(),
                    };
                    lutties.push(lookup_table_address_account);
                }
            }
            if swap_transaction_reverse.address_lookup_table_addresses.len() > 0 {
                for lut in swap_transaction_reverse.address_lookup_table_addresses.clone() {
                    let lut = Pubkey::from_str(&lut).unwrap();
                    let account = rpc_client.get_account(&lut).unwrap();
                    let account = AddressLookupTable::deserialize(&account.data).unwrap();
                    let lookup_table_address_account = AddressLookupTableAccount {
                        key: lut,
                        addresses: account.addresses.to_vec(),
                    };
                    lutties.push(lookup_table_address_account);
                }
            }
            
            
        let tx = create_tx_with_address_table_lookup(
                &rpc_client,
                &ixs,
                &lutties,
                &payer_wallet);
                
                let signature = rpc_client
                    .send_transaction_with_config(
                        &tx,
                        solana_client::rpc_config::RpcSendTransactionConfig {
                            skip_preflight: false,
                            ..solana_client::rpc_config::RpcSendTransactionConfig::default()
                        }, 
                    )
                    ;
                    if !signature.is_err() {
                    }
                    else {
                        println!("error: {:?}", signature.err().unwrap());
                    }
    }
            
        }
                        
}
pub fn make_moar_luts(
    lutties: &mut Vec<AddressLookupTableAccount>,
    public_keys: Vec<String>,
    triton: &RpcClient,
    rpc_client: &RpcClient,
    payer: &Keypair,
) -> Result<Vec<AddressLookupTableAccount>, Box<dyn std::error::Error>> {
    let unique_public_keys = deduplicate_public_keys(&public_keys);
    let mut luts = fetch_existing_luts(lutties, rpc_client, &unique_public_keys)?;
    let luts_public_keys = get_public_keys_from_luts(&luts);
    let remaining_public_keys = get_remaining_public_keys(&unique_public_keys, &luts_public_keys);
    let used_luts = luts;
    save_luts_to_file(&used_luts.
        iter()
        .map(|lut| lut.key.to_string())
        .collect::<Vec<String>>()).unwrap();
    Ok(used_luts)
}

fn deduplicate_public_keys(public_keys: &Vec<String>) -> Vec<Pubkey> {
    let mut unique_keys = HashSet::new();
    for key in public_keys {
        let pubkey = Pubkey::from_str(key).unwrap();
        unique_keys.insert(pubkey);
    }
    unique_keys.into_iter().collect()
}

fn fetch_existing_luts(
    lutties: &Vec<AddressLookupTableAccount>,
    rpc_client: &RpcClient,
    needed_keys: &Vec<Pubkey>,
) -> Result<Vec<AddressLookupTableAccount>, Box<dyn std::error::Error>> {
   
    // iterate thru luts. 
    // count how many keys we have in each lut - create a HashMap of lut key to number of keys

    let mut lut_key_to_num_keys = HashMap::new();
    for lut in lutties {
        // count how many public_keys are in lut.addresses
        let mut num_keys = 0;
        for address in &lut.addresses {
            if needed_keys.contains(address) {
                num_keys += 1;
            }
        }
        lut_key_to_num_keys.insert(lut.key, num_keys);
    }

    // sort lut_key_to_num_keys by num_keys
    let mut lut_key_to_num_keys = lut_key_to_num_keys
        .into_iter()
        .collect::<Vec<(Pubkey, usize)>>();
    lut_key_to_num_keys.sort_by(|a, b| a.1.cmp(&b.1));

    // create a new vector of luts sorted by num_keys
    let mut sorted_luts = Vec::new();
    for lut in lut_key_to_num_keys {
        for lut2 in lutties {
            if lut.0 == lut2.key {
                sorted_luts.push(lut2.clone());
            }
        }
    }
    sorted_luts.truncate(4);
    println!("sorted luts: {:?}", sorted_luts.len());
    Ok(sorted_luts)

}

fn get_public_keys_from_luts(luts: &Vec<AddressLookupTableAccount>) -> Vec<String> {
    let mut public_keys = Vec::new();
    for lut in luts {
        for address in &lut.addresses {
            public_keys.push(address.to_string());
        }
    }
    public_keys
}

fn get_remaining_public_keys(
    unique_public_keys: &Vec<Pubkey>,
    luts_public_keys: &Vec<String>,
) -> Vec<Pubkey> {
    let luts_public_keys: HashSet<Pubkey> = luts_public_keys
    .iter()
    .map(|key| Pubkey::from_str(key).unwrap())
    .collect();

unique_public_keys
    .iter()
    .filter(|key| !luts_public_keys.contains(key))
    .cloned()
    .collect()}

fn create_or_extend_luts(
    remaining_public_keys: &Vec<Pubkey>,
    rpc_client: &RpcClient,
    luts: &mut Vec<AddressLookupTableAccount>,
    payer: &Keypair,
) -> Result<Vec<Pubkey>, Box<dyn std::error::Error>> {
    let mut used_luts = Vec::new();

    for pubkey in remaining_public_keys {
        let (mut lut, index) = find_or_create_lut(pubkey, luts)?;

        if lut.addresses.len() < 255 {
            lut.addresses.push(*pubkey);
            used_luts.push(lut.key);
            luts[index] = lut;
        } else {
            let new_lut = create_new_lut( rpc_client, payer)?;
            used_luts.push(new_lut.key);
            luts.push(new_lut);
        }
    }

    Ok(used_luts)
}
fn find_or_create_lut(
    pubkey: &Pubkey,
    luts: &mut Vec<AddressLookupTableAccount>,
) -> Result<(AddressLookupTableAccount, usize), Box<dyn std::error::Error>> {
    for (index, lut) in luts.iter().enumerate() {
        if lut.addresses.len() < 255 {
            return Ok((lut.clone(), index));
        }
    }

    Err("No suitable LUT found".into())
}
use solana_sdk::address_lookup_table::state::AddressLookupTable;

fn create_new_lut(
    rpc_client: &RpcClient,
    payer: &Keypair,
) -> Result<AddressLookupTableAccount, Box<dyn std::error::Error>> {
    // Create a new AddressLookupTable
    let recent_slot = rpc_client
    .get_slot_with_commitment(CommitmentConfig::finalized())
    .unwrap();
    let (create_ix, table_pk) =
        solana_program::address_lookup_table::instruction::create_lookup_table(
            payer.pubkey(),
            payer.pubkey(),
            recent_slot,
        );
    let recent_blockhash = rpc_client.get_latest_blockhash().unwrap();  
    let mut transaction = Transaction::new_with_payer(&[create_ix], Some(&payer.pubkey()));
    transaction.sign(&[payer], recent_blockhash);
    rpc_client.send_and_confirm_transaction(&transaction)?;

    let lut = AddressLookupTableAccount {
        key: table_pk,
        addresses: vec![],
    };

    Ok(lut)

}
use std::fs;

fn save_luts_to_file(lutties: &Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let data = lutties.join("\n");
    fs::write("./src/luts.txt", data)?;
    Ok(())
}
pub fn calculate_recent_fee(
    write_locked_accounts: &[Pubkey],
    rpc_client: &RpcClient
) -> u64 {
    println!("calculating recent fee");
    println!("write locked accounts: {:?}", write_locked_accounts.len());
    // do in chunks of 100 
    let mut write_locked_accounts = write_locked_accounts.to_vec();
    let mut chunks = write_locked_accounts.chunks(100);
    for chunk in chunks {
            let account_infos = rpc_client.get_multiple_accounts_with_commitment(
                &chunk,
                CommitmentConfig::confirmed()
            ).unwrap().value;
            let mut index = 0;
            let write_locked_accounts = &account_infos
            .into_iter()
            .map(|account: Option<Account>| {
                index += 1;
                if account.is_some() {
                    write_locked_accounts[index-1]
                }
                else {
                    Pubkey::default()
                }
            })
            .collect::<Vec<Pubkey>>()
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<Pubkey>>()
            .iter()
            .filter(|pubkey| **pubkey != Pubkey::default())
            .cloned()
            .collect::<Vec<Pubkey>>();
            println!("write locked accounts that were resolved on this cluster: {:?}", write_locked_accounts.len());
            let recent_fees = rpc_client.get_recent_prioritization_fees(
                write_locked_accounts
            ).unwrap_or_default();
            let fee = recent_fees
            .iter()
            .map(|fee| fee.prioritization_fee)
            .filter(|fee| *fee != 0)
            .sum::<u64>()
            .checked_div(recent_fees.len() as u64)
            .unwrap_or(138 * write_locked_accounts.len() as u64)
            .checked_div(write_locked_accounts.len() as u64)
            .unwrap_or(138);
            if fee != 138 {
                return fee;
            }
        }
    138
}
async fn get_top_tokens() -> Vec<String> {
    let url = "https://cache.jup.ag/top-tokens";
    let top_tokens = serde_json::from_str::<Vec<String>>(&reqwest::get(url).await.unwrap().text().await.unwrap()).unwrap();
    return top_tokens;
}

fn get_configs() -> Vec<MarketConfigJson> {
   
    let file = std::fs::read("./src/configs.json").unwrap();
    let string = String::from_utf8(file).unwrap();
    let configs: Vec<MarketConfigJson> = serde_json::from_str(&string).unwrap();
    return configs;
}
const MAX_THREADS: usize = 124;

#[tokio::main(worker_threads = 124)]
async fn main() {

    let file = std::fs::read("./src/luts.json").unwrap();
    let string = String::from_utf8(file).unwrap();
        let mut lutties: Vec<String> = serde_json::from_str(&string).unwrap();
        println !("lutties: {:?}", lutties.len());
// dedupe
        lutties.sort();
        lutties.dedup();
        println !("lutties: {:?}", lutties.len());
    let args = CliArgs::parse();

    let configs = get_configs();
    
    let client = Arc::new(RpcClient::new(&args.url));
    let triton = Arc::new(
        RpcClient::new("https://jarrett-solana-7ba9.mainnet.rpcpool.com/8d890735-edf2-4a75-af84-92f7c9e31718"));

        let mut luts = Vec::new();
        let mut lutties = lutties. 
        iter()
        .map(|x| Pubkey::from_str(x).unwrap())
        .collect::<Vec<Pubkey>>();
        lutties.sort();
        lutties.reverse();
        let lutties = lutties.clone();
        luts.extend((
            &lutties)
            .iter()
            .map(|addy| addy.to_string())
            .collect::<Vec<String>>());
    let mut lutties = get_address_lookup_table_accounts(&triton, luts.clone());
    println!("lutties: {:?}", lutties.len());
    let payer_wallet = Arc::new(read_keypair_file(&*args.payer_keypair).unwrap());

    let slice = get_top_tokens().await[0..100].to_vec();
    
    let mut input_mints: Vec<String> = configs.iter().map(|config| {

        config.reserves
        .iter()
        .map(|reserve| {
            reserve.liquidity_token.mint.clone()
        })
    })
    .flatten()
    .collect::<Vec<String>>();
    input_mints.shuffle(&mut rand::thread_rng());
    input_mints.dedup();
    
// write to file
    let mut input_mints = input_mints.clone();
    loop {
        let mut tasks = Vec::new();
        for i in 0..MAX_THREADS {
            let random_mint_rng = rand::thread_rng().gen_range(0..input_mints.len());
            let mint = input_mints[random_mint_rng].clone();
            let configs = configs.clone();
            let payer_wallet = payer_wallet.clone();
            let client = client.clone();
            let triton = triton.clone();
            let handle = tokio::runtime::Handle::current();
            let mut slice = slice.clone();

            let rng = &mut rand::thread_rng();
            let random_number_1e9_to_1e12 = rand::thread_rng().gen_range(1e0..1e3);

            let random_number_1e9_to_1e12 = random_number_1e9_to_1e12 as u64;
            slice.shuffle(rng);
            let rng_slice = rand::thread_rng().gen_range(0..slice.len());
            let mut lutties = lutties.clone();
            let task = handle.spawn(async move  {
                
            
                // get the quote
                doit(mint.to_string(), slice[rng_slice as usize].to_string(), &configs, &payer_wallet, &client, &triton, random_number_1e9_to_1e12,  lutties.clone() ).await
            });
        
            tasks.push(task);
        }
        
        let results = futures::future::join_all(tasks).await;
    }


    
}