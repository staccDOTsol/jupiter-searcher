
mod cli_args;
use clap::Parser;
use cli_args::CliArgs;
use reqwest::header::HeaderMap;
use solana_program::address_lookup_table::{AddressLookupTableAccount};
use solana_program::hash::Hash;
use solana_sdk::compute_budget::ComputeBudgetInstruction;
mod serde_helpers;
use anyhow::{anyhow, Error};

use crate::serde_helpers::{field_as_string};   
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


#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PlatformFee {
    #[serde(with = "field_as_string")]
    pub amount: u64,
    pub fee_bps: u8,
}

#[derive(Serialize, Deserialize, Default, PartialEq, Clone, Debug)]
pub enum SwapMode {
    #[default]
    ExactIn,
    ExactOut,
}

impl FromStr for SwapMode {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "ExactIn" => Ok(Self::ExactIn),
            "ExactOut" => Ok(Self::ExactOut),
            _ => Err(anyhow!("{} is not a valid SwapMode", s)),
        }
    }
}
/// Topologically sorted DAG with additional metadata for rendering
pub type RoutePlanWithMetadata = Vec<RoutePlanStep>;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RoutePlanStep {
    pub swap_info: SwapInfo,
    pub percent: u8,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SwapInfo {
    #[serde(with = "field_as_string")]
    pub amm_key: Pubkey,
    pub label: String,
    #[serde(with = "field_as_string")]
    pub input_mint: Pubkey,
    #[serde(with = "field_as_string")]
    pub output_mint: Pubkey,
    /// An estimation of the input amount into the AMM
    #[serde(with = "field_as_string")]
    pub in_amount: u64,
    /// An estimation of the output amount into the AMM
    #[serde(with = "field_as_string")]
    pub out_amount: u64,
    #[serde(with = "field_as_string")]
    pub fee_amount: u64,
    #[serde(with = "field_as_string")]
    pub fee_mint: Pubkey,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct QuoteResponse {
    #[serde(with = "field_as_string")]
    pub input_mint: Pubkey,
    #[serde(with = "field_as_string")]
    pub in_amount: u64,
    #[serde(with = "field_as_string")]
    pub output_mint: Pubkey,
    #[serde(with = "field_as_string")]
    pub out_amount: u64,
    /// Not used by build transaction
    #[serde(with = "field_as_string")]
    pub other_amount_threshold: u64,
    pub swap_mode: SwapMode,
    pub slippage_bps: u16,
    pub platform_fee: Option<PlatformFee>,
    pub price_impact_pct: String,
    pub route_plan: RoutePlanWithMetadata,
    #[serde(default)]
    pub context_slot: u64,
    #[serde(default)]
    pub time_taken: f64,
}
impl Default for QuoteResponse {
    fn default() -> Self {
        Self {
            input_mint: Pubkey::default(),
            in_amount: 0,
            output_mint: Pubkey::default(),
            out_amount: 0,
            other_amount_threshold: 0,
            swap_mode: SwapMode::ExactIn,
            slippage_bps: 0,
            platform_fee: None,
            price_impact_pct: "0".to_string(),
            route_plan: vec![],
            context_slot: 0,
            time_taken: 0.0,
        }
    }
}
impl QuoteResponse {
    pub async fn try_from_response(response: reqwest::Response) -> Result<Self, Error> {
        Ok(response.json::<QuoteResponse>().await.unwrap_or_default())
    }
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
fn get_address_lookup_table_accounts(client: &RpcClient, keys: Vec<String>, payer: Pubkey) -> Vec<AddressLookupTableAccount> {
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
            let raw_accounts = client.get_multiple_accounts(chunk).unwrap();

            for i in 0..raw_accounts.len() {
                if raw_accounts[i].is_some() {
                    let raw_account = raw_accounts[i].as_ref().unwrap();
                    let address_lookup_table = solana_sdk::address_lookup_table::state::AddressLookupTable::deserialize(&raw_account.data).unwrap();
                    if address_lookup_table.meta.authority.unwrap() == payer {
                        let address_lookup_table_account = AddressLookupTableAccount {
                            key: chunk[i],
                            addresses: address_lookup_table.addresses.to_vec(),
                        };
                        luts.push(address_lookup_table_account);
                    }
                    
                }
            }
        }
    
    luts 
}
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
// from https://github.com/solana-labs/solana/blob/10d677a0927b2ca450b784f750477f05ff6afffe/sdk/program/src/message/versions/v0/mod.rs#L1269
fn create_tx_with_address_table_lookup(
    client: &RpcClient,
    instructions: &[Instruction],
    luts: &[AddressLookupTableAccount],
    payer: &Keypair,
) -> VersionedTransaction {

    let blockhash = client.get_latest_blockhash_with_commitment(CommitmentConfig::finalized()).unwrap().0;
    VersionedTransaction::try_new(
        VersionedMessage::V0(v0::Message::try_compile(
            &payer.pubkey(),
            instructions,
            luts,
            blockhash,
        ).unwrap()),
        &[payer],
    ).unwrap()
}

async fn doit(input: String, output: String, configs: &Vec<MarketConfigJson>
    , payer_wallet: &Arc<Keypair>,
    rpc_client: &Arc<RpcClient>, triton: &Arc<RpcClient>,
amount: u64,
mut lutties: Vec<AddressLookupTableAccount>, 
reserve: ReserveConfigJson,

)  {
        let input_mint = Pubkey::from_str(&input).unwrap();
        let _output_mint = Pubkey::from_str(&output).unwrap();
        let pda = payer_wallet.pubkey();
    
        
       // let out_ata = get_associated_token_address_with_program_id(&pda, &output_mint, &token_program_output_mint);

       let max_accounts: i32 = 40;

        let mut ixs: Vec<Instruction> = Vec::new();

    let url = "http://127.0.0.1:8080/quote?inputMint="
    .to_owned()
    +&input+"&outputMint="
    +&output+"&amount="+amount.to_string().as_str() +  "&slippageBps=10000&asLegacyTransaction=false&maxAccounts="+max_accounts.to_string().as_str();

    let quote = QuoteResponse::try_from_response(reqwest::get(url.clone()).await.unwrap()).await.unwrap_or_default();
    let input_amount = quote.clone().in_amount;
    let output_amount = quote.clone().out_amount;
    if output_amount == 0 {
        return;
    }
    let reverse_url =  "http://127.0.0.1:8080/quote?inputMint="
    .to_owned()
    +&output+"&outputMint="
    +&input+"&amount="+output_amount.to_string().as_str() +  "&slippageBps=10000&swapMode=ExactIn&asLegacyTransaction=false&maxAccounts="+max_accounts.to_string().as_str();
    
    let reverse_quote= QuoteResponse::try_from_response(reqwest::get(reverse_url.clone()).await.unwrap()).await.unwrap_or_default();
    let reverse_output_amount = reverse_quote.clone().out_amount;
    if reverse_output_amount == 0 {
        return;
    }
    
    if reverse_output_amount as f64 > input_amount as f64 * (1.0002) {
        let mut market_addr = Pubkey::default();
        println!("Arb: {} {} {} {}", input_amount, reverse_output_amount, output, input);
       
                        let config_for_reserve = configs.iter().find(|config| config.reserves.iter().any(|reserve| reserve.address == reserve.address)).unwrap();
let market_addr = Pubkey::from_str(&config_for_reserve.address).unwrap();
            //let out_ata = get_associated_token_address_with_program_id(&pda, &output_mint, &token_program_output_mint);
                let reqclient = reqwest::Client::new();
            let request_body: reqwest::Body = reqwest::Body::from(serde_json::json!({
                "quoteResponse": quote,
                "userPublicKey": pda.to_string(),
                "restrictIntermediateTokens": false,
                "useSharedAccounts": false,
                "useTokenLedger": false,
                "asLegacyTransaction": false,
                "wrapAndUnwrapSol": false
            }).to_string());
            let mut headers = HeaderMap::new();
            headers.insert("Content-Type", "application/json".parse().unwrap());
            headers.insert("Accept", "application/json".parse().unwrap());
            let swap_transaction: String = (reqclient.post("http://127.0.0.1:8080/swap-instructions")
            .body(request_body
            ).send().await.unwrap().text().await.unwrap());
            let swap_transaction: SwapInstructions = serde_json::from_str(&swap_transaction).unwrap();
            // replace instances of / with nothing
            
            let maybe_setup_ixs: Vec<Instruction>;

            if swap_transaction.setup_instructions.is_some() {
                 maybe_setup_ixs = swap_transaction.setup_instructions.clone().unwrap().iter().map(|instruction| {
                    deserialize_instruction(instruction.clone())
                }).collect::<Vec<Instruction>>();
            } else {
                 maybe_setup_ixs = vec![];
            }
            
        if !maybe_setup_ixs.is_empty() {
            let tx = create_tx_with_address_table_lookup(
                rpc_client,
                &maybe_setup_ixs,
                &[],
                payer_wallet);            
                println!("attempting xtra setup ix (whynot)");
                let signature = rpc_client
                    .send_transaction(
                        &tx,/*
                        RpcSendTransactionConfig {
                            skip_preflight: false,
                            ..RpcSendTransactionConfig::default()
                        }, */
                    )
                    ;
                    if signature.is_ok() {
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
                "restrictIntermediateTokens": false,
                "useSharedAccounts": false,
                "useTokenLedger": false,
                "asLegacyTransaction": false,
                "wrapAndUnwrapSol": false
            }).to_string());
            let swap_transaction_reverse: SwapInstructions = (reqclient.post("http://127.0.0.1:8080/swap-instructions")
            .body(request_body
            ).send().await.unwrap().json::<SwapInstructions>().await.unwrap());


            
        let token_program_input_mint = triton.get_account(&input_mint).unwrap().owner;
        

        let ata = get_associated_token_address_with_program_id(&pda, &input_mint, &token_program_input_mint);
    ixs.push(solend_sdk::instruction::flash_borrow_reserve_liquidity(
        solend_sdk::solend_mainnet::ID,
        input_amount,
        Pubkey::from_str(&reserve.liquidity_address).unwrap(),
        ata,
        Pubkey::from_str(&reserve.address).unwrap(),
        market_addr
    ));
        for ix in [deserialize_instruction(swap_transaction.swap_instruction.clone()),
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
                let mut bororw_ix_index = 1;
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
    let balance_ata = u64::from_str(&rpc_client.get_token_account_balance(&ata).unwrap().amount).unwrap();
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
        .flat_map(|ix| ix.accounts.iter().map(|acc| 
            if acc.is_writable { acc.pubkey } else { Pubkey::default() })
            .collect::<Vec<Pubkey>>()
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<Pubkey>>()
            .iter()
            .filter(|pubkey| **pubkey != Pubkey::default())
            .cloned()
            .collect::<Vec<Pubkey>>())
        .collect::<Vec<Pubkey>>().as_slice(),
        triton);
        println!("recent fees: {:?}", recent_fees);
        let needed_keys: HashSet<_> = ixs.iter()
        .flat_map(|ix| ix.accounts.iter().map(|acc| acc.pubkey.to_string()))
        .collect();
    
    let mut missing_keys = Vec::new();
    
    let add_lut = |lut_str: &str, lutties: &mut Vec<_>| {
        let lut = Pubkey::from_str(lut_str).unwrap();
        let account = rpc_client.get_account(&lut).unwrap();
        let account = solana_sdk::address_lookup_table::state::AddressLookupTable::deserialize(&account.data).unwrap();
        let lookup_table_address_account = AddressLookupTableAccount {
            key: lut,
            addresses: account.addresses.to_vec(),
        };
        lutties.push(lookup_table_address_account);
    };
    
    if let Some(lookuptable) = &config_for_reserve.lookup_table_address {
        add_lut(lookuptable, &mut lutties);
    }
    
    for lut in &swap_transaction.address_lookup_table_addresses {
        add_lut(lut, &mut lutties);
    }
    
    for lut in &swap_transaction_reverse.address_lookup_table_addresses {
        add_lut(lut, &mut lutties);
    }
    
    let lutties_public_keys: HashSet<_> = lutties.iter()
        .flat_map(|lut| lut.addresses.clone())
        .collect();
    
    for key in &needed_keys {
        if !lutties_public_keys.contains(&Pubkey::from_str(key).unwrap()) {
            missing_keys.push(key.clone());
        }
    }
    
    let mut new_lutties = create_and_or_extend_luts(
        &missing_keys.iter().map(|key| Pubkey::from_str(key).unwrap()).collect::<Vec<_>>(),
        rpc_client,
        &mut lutties,
        payer_wallet,
    ).unwrap();
    
    let mut usized_lutties: Vec<_> = lutties.iter()
        .map(|lut| {
            let num_keys = needed_keys.iter()
                .filter(|key| lut.addresses.contains(&Pubkey::from_str(key).unwrap()))
                .count();
            (lut.clone(), num_keys)
        })
        .filter(|lut| lut.1 > 0)
        .collect();
    
    usized_lutties.sort_by_key(|a| std::cmp::Reverse(a.1));
    
    let usize_rounded_half = (usized_lutties.len() as f64 / 2.0).round() as usize;
    usized_lutties.truncate(usize_rounded_half);
    
    let mut arglutties: Vec<_> = usized_lutties.into_iter().map(|lut| lut.0).collect();
    arglutties.append(&mut new_lutties);
    
    println!("lutties {:?}, needed_keys {:?}, missing_keys {:?}", arglutties.len(), needed_keys.len(), missing_keys.len());

            let priority_fee_ix = ComputeBudgetInstruction::set_compute_unit_price(
                recent_fees );
                ixs.insert(
                    0, priority_fee_ix
                );
        let tx = create_tx_with_address_table_lookup(
                rpc_client,
                &ixs,
                &arglutties,
                payer_wallet);
                println!("attempting {} <-> {} swap", input, output);
                let signature = rpc_client
                    .send_transaction_with_config(
                        &tx,
                        solana_client::rpc_config::RpcSendTransactionConfig {
                            skip_preflight: false,
                            ..solana_client::rpc_config::RpcSendTransactionConfig::default()
                        }, 
                    )
                    ;
                    if signature.is_ok() {
                        println!("https://solscan.io/tx/{}", signature.unwrap());
                    }
                    else {
                        println!("error: {:?}", signature.err().unwrap());
                    }
    }
            
                        
}
pub fn make_moar_luts(
    lutties: &mut Vec<AddressLookupTableAccount>,
    public_keys: Vec<String>,
    _triton: &RpcClient,
    rpc_client: &RpcClient,
    _payer: &Keypair,
) -> Result<Vec<AddressLookupTableAccount>, Box<dyn std::error::Error>> {
    let unique_public_keys = deduplicate_public_keys(&public_keys);
    let luts = fetch_existing_luts(lutties, rpc_client, &unique_public_keys)?;
    let luts_public_keys = get_public_keys_from_luts(&luts);
    let _remaining_public_keys = get_remaining_public_keys(&unique_public_keys, &luts_public_keys);
    save_luts_to_file(&luts.iter().map(|lut| lut.key.to_string()).collect::<Vec<String>>()).unwrap();
    Ok(luts)
}

fn deduplicate_public_keys(public_keys: &Vec<String>) -> Vec<Pubkey> {
    public_keys.iter().map(|key| Pubkey::from_str(key).unwrap()).collect::<HashSet<_>>().into_iter().collect()
}

fn fetch_existing_luts(
    lutties: &Vec<AddressLookupTableAccount>,
    _rpc_client: &RpcClient,
    needed_keys: &Vec<Pubkey>,
) -> Result<Vec<AddressLookupTableAccount>, Box<dyn std::error::Error>> {
    let lut_key_to_num_keys: HashMap<_, _> = lutties.iter().map(|lut| {
        let num_keys = lut.addresses.iter().filter(|address| needed_keys.contains(address)).count();
        (lut.key, num_keys)
    }).collect();

    let mut lut_key_to_num_keys: Vec<_> = lut_key_to_num_keys.into_iter().collect();
    lut_key_to_num_keys.sort_by_key(|a| a.1);

    let sorted_luts: Vec<_> = lut_key_to_num_keys.into_iter().filter_map(|lut| {
        lutties.iter().find(|lut2| lut.0 == lut2.key).cloned()
    }).collect();

    println!("sorted luts: {:?}", sorted_luts.len());
    Ok(sorted_luts)
}

fn get_public_keys_from_luts(luts: &Vec<AddressLookupTableAccount>) -> Vec<String> {
    luts.iter().flat_map(|lut| lut.addresses.iter().map(|address| address.to_string())).collect()
}

fn get_remaining_public_keys(
    unique_public_keys: &Vec<Pubkey>,
    luts_public_keys: &Vec<String>,
) -> Vec<Pubkey> {
    let luts_public_keys: HashSet<_> = luts_public_keys.iter().map(|key| Pubkey::from_str(key).unwrap()).collect();
    unique_public_keys.iter().filter(|key| !luts_public_keys.contains(key)).cloned().collect()
}
fn create_and_or_extend_luts(
    remaining_public_keys: &[Pubkey],
    rpc_client: &RpcClient,
    luts: &mut Vec<AddressLookupTableAccount>,
    payer: &Keypair,
) -> Result<Vec<AddressLookupTableAccount>, Box<dyn std::error::Error>> {
    let mut used_luts = Vec::new();
    let mut signature = solana_sdk::signature::Signature::default();
    let mut latest_blockhash: Hash = Hash::default();
    for pubkeys in remaining_public_keys.chunks(25) {
        let (lut, _) = find_or_create_lut(rpc_client, payer, luts, remaining_public_keys.len())?;
        let extend_ix = solana_program::address_lookup_table::instruction::extend_lookup_table(
            lut.key,
            payer.pubkey(),
            Some(payer.pubkey()),
            pubkeys.to_vec()
        );
        latest_blockhash = rpc_client.get_latest_blockhash_with_commitment(CommitmentConfig::finalized()).unwrap().0;
        signature = rpc_client
            .send_transaction(&VersionedTransaction::try_new(
                    VersionedMessage::V0(v0::Message::try_compile(
                        &payer.pubkey(),
                        &[extend_ix],
                        &[],
                        latest_blockhash,
                    )?),
                    &[payer],
                )?
            )?;

        used_luts.push(lut);
    }
    rpc_client.confirm_transaction_with_spinner(&signature, 
        &latest_blockhash, 
        CommitmentConfig::confirmed()).unwrap_or_default();
    Ok(used_luts)
}

fn find_or_create_lut(
    rpc_client:  &RpcClient,
    payer: &Keypair,
    luts: &mut Vec<AddressLookupTableAccount>,
    howmany: usize
) -> Result<(AddressLookupTableAccount, usize), Box<dyn std::error::Error>> {
    luts.shuffle(&mut rand::thread_rng());
    for (index, lut) in luts.iter().enumerate() {
        let acc = rpc_client.get_account(&lut.key).unwrap();
        let address_lookup_table = solana_sdk::address_lookup_table::state::AddressLookupTable::deserialize(&acc.data)?;
        if lut.addresses.len() < (255_usize -howmany) && address_lookup_table.meta.authority.unwrap() == payer.pubkey() {
            return Ok((lut.clone(), index));
        }
    }
    create_new_lut(rpc_client, payer).map(|lut| (lut, luts.len()))
}

fn create_new_lut(
    rpc_client: &RpcClient,
    payer: &Keypair,
) -> Result<AddressLookupTableAccount, Box<dyn std::error::Error>> {
    let recent_slot = rpc_client
        .get_slot_with_commitment(CommitmentConfig::confirmed())?
        - 50;
    let (create_ix, table_pk) =
        solana_program::address_lookup_table::instruction::create_lookup_table(
            payer.pubkey(),
            payer.pubkey(),
            recent_slot,
        );
    let latest_blockhash = rpc_client.get_latest_blockhash_with_commitment(CommitmentConfig::finalized()).unwrap().0;
    
    rpc_client
        .send_and_confirm_transaction_with_spinner(&VersionedTransaction::try_new(
                VersionedMessage::V0(v0::Message::try_compile(
                    &payer.pubkey(),
                    &[create_ix],
                    &[],
                    latest_blockhash,
                )?),
                &[payer],
            )?
        )?;

    let lut = AddressLookupTableAccount {
        key: table_pk,
        addresses: vec![],
    };

    let file = std::fs::read("./src/luts.json")?;
    let string = String::from_utf8(file)?;
    let mut lutties: Vec<String> = serde_json::from_str(&string)?;
    lutties.sort();
    lutties.dedup();
    lutties.push(lut.key.to_string());
    save_luts_to_file(&lutties)?;
    
    Ok(lut)
}

fn save_luts_to_file(lutties: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let lutties = serde_json::to_string(lutties)?;
    std::fs::write("./src/luts.json", lutties)?;

    Ok(())
}
pub fn calculate_recent_fee(
    write_locked_accounts: &[Pubkey],
    rpc_client: &RpcClient
) -> u64 {
    println!("calculating recent fee");
    println!("write locked accounts: {:?}", write_locked_accounts.len());
    // do in chunks of 100 
    let write_locked_accounts = write_locked_accounts.to_vec();
    let chunks = write_locked_accounts.chunks(100);
    for chunk in chunks {
            let account_infos = rpc_client.get_multiple_accounts_with_commitment(
                chunk,
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
            if fee > 138 {
                return fee;
            }
        }
    138
}
async fn get_top_tokens() -> Vec<String> {
    let url = "https://cache.jup.ag/top-tokens";
    
    serde_json::from_str::<Vec<String>>(&reqwest::get(url).await.unwrap().text().await.unwrap()).unwrap()
}

fn get_configs() -> Vec<MarketConfigJson> {
   
    let file = std::fs::read("./src/configs.json").unwrap();
    let string = String::from_utf8(file).unwrap();
    let configs: Vec<MarketConfigJson> = serde_json::from_str(&string).unwrap();
    configs
}
const MAX_THREADS: usize = 126;

#[tokio::main(worker_threads = 126)]
async fn main() {

    let file = std::fs::read("./src/luts.json").unwrap();
    let string = String::from_utf8(file).unwrap();
        let mut lutties: Vec<String> = serde_json::from_str(&string).unwrap();
        //println !("lutties: {:?}", lutties.len());
// dedupe
        lutties.sort();
        lutties.dedup();
        //println !("lutties: {:?}", lutties.len());
    let args = CliArgs::parse();

    let configs = get_configs();
    
    let client = Arc::new(RpcClient::new_with_commitment(&args.url, CommitmentConfig::confirmed()));
    let triton = Arc::new(
        RpcClient::new_with_commitment("https://jarrett-solana-7ba9.mainnet.rpcpool.com/8d890735-edf2-4a75-af84-92f7c9e31718", CommitmentConfig::confirmed()));

        let mut luts = Vec::new();
        let mut lutties = lutties. 
        iter()
        .map(|x| Pubkey::from_str(x).unwrap())
        .collect::<Vec<Pubkey>>();
        lutties.sort();
        lutties.reverse();
        let lutties = lutties.clone();
        luts.extend(lutties
            .iter()
            .map(|addy| addy.to_string())
            .collect::<Vec<String>>());
        let payer_wallet = Arc::new(read_keypair_file(&*args.payer_keypair).unwrap());
    let lutties = get_address_lookup_table_accounts(&triton, luts.clone(), payer_wallet.pubkey());
    println!("lutties: {:?}", lutties.len());

    let slice = get_top_tokens().await.to_vec();
    
    let mut values = HashMap::new();
    let mut input_mints = Vec::new();

        for reserve in configs.iter().flat_map(|config| config.reserves.iter()) {
                let liquidity_address = Pubkey::from_str(&reserve.liquidity_address).unwrap();
                let balance_ata = u64::from_str(&client.get_token_account_balance(&liquidity_address).unwrap().amount).unwrap();
                let decimals = reserve.liquidity_token.decimals;
                let balance_ata = balance_ata as f64 / 10f64.powi(decimals as i32);
                let url = "http://127.0.0.1:8080/quote?inputMint="
                .to_owned()
                +USDC+"&outputMint="
                +&reserve.liquidity_token.mint.clone()+"&amount=1000000";
        
                let quote = QuoteResponse::try_from_response(reqwest::get(url.clone()).await.unwrap()).await.unwrap_or_default();

                let value = quote.out_amount as u128 * balance_ata as u128;
                println!("reserve token mint{}: value: {}", reserve.liquidity_token.mint, value);
                if value > 10_000 {
                input_mints.push(reserve.liquidity_token.mint.clone());

                let value = quote.out_amount as f64;
                if value != 0.0 {
                    values.insert(reserve.address.clone(), (value, reserve.liquidity_token.mint.clone()));
                    println!("$1.00 of {}: {}", reserve.liquidity_token.mint.clone(), value);
                }
            }
        }

    input_mints.shuffle(&mut rand::thread_rng());
    
// write to file
    loop {
        let mut tasks = Vec::new();
        for _i in 0..MAX_THREADS {
            let random_mint_rng = rand::thread_rng().gen_range(0..values.keys().collect::<Vec<&String>>().len());
            let mint = values.values().collect::<Vec<&(f64, String)>>()[random_mint_rng].1.clone();
            let reserve = values.keys().collect::<Vec<&String>>()[random_mint_rng].clone();
            let configs = configs.clone();
            let payer_wallet = payer_wallet.clone();
            let client = client.clone();
            let triton = triton.clone();
            let handle = tokio::runtime::Handle::current();
            let mut slice = slice.clone();

            let rng = &mut rand::thread_rng();
            let random_number_1e9_to_1e12 = rand::thread_rng().gen_range(10..1000);

            let random_number_1e9_to_1e12 = random_number_1e9_to_1e12 as u64;

            let amount = (random_number_1e9_to_1e12 as f64 * values.values().collect::<Vec<&(f64, String)>>()[random_mint_rng].0) as u64;
            slice.shuffle(rng);
            let rng_slice = rand::thread_rng().gen_range(0..slice.len());
            let lutties = lutties.clone();
            let task = handle.spawn(async move  {
                
                let reserve: ReserveConfigJson = configs.iter().flat_map(|config| config.reserves.iter()).find(|r| r.address == *reserve).unwrap().clone();
                // get the quote
                doit(mint.to_string(), slice[rng_slice as usize].to_string(), &configs, &payer_wallet, &client, &triton, amount,  lutties.clone(), reserve.clone() ).await
            });
        
            tasks.push(task);
        }
        
        let _results = futures::future::join_all(tasks).await;
    }


    
}