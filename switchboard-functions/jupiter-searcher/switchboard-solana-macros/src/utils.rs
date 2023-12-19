use syn::{GenericArgument, PathArguments, Type, ItemFn, TypePath};
use quote::ToTokens;
use solana_program::address_lookup_table::AddressLookupTableAccount;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::instruction::Instruction;
/// Helper function to extract the inner type from an `Arc` type.
pub fn extract_inner_type_from_arc(ty: &Type) -> Option<&Type> {
    if let Type::Path(type_path) = ty {
        // Check for either `Arc` or `std::sync::Arc`
        let segments = &type_path.path.segments;
        let is_arc = segments.last().map_or(false, |seg| seg.ident == "Arc")
            && (segments.len() == 1 || // it's just `Arc`
                (segments.len() == 3 && // it's `std::sync::Arc`
                    segments[0].ident == "std" &&
                    segments[1].ident == "sync"));

        if is_arc {
            if let PathArguments::AngleBracketed(angle_bracketed) =
                &segments.last().unwrap().arguments
            {
                if let Some(GenericArgument::Type(inner_ty)) = angle_bracketed.args.first() {
                    return Some(inner_ty);
                }
            }
        }
    }
    None
}

/// Helper function to extract the generic arguments from a `Result` type.
pub fn extract_result_args(ty: &Type) -> Option<(&Type, &Type)> {
    if let Type::Path(TypePath { path, .. }) = ty {
        let result_segment = path.segments.iter().find(|seg| seg.ident == "Result");
        if let Some(result_segment) = result_segment {
            if let PathArguments::AngleBracketed(angle_bracketed_params) = &result_segment.arguments
            {
                if angle_bracketed_params.args.len() == 2 {
                    if let (GenericArgument::Type(first_arg), GenericArgument::Type(second_arg)) = (
                        &angle_bracketed_params.args[0],
                        &angle_bracketed_params.args[1],
                    ) {
                        return Some((first_arg, second_arg));
                    }
                }
            }
        }
    }
    None
}

pub fn extract_inner_type_from_vec(ty: &Type) -> Option<&Type> {
    if let Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.iter().last() {
            if segment.ident == "Vec" {
                if let PathArguments::AngleBracketed(angle_bracketed) = &segment.arguments {
                    if let Some(GenericArgument::Type(inner_ty)) = angle_bracketed.args.first() {
                        return Some(inner_ty);
                    }
                }
            }
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct SbFunctionResult {
    pub ixs: Vec<Instruction>,
    pub commitment: Option<CommitmentConfig>,
    pub priority_fee: Option<u64>,
    pub compute_limit: Option<u32>,
    pub address_lookup_table_accounts: Option<Vec<AddressLookupTableAccount>>
}
impl syn::parse::Parse for SbFunctionResult {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let ixs = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated(input)?;
        let ixs: Vec<Instruction> = ixs.iter().map(|ix| {
            let ix: syn::LitStr = syn::parse2(ix.to_token_stream()).unwrap();
            let ix: Instruction = bincode::deserialize(bs58::decode(ix.value()).into_vec().unwrap().as_slice()).unwrap();
            ix
        }).collect();
        let mut commitment = None;
        let mut priority_fee = None;
        let mut compute_limit = None;
        let mut address_lookup_table_accounts = None;

        while !input.is_empty() {
            input.parse::<syn::Token![,]>()?;
            let attr_name: syn::Ident = input.parse()?;
            input.parse::<syn::Token![=]>()?;
            match &*attr_name.to_string() {
                "commitment" => {
                    let commitment_str: syn::LitStr = input.parse()?;
                    commitment = Some(match commitment_str.value().as_str() {
                        "confirmed" => CommitmentConfig::confirmed(),
                        "finalized" => CommitmentConfig::finalized(),
                        "processed" => CommitmentConfig::processed(),
                        _ => CommitmentConfig::confirmed()
                    });
                }
                "priority_fee" => {
                    let priority_fee_lit: syn::LitInt = input.parse()?;
                    priority_fee = Some(priority_fee_lit.base10_parse()?);
                }
                "compute_limit" => {
                    let compute_limit_lit: syn::LitInt = input.parse()?;
                    compute_limit = Some(compute_limit_lit.base10_parse()?);
                }
                "address_lookup_table_accounts" => {
                    let address_lookup_table_accounts = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated(input)?;
                }
                _ => {
                    return Err(syn::Error::new_spanned(
                        &attr_name,
                        "Expected 'commitment', 'priority_fee', 'compute_limit', or 'address_lookup_table_accounts'",
                    ));
                }
            }
        }
        Ok(SbFunctionResult {
            ixs,
            commitment,
            priority_fee,
            compute_limit,
            address_lookup_table_accounts
        })
    }
}