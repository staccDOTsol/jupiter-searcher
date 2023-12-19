use syn::parse::{Parse, ParseStream, Result as ParseResult};
use syn::punctuated::Punctuated;
use syn::{ExprAssign, Token};
use solana_sdk::commitment_config::CommitmentConfig;
use solana_program::address_lookup_table::AddressLookupTableAccount;

#[derive(Default, Debug, Clone)]
pub enum SolanaParamsEncoding {
    #[default]
    Bytes,
    Borsh,
    Serde,
}
impl Parse for SolanaParamsEncoding {
    fn parse(input: ParseStream) -> ParseResult<Self> {
        let ident: syn::Ident = input.parse()?;

        match ident.to_string().as_str() {
            "Bytes" => Ok(SolanaParamsEncoding::Bytes),
            "Borsh" => Ok(SolanaParamsEncoding::Borsh),
            "Serde" => Ok(SolanaParamsEncoding::Serde),
            _ => Err(syn::Error::new_spanned(
                ident,
                "Expected 'Bytes', `Borsh`, or `Serde`",
            )),
        }
    }
}

#[derive(Default, Clone)]
pub struct SwitchboardSolanaFunctionArgs {
    pub timeout_seconds: Option<syn::LitInt>,
    pub encoding: Option<SolanaParamsEncoding>,
    pub commitment: Option<CommitmentConfig>,
    pub priority_fee: Option<u64>,
    pub compute_limit: Option<u32>,
    pub address_table_lookups: Option<Vec<AddressLookupTableAccount>>
}
pub fn parse_commitment_config(input: ParseStream) -> ParseResult<CommitmentConfig> {
    let ident: syn::Ident = input.parse()?;

    match ident.to_string().as_str() {
        "Confirmed" => Ok(CommitmentConfig::confirmed()),
        "Finalized" => Ok(CommitmentConfig::finalized()),
        "Processed" => Ok(CommitmentConfig::processed()),
        _ => Err(syn::Error::new_spanned(
            ident,
            "Expected 'Confirmed', `Finalized`, `Processed`",
        )),
    }
}
pub fn parse_address_lookup_table_account(input: ParseStream) -> ParseResult<AddressLookupTableAccount> {
    let ident: syn::Ident = input.parse()?;

    let bytes = [0u8; 8400];
    
    match ident.to_string().as_str() {
        "AddressLookupTableAccount" => Ok(AddressLookupTableAccount {
            key: solana_program::pubkey::Pubkey::new_from_array(bytes[0..32].to_vec().try_into().unwrap_or_default()),
            addresses: bytes.iter().skip(32).step_by(32).map(|x| {
                let x = *x as usize;
                solana_program::pubkey::Pubkey::new_from_array(bytes[(x..x+32)].to_vec().try_into().unwrap_or_default())
            }
            )
            .collect::<Vec<solana_program::pubkey::Pubkey>>().into_iter()
            .filter(|x| x != &solana_program::pubkey::Pubkey::default())
            .collect::<Vec<solana_program::pubkey::Pubkey>>()
        }),
        _ => Err(syn::Error::new_spanned(
            ident,
            "Expected 'AddressLookupTableAccount'",
        )),
    }
}


impl SwitchboardSolanaFunctionArgs {
    pub fn set_timeout_seconds(&mut self, timeout_seconds: Option<syn::LitInt>) {
        self.timeout_seconds = timeout_seconds;
    }
    pub fn set_encoding(&mut self, encoding: Option<SolanaParamsEncoding>) {
        self.encoding = encoding;
    }
    pub fn set_commitment(&mut self, commitment: Option<CommitmentConfig>) {
        self.commitment = commitment;
    }
    pub fn set_priority_fee(&mut self, priority_fee: Option<u64>) {
        self.priority_fee = priority_fee;
    }
    pub fn set_compute_limit(&mut self, compute_limit: Option<u32>) {
        self.compute_limit = compute_limit;
    }
    pub fn set_address_table_lookups(&mut self, address_table_lookups: Option<Vec<AddressLookupTableAccount>>) {
        self.address_table_lookups = address_table_lookups;
    }
}


impl Parse for SwitchboardSolanaFunctionArgs {
    fn parse(input: ParseStream) -> ParseResult<Self> {
        // If the input is empty, return the default instance
        if input.is_empty() {
            return Ok(Self::default());
        }

        let mut timeout_seconds = None;
        let mut encoding = None;
        let mut commitment = None;
        let mut priority_fee = None;
        let mut compute_limit = None;
        let mut address_table_lookups = None;

        // Parse a list of field assignments separated by commas.
        let parsed_fields: Punctuated<ExprAssign, Token![,]> =
            input.parse_terminated(ExprAssign::parse, Token![,])?;

        for field in parsed_fields {
            let field_name = match &*field.left {
                syn::Expr::Path(expr_path) if expr_path.path.segments.len() == 1 => {
                    expr_path.path.segments.first().unwrap().ident.to_string()
                }
                _ => {
                    return Err(syn::Error::new_spanned(
                        &field.left,
                        "Expected a field name",
                    ));
                }
            };

            match field_name.as_str() {
                "timeout_seconds" => {
                    if let syn::Expr::Lit(expr_lit) = &*field.right {
                        if let syn::Lit::Int(lit_int) = &expr_lit.lit {
                            timeout_seconds = Some(lit_int.clone());
                        }
                    } else {
                        return Err(syn::Error::new_spanned(
                            &field.right,
                            "Expected integer literal for `timeout_seconds`",
                        ));
                    }
                }
                "encoding" => {
                    if let syn::Expr::Path(expr_path) = &*field.right {
                        if let Some(ident) = expr_path.path.get_ident() {
                            encoding = Some(syn::parse::Parser::parse_str(
                                SolanaParamsEncoding::parse,
                                ident.to_string().as_str(),
                            )?);
                        }
                    } else {
                        return Err(syn::Error::new_spanned(
                            field.right,
                            "Expected identifier for `encoding`",
                        ));
                    }
                }
                "commitment" => {
                    if let syn::Expr::Path(expr_path) = &*field.right {
                        if let Some(ident) = expr_path.path.get_ident() {
                            commitment = Some(syn::parse::Parser::parse_str(
                                parse_commitment_config,
                                ident.to_string().as_str(),
                            )?);
                        }
                    } else { 
                        return Err(syn::Error::new_spanned(
                            field.right,
                            "Expected identifier for `commitment`",
                        ));
                    }
                }
                "priority_fee" => {
                    if let syn::Expr::Lit(expr_lit) = &*field.right {
                        if let syn::Lit::Int(lit_int) = &expr_lit.lit {
                            priority_fee = Some(lit_int.base10_parse::<u64>()?);
                        }
                    } else {
                        return Err(syn::Error::new_spanned(
                            &field.right,
                            "Expected integer literal for `priority_fee`",
                        ));
                    }
                }
                "compute_limit" => {
                    if let syn::Expr::Lit(expr_lit) = &*field.right {
                        if let syn::Lit::Int(lit_int) = &expr_lit.lit {
                            compute_limit = Some(lit_int.base10_parse::<u32>()?);
                        }
                    } else {
                        return Err(syn::Error::new_spanned(
                            &field.right,
                            "Expected integer literal for `compute_limit`",
                        ));
                    }
                }
                "address_table_lookups" => {
                    if let syn::Expr::Array(expr_array) = &*field.right {
                        let mut address_table_lookups_vec = Vec::new();
                        for expr in expr_array.elems.iter() {
                            if let syn::Expr::Path(expr_path) = expr {
                                if let Some(ident) = expr_path.path.get_ident() {
                                    address_table_lookups_vec.push(syn::parse::Parser::parse_str(
                                        parse_address_lookup_table_account,
                                        ident.to_string().as_str(),
                                    )?);
                                }
                            } else {
                                return Err(syn::Error::new_spanned(
                                    expr,
                                    "Expected identifier for `address_table_lookups`",
                                ));
                            }
                        }
                        address_table_lookups = Some(address_table_lookups_vec);
                    } else {
                        return Err(syn::Error::new_spanned(
                            &field.right,
                            "Expected array literal for `address_table_lookups`",
                        ));
                    }
                }
                _ => {
                    return Err(syn::Error::new_spanned(field.left, "Unknown field"));
                }
            }
        }

        Ok(SwitchboardSolanaFunctionArgs {
            timeout_seconds,
            encoding,
            commitment,
            priority_fee,
            compute_limit,
            address_table_lookups
        })
    }
}
