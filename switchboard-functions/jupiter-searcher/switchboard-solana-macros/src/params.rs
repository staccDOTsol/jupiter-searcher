use syn::parse::{Parse, ParseStream, Result as ParseResult};
use syn::punctuated::Punctuated;
use syn::{ExprAssign, Token};
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::instruction::Instruction;
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
}
impl Parse for SwitchboardSolanaFunctionArgs {
    fn parse(input: ParseStream) -> ParseResult<Self> {
        // If the input is empty, return the default instance
        if input.is_empty() {
            return Ok(Self::default());
        }

        let mut timeout_seconds = None;
        let mut encoding = None;

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
                _ => {
                    return Err(syn::Error::new_spanned(field.left, "Unknown field"));
                }
            }
        }

        Ok(SwitchboardSolanaFunctionArgs {
            timeout_seconds,
            encoding,
        })
    }
}
