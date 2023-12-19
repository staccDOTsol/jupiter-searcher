extern crate proc_macro;

mod params;
mod utils;
use proc_macro::TokenStream;
use quote::quote;
use syn::{GenericArgument, PathArguments, Type, FnArg, ItemFn, Result as SynResult, ReturnType};

#[proc_macro_attribute]
pub fn switchboard_function(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse the macro parameters to set a timeout
    let macro_params = match syn::parse::<params::SwitchboardSolanaFunctionArgs>(attr.clone()) {
        Ok(args) => args,
        Err(err) => {
            let e = syn::Error::new_spanned(
                err.to_compile_error(),
                format!("Failed to parse macro parameters: {:?}", err),
            );

            return e.to_compile_error().into();
        }
    };

    // Try to build the token stream, return errors if failed
    match build_token_stream(macro_params, item) {
        Ok(token_stream) => token_stream,
        Err(err) => err.to_compile_error().into(),
    }
}

/// Validates whether the first param is &mut FunctionRunner
fn validate_function_runner_param_mut_ref(input: &ItemFn) -> SynResult<()> {
    // Extract the first parameter of the function.
    let first_param_type = input.sig.inputs.iter().next().ok_or_else(|| {
        syn::Error::new_spanned(
            &input.sig,
            "The switchboard_function must take at least one parameter",
        )
    })?;

    // Ensure the first parameter is a typed argument.
    let typed_arg = match first_param_type {
        FnArg::Typed(typed) => typed,
        _ => {
            return Err(syn::Error::new_spanned(
                first_param_type,
                "Expected a typed parameter",
            ));
        }
    };

    // Check if the first parameter is a mutable reference to FunctionRunner.
    let is_function_runner_param = if let Type::Reference(type_reference) = &*typed_arg.ty {
        if let Type::Path(type_path) = &*type_reference.elem {
            type_reference.mutability.is_some() && // Check for mutability
                type_path.path.is_ident("FunctionRunner")
        } else {
            false
        }
    } else {
        false
    };

    if !is_function_runner_param {
        return Err(syn::Error::new_spanned(
            &typed_arg.ty,
            "First parameter must be of type `&mut FunctionRunner`",
        ));
    }

    Ok(())
}

/// Validates whether the first param is Arc<FunctionRunner>
fn validate_function_runner_param_arc(input: &ItemFn) -> SynResult<()> {
    // Extract the first parameter of the function.
    let first_param_type = input.sig.inputs.iter().next().ok_or_else(|| {
        syn::Error::new_spanned(
            &input.sig,
            "The switchboard_function must take at least one parameter",
        )
    })?;

    // Ensure the first parameter is a typed argument.
    let typed_arg = match first_param_type {
        FnArg::Typed(typed) => typed,
        _ => {
            return Err(syn::Error::new_spanned(
                first_param_type,
                "Expected a typed parameter",
            ));
        }
    };

    // Extract the inner type from the expected `Arc`.
    let inner_type = utils::extract_inner_type_from_arc(&typed_arg.ty).ok_or_else(|| {
        syn::Error::new_spanned(
            &typed_arg.ty,
            "Parameter must be of type Arc<FunctionRunner>",
        )
    })?;

    // Check that the inner type of `Arc` is `FunctionRunner`.
    let is_function_runner = if let Type::Path(type_path) = inner_type {
        &type_path.path.segments.last().unwrap().ident == "FunctionRunner"
    } else {
        false
    };

    if !is_function_runner {
        return Err(syn::Error::new_spanned(
            &typed_arg.ty,
            "Parameter inside Arc must be of type FunctionRunner",
        ));
    }

    Ok(())
}

/// Validates whether the first param is FunctionRunner
fn validate_function_runner_param(input: &ItemFn) -> SynResult<()> {
    // Extract the first parameter of the function.
    let first_param_type = input.sig.inputs.iter().next().ok_or_else(|| {
        syn::Error::new_spanned(
            &input.sig,
            "The switchboard_function must take at least one parameter",
        )
    })?;

    let typed_arg = match first_param_type {
        FnArg::Typed(typed) => typed,
        _ => {
            return Err(syn::Error::new_spanned(
                first_param_type,
                "Expected a typed parameter",
            ));
        }
    };

    let is_function_runner = if let Type::Path(type_path) = &*typed_arg.ty {
        &type_path.path.segments.last().unwrap().ident == "FunctionRunner"
    } else {
        false
    };

    if !is_function_runner {
        return Err(syn::Error::new_spanned(
            &typed_arg.ty,
            "Parameter must be FunctionRunner",
        ));
    }

    Ok(())
}

/// Helper function to validate the return type is a Result with the correct arguments.
fn validate_function_return_type(input: &ItemFn) -> SynResult<()> {
    let ty = match &input.sig.output {
        ReturnType::Type(_, ty) => ty,
        ReturnType::Default => {
            return Err(syn::Error::new_spanned(
                &input.sig.output,
                "Function does not have a return type",
            ));
        }
    };

    let (ok_type, err_type) = utils::extract_result_args(ty).ok_or_else(|| {
        syn::Error::new_spanned(&input.sig.output, "Return type must be a Result")
    })?;
/*
    // Validate the inner Vec type
    let inner_vec_type = utils::extract_inner_type_from_vec(inner_sb_type).ok_or_else(|| {
        syn::Error::new_spanned(
            &input.sig.output,
            "Ok variant of SbFunctionResult must be Vec<Instruction>"
        )
    })?;

    if !matches!(inner_vec_type, Type::Path(t) if t.path.is_ident("Instruction")) {
        return Err(syn::Error::new_spanned(
            &input.sig.output,
            "Ok variant of Result must be a (Vec<Instruction>,
                    Option<CommitmentConfig>,
                    Option<u64>,
                    Option<u32>,
                    Option<Vec<AddressLookupTableAccount>>)",
        ));
    } 

    // Validate the error type
    let error_type_path_segments = match err_type {
        Type::Path(type_path) => &type_path.path.segments,
        _ => {
            return Err(syn::Error::new_spanned(
                err_type,
                "Error type must be a path type",
            ));
        }
    };
    // Check if the error type is SbFunctionError or switchboard_common::SbFunctionError
    let is_sb_function_error = match error_type_path_segments.last() {
        Some(last_segment) if last_segment.ident == "SbFunctionError" => true,
        Some(last_segment) if last_segment.ident == "Error" => {
            // If the last segment is "Error", check the preceding segment for "switchboard_common"
            error_type_path_segments.len() > 1
                && error_type_path_segments[error_type_path_segments.len() - 2].ident
                    == "switchboard_common"
        }
        _ => false,
    };

    if !is_sb_function_error {
        return Err(syn::Error::new_spanned(
            &input.sig.output,
            "The error variant in the Result return type should be SbFunctionError",
        ));
    }
*/

    Ok(())
}

fn validate_second_parameter(input: &ItemFn) -> SynResult<()> {
    let second_param = input.sig.inputs.iter().nth(1).ok_or_else(|| {
        syn::Error::new_spanned(
            &input.sig,
            "The switchboard_function must take two parameters",
        )
    })?;

    let typed_arg = match second_param {
        FnArg::Typed(typed) => typed,
        _ => {
            return Err(syn::Error::new_spanned(
                second_param,
                "Expected a typed second parameter",
            ));
        }
    };
    
    // Use the utility function to extract the inner type from a Vec
    let inner_type = utils::extract_inner_type_from_vec(&typed_arg.ty).ok_or_else(|| {
        syn::Error::new_spanned(
            &typed_arg.ty,
            "The second parameter must be of type Vec<u8>",
        )
    })?;

    // Ensure the inner type of the Vec is u8
    if let Type::Path(type_path) = inner_type {
        if !type_path.path.is_ident("u8") {
            return Err(syn::Error::new_spanned(
                &typed_arg.ty,
                "The second parameter must be of type Vec<u8>",
            ));
        }
    } else {
        return Err(syn::Error::new_spanned(
            &typed_arg.ty,
            "The second parameter must be of type Vec<u8>",
        ));
    }

    Ok(())
}

fn build_token_stream(
    _params: params::SwitchboardSolanaFunctionArgs,
    item: TokenStream,
) -> SynResult<TokenStream> {
    let input: ItemFn = syn::parse(item.clone())?;
    let function_name = &input.sig.ident;

    // Validate that there's exactly one input of the correct type
    if input.sig.inputs.len() != 2 {
        return Err(
            syn::Error::new_spanned(
                &input.sig,
                "The switchboard_function must take exactly one parameter of type 'Arc<FunctionRunner>' and 'Vec<u8>'"
            )
        );
    }

    let expanded = quote! {
            use switchboard_solana::prelude::*;

            // Include the original function definition
            #input

            pub type SwitchboardFunctionResult<T> = std::result::Result<T, SbFunctionError>;

            /// Run an async function and catch any panics
            pub async fn run_switchboard_function<F, T>(
                logic: F,
            ) -> SwitchboardFunctionResult<()>
            where
                F: Fn(FunctionRunner, Vec<u8>) -> T + Send + 'static,
                T: futures::Future<Output = SwitchboardFunctionResult<SbFunctionResult>>
                    + Send,
            {
                // Initialize the runner
                let mut runner = FunctionRunner::from_env(None).unwrap();

                // Lets pre-load all of the accounts we'll need to yield our container parameters
                runner.load_accounts().await.map_err(|_e| SbFunctionError::FunctionResultEmitError)?;

                // Parse the container parameters based on our loaded accounts
                let params = runner.load_params().await.map_err(|_e| SbFunctionError::FunctionResultEmitError)?;
                
                match logic(runner.clone(), params).await {
                    Ok(ixs) => {
                        let sb_function_result: SbFunctionResult = SbFunctionResult {
                            ixs: ixs.clone(),
                            commitment: Some(CommitmentConfig::confirmed()),
                            priority_fee: None,
                            compute_limit: None,
                            address_lookup_table_accounts: None,
                        };
                        runner
                            .emit(sb_function_result)
                            .await
                            .map_err(|_e| SbFunctionError::FunctionResultEmitError)?;

                        Ok(())
                    }
                    Err(e) => {
                        println!("Error: Switchboard function failed with error code: {:?}", e);
                        let mut err_code = 199;
                        if let SbFunctionError::FunctionError(code) = e {
                            err_code = code;
                        }
                        runner
                            .emit_error(err_code)
                            .await
                            .map_err(|_e| SbFunctionError::FunctionResultEmitError)?;

                        Ok(())
                    }
                }
            }

            /// Run an async function and catch any panics
            pub async fn run_switchboard_function_simulation<F, T>(
                logic: F,
            ) -> SwitchboardFunctionResult<()>
            where
                F: Fn(FunctionRunner, Vec<u8>) -> T + Send + 'static,
                T: futures::Future<Output = SwitchboardFunctionResult<SbFunctionResult>>
                    + Send,
            {
                // Initialize the runner
                let mut runner = FunctionRunner::from_env(None).unwrap();

                // Lets pre-load all of the accounts we'll need to yield our container parameters
                runner.load_accounts().await.map_err(|_e| SbFunctionError::FunctionResultEmitError)?;

                // Parse the container parameters based on our loaded accounts
                let params = runner.load_params().await.map_err(|_e| SbFunctionError::FunctionResultEmitError)?;

                match logic(runner.clone(), params).await {
                    Ok(ixs) => {
                        let sb_function_result: SbFunctionResult = SbFunctionResult {
                            ixs: ixs.clone(),
                            commitment: Some(CommitmentConfig::confirmed()),
                            priority_fee: None,
                            compute_limit: None,
                            address_lookup_table_accounts: None,
                        };
                        match runner.get_function_result(sb_function_result, 0).await {
                            Ok(function_result) => {
                                let serialized_output = format!(
                                    "{}{}",
                                    FUNCTION_RESULT_PREFIX,
                                    function_result.hex_encode()
                                );

                                println!("\n## Output\n{}", serialized_output);
                                println!("\n## Instructions\n{:#?}", ixs.clone());
                            }
                            Err(e) => {
                                panic!("Failed to get FunctionResult from ixs: {:?}", e);
                            }
                        }

                        Ok(())
                    }
                    Err(e) => {
                        println!("Error: Switchboard function failed with error code: {:?}", e);
                        let mut err_code = 199;
                        if let SbFunctionError::FunctionError(code) = e {
                            err_code = code;
                        }
                        runner
                            .emit_error(err_code)
                            .await
                            .map_err(|_e| SbFunctionError::FunctionResultEmitError)?;

                        Ok(())
                    }
                }
            }

            #[tokio::main(worker_threads = 12)]
            async fn main() -> SwitchboardFunctionResult<()> {
                let is_simulation = match std::env::var("SWITCHBOARD_FUNCTION_SIMULATION") {
                    Ok(value) => {
                        let value = value.to_lowercase().trim().to_string();
                        value == "1" || value == "true"
                    }
                    Err(_) => false,
                };

                if is_simulation {
                    println!("[Debug] Simulation mode detected");
                    #[cfg(feature = "dotenv")]
                    dotenvy::dotenv().ok();

                    run_switchboard_function_simulation(#function_name).await?;
                } else {
                    run_switchboard_function(#function_name).await?;
                }


                Ok(())
            }
    };

    Ok(TokenStream::from(expanded))
}

#[proc_macro_attribute]
pub fn sb_error(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(item as syn::DeriveInput);

    let name = &input.ident;
    let expanded = quote! {
        #[derive(Clone, Copy, Debug, PartialEq)]
        #[repr(u8)]
        #input

        impl From<#name> for SbFunctionError {
            fn from(item: #name) -> Self {
                SbFunctionError::FunctionError(item as u8 + 1)
            }
        }

        impl From<#name> for u8 {
            fn from(item: #name) -> Self {
                item as u8 + 1
            }
        }

        impl std::fmt::Display for #name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{:?}", self)
            }
        }

        impl std::error::Error for #name {}
    };

    TokenStream::from(expanded)
}
