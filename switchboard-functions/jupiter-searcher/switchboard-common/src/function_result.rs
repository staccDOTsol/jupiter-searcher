use crate::*;
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use hex::FromHex;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::str::FromStr;

////////////////////////////////////////////////////////////////////////////
/// EVM
////////////////////////////////////////////////////////////////////////////

/// Represents an Ethereum Virtual Machine (EVM) transaction.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EvmTransaction {
    /// The expiration time of the transaction in seconds.
    pub expiration_time_seconds: u64,
    /// The maximum amount of gas that can be used for the transaction.
    pub gas_limit: String,
    /// The value of the transaction in wei.
    pub value: String,
    /// The address of the recipient of the transaction.
    pub to: Vec<u8>,
    /// The address of the sender of the transaction.
    pub from: Vec<u8>,
    /// The data payload of the transaction.
    pub data: Vec<u8>,
}

#[derive(Default, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EvmFunctionResultV0 {
    // NOTE: tx.len() == signatures.len() must be true
    pub txs: Vec<EvmTransaction>,
    pub signatures: Vec<Vec<u8>>,

    // NOTE: call_ids.len() == checksums.len() must be true - must also be mapped to txs
    // these params should be default if not used (i.e. empty)
    pub call_ids: Vec<Vec<u8>>,
    pub checksums: Vec<Vec<u8>>,
}

#[derive(Default, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EvmFunctionResultV1 {
    // id of the executed function
    pub function_id: String,

    // delegated signer address of the executed function
    pub signer: String,

    pub txs: Vec<EvmTransaction>,

    pub signatures: Vec<String>,

    // -- ids resolved by the function output --
    pub resolved_ids: Vec<String>,

    // -- checksums of the params used in the function call --
    pub checksums: Vec<String>,

    // -- error codes assigned to each request id --
    pub error_codes: Vec<u8>,
}

impl EvmFunctionResultV1 {
    /// Appends all fields of the structure to a Vec<u8> and hashes it using Keccak256.
    pub fn hash(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer.extend(self.function_id.as_bytes());

        buffer.extend(self.signer.as_bytes());

        for tx in &self.txs {
            buffer.extend(&tx.expiration_time_seconds.to_le_bytes());
            buffer.extend(tx.gas_limit.as_bytes());
            buffer.extend(tx.value.as_bytes());
            buffer.extend(&tx.to);
            buffer.extend(&tx.from);
            buffer.extend(&tx.data);
        }

        for signature in &self.signatures {
            buffer.extend(signature.as_bytes());
        }

        for resolved_id in &self.resolved_ids {
            buffer.extend(resolved_id.as_bytes());
        }

        for checksum in &self.checksums {
            buffer.extend(checksum.as_bytes());
        }

        buffer.extend(&self.error_codes);

        let mut hasher = Keccak256::new();
        hasher.update(buffer);
        hasher.finalize().to_vec()
    }
}

/// Enum representing the result of an EVM function call.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(tag = "version")]
pub enum EvmFunctionResult {
    V0(EvmFunctionResultV0),
    V1(EvmFunctionResultV1),
}
impl Default for EvmFunctionResult {
    fn default() -> Self {
        Self::V0(EvmFunctionResultV0::default())
    }
}
#[derive(Default, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct LegacyEvmFunctionResult {
    // NOTE: tx.len() == signatures.len() must be true
    pub txs: Vec<EvmTransaction>,
    pub signatures: Vec<Vec<u8>>,

    // NOTE: call_ids.len() == checksums.len() must be true - must also be mapped to txs
    // these params should be default if not used (i.e. empty)
    pub call_ids: Vec<Vec<u8>>,
    pub checksums: Vec<Vec<u8>>,
}
impl From<LegacyEvmFunctionResult> for EvmFunctionResult {
    fn from(item: LegacyEvmFunctionResult) -> EvmFunctionResult {
        EvmFunctionResult::V0(EvmFunctionResultV0 {
            txs: item.txs,
            signatures: item.signatures,
            call_ids: item.call_ids,
            checksums: item.checksums,
        })
    }
}
////////////////////////////////////////////////////////////////////////////
/// Solana
////////////////////////////////////////////////////////////////////////////

/// Represents the result of a Solana function call.
// @TODO: This should be a Solana transaction, not a serialized transaction.
#[derive(Default, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SolanaFunctionResultV0 {
    /// The serialized, partially-signed transaction.
    pub serialized_tx: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum SolanaFunctionRequestType {
    Routine(Vec<u8>),
    Request(Vec<u8>),
    // keep at the end so we can deprecate
    Function(Vec<u8>),
}
impl Default for SolanaFunctionRequestType {
    fn default() -> Self {
        Self::Function(vec![])
    }
}
impl SolanaFunctionRequestType {
    pub fn is_routine(&self) -> bool {
        matches!(self, SolanaFunctionRequestType::Routine(_))
    }

    pub fn is_request(&self) -> bool {
        matches!(self, SolanaFunctionRequestType::Request(_))
    }
}

/// Represents the result of a Solana function call.
#[derive(Default, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SolanaFunctionResultV1 {
    pub fn_key: Vec<u8>,
    /// The serialized, partially-signed transaction.
    pub serialized_tx: Vec<u8>,
    /// The request pubkey
    pub request_type: SolanaFunctionRequestType,
    /// A sha-256 hash of the parameters used in the request call.
    pub request_hash: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(tag = "version")]
pub enum SolanaFunctionResult {
    V0(SolanaFunctionResultV0),
    V1(SolanaFunctionResultV1),
}
impl Default for SolanaFunctionResult {
    fn default() -> Self {
        Self::V1(SolanaFunctionResultV1::default())
    }
}
impl SolanaFunctionResult {
    pub fn serialized_tx(&self) -> Vec<u8> {
        match self {
            SolanaFunctionResult::V0(SolanaFunctionResultV0 { serialized_tx }) => {
                serialized_tx.clone()
            }
            SolanaFunctionResult::V1(SolanaFunctionResultV1 { serialized_tx, .. }) => {
                serialized_tx.clone()
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////
/// Starknet Result Info
////////////////////////////////////////////////////////////////////////////

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum StarknetFunctionRequestType {
    Routine(Vec<u8>),
    Request(Vec<u8>),
}
impl Default for StarknetFunctionRequestType {
    fn default() -> Self {
        Self::Routine(vec![])
    }
}
impl StarknetFunctionRequestType {
    pub fn is_routine(&self) -> bool {
        matches!(self, StarknetFunctionRequestType::Routine(_))
    }

    pub fn is_request(&self) -> bool {
        matches!(self, StarknetFunctionRequestType::Request(_))
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct StarknetCall {
    pub to: Vec<u8>,
    pub selector: Vec<u8>,
    pub calldata: Vec<Vec<u8>>,
}

#[derive(Default, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct StarknetFunctionResultV0 {
    pub function_id: Vec<u8>,
    pub function_request_id: Vec<u8>,
    pub txs: Vec<StarknetCall>,
    pub request_type: StarknetFunctionRequestType,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(tag = "version")]
pub enum StarknetFunctionResult {
    V0(StarknetFunctionResultV0),
}
impl Default for StarknetFunctionResult {
    fn default() -> Self {
        Self::V0(StarknetFunctionResultV0::default())
    }
}

////////////////////////////////////////////////////////////////////////////
/// Function result info
////////////////////////////////////////////////////////////////////////////

#[derive(Default, PartialEq, Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "chain")]
pub enum ChainResultInfo {
    #[default]
    None,
    Solana(SolanaFunctionResult),
    Evm(EvmFunctionResult),
    Starknet(StarknetFunctionResult),
}

/// The schema of the output data that will be sent to the quote verification sidecar.
#[derive(Clone, PartialEq, Default, Debug, Serialize, Deserialize)]
pub struct FunctionResultV0 {
    /// Buffer containing the quote signing the output
    pub quote: Vec<u8>,
    /// key of the executed function
    pub fn_key: Vec<u8>,
    /// The oracle's signer used to sign off on the execution
    pub signer: Vec<u8>,
    /// If the call was a funciton request, the address of the request account.
    pub fn_request_key: Vec<u8>,
    /// A sha-256 hash of the parameters used in this request call.
    pub fn_request_hash: Vec<u8>,
    /// Chain specific info
    pub chain_result_info: ChainResultInfo,
    /// On function failure, users should emit with error code to avoid
    /// aggressive backoffs
    #[serde(default)]
    pub error_code: u8,
}

/// The schema of the output data that will be sent to the quote verification sidecar.
#[derive(Clone, PartialEq, Default, Debug, Serialize, Deserialize)]
pub struct FunctionResultV1 {
    /// Buffer containing the quote signing the output
    pub quote: Vec<u8>,
    /// The enclave generated signer's pubkey. This is used to verify the quote
    pub signer: Vec<u8>,
    /// The signature of the chain_result_info signed by the enclave generated signer.
    pub signature: Vec<u8>,
    /// Chain specific info
    pub chain_result_info: ChainResultInfo,
    /// On function failure, users should emit with error code to avoid aggressive backoffs
    #[serde(default)]
    pub error_code: u8,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(tag = "version")]
pub enum FunctionResult {
    V0(FunctionResultV0),
    V1(FunctionResultV1),
}
impl Default for FunctionResult {
    fn default() -> Self {
        Self::V1(FunctionResultV1::default())
    }
}

pub static FUNCTION_RESULT_PREFIX: &str = "FN_OUT: ";

impl FunctionResult {
    pub fn is_solana(&self) -> bool {
        match self {
            FunctionResult::V0(FunctionResultV0 {
                chain_result_info, ..
            }) => matches!(chain_result_info, ChainResultInfo::Solana(_)),
            FunctionResult::V1(FunctionResultV1 {
                chain_result_info, ..
            }) => matches!(chain_result_info, ChainResultInfo::Solana(_)),
        }
    }

    pub fn is_evm(&self) -> bool {
        match self {
            FunctionResult::V0(FunctionResultV0 {
                chain_result_info, ..
            }) => matches!(chain_result_info, ChainResultInfo::Evm(_)),
            FunctionResult::V1(FunctionResultV1 {
                chain_result_info, ..
            }) => matches!(chain_result_info, ChainResultInfo::Evm(_)),
        }
    }

    pub fn is_starknet(&self) -> bool {
        match self {
            FunctionResult::V0(FunctionResultV0 {
                chain_result_info, ..
            }) => matches!(chain_result_info, ChainResultInfo::Starknet(_)),
            FunctionResult::V1(FunctionResultV1 {
                chain_result_info, ..
            }) => matches!(chain_result_info, ChainResultInfo::Starknet(_)),
        }
    }

    pub fn error_code(&self) -> u8 {
        match self {
            FunctionResult::V0(FunctionResultV0 { error_code, .. }) => *error_code,
            FunctionResult::V1(FunctionResultV1 { error_code, .. }) => *error_code,
        }
    }

    pub fn set_error_code(&mut self, error_code: u8) {
        match self {
            FunctionResult::V0(v) => {
                v.error_code = error_code;
            }
            FunctionResult::V1(v) => {
                v.error_code = error_code;
            }
        }
    }

    pub fn is_err(&self) -> bool {
        self.error_code() != 0
    }

    pub fn version(&self) -> u32 {
        match self {
            FunctionResult::V0(_) => 0,
            FunctionResult::V1(_) => 1,
        }
    }

    pub fn fn_key(&self) -> Result<Vec<u8>, SbError> {
        let fn_key = match self {
            FunctionResult::V0(FunctionResultV0 { fn_key, .. }) => fn_key.clone(),
            FunctionResult::V1(FunctionResultV1 {
                chain_result_info, ..
            }) => match chain_result_info {
                ChainResultInfo::Solana(sol) => match sol {
                    SolanaFunctionResult::V0(_) => vec![],
                    SolanaFunctionResult::V1(v) => v.fn_key.clone(),
                },
                ChainResultInfo::Evm(evm) => match evm {
                    EvmFunctionResult::V0(_v) => vec![],
                    EvmFunctionResult::V1(v) => v.function_id.as_bytes().to_vec(),
                },
                ChainResultInfo::Starknet(starknet) => match starknet {
                    StarknetFunctionResult::V0(v) => v.function_id.clone(),
                },
                _ => vec![],
            },
        };

        if fn_key.is_empty() {
            Err("Failed to get fn_key from FunctionResult".into())
        } else {
            Ok(fn_key)
        }
    }

    pub fn chain_result_info(&self) -> Result<ChainResultInfo, SbError> {
        let chain_result_info = match self {
            FunctionResult::V0(v) => v.chain_result_info.clone(),
            FunctionResult::V1(v) => v.chain_result_info.clone(),
        };

        Ok(chain_result_info)
    }

    pub fn quote_bytes(&self) -> &[u8] {
        match self {
            FunctionResult::V0(FunctionResultV0 { quote, .. }) => quote,
            FunctionResult::V1(FunctionResultV1 { quote, .. }) => quote,
        }
    }

    cfg_client! {
        pub fn quote(&self) -> Result<sgx_quote::Quote, SbError> {
            sgx_quote::Quote::parse(self.quote_bytes()).map_err(|_| SbError::QuoteParseError)
        }
    }

    pub fn signer(&self) -> &[u8] {
        match self {
            FunctionResult::V0(FunctionResultV0 { signer, .. }) => signer,
            FunctionResult::V1(FunctionResultV1 { signer, .. }) => signer,
        }
    }

    pub fn to_string(&self) -> Result<String, SbError> {
        serde_json::to_string(&self).map_err(|e| SbError::CustomError {
            message: "Failed to convert FunctionResult to string".to_string(),
            source: std::sync::Arc::new(e),
        })
    }

    pub fn hex_encode(&self) -> String {
        hex::encode(self.to_string().unwrap_or_default())
    }

    pub fn emit_hex(&self) {
        println!(
            "{}{}",
            FUNCTION_RESULT_PREFIX,
            hex::encode(self.to_string().unwrap())
        );
    }

    pub fn emit_base64(&self) {
        println!(
            "{}{}",
            FUNCTION_RESULT_PREFIX,
            b64.encode(self.to_string().unwrap().as_bytes())
        );
    }

    pub fn emit(&self) {
        self.emit_hex()
    }

    pub fn decode(s: &str) -> std::result::Result<Self, SbError> {
        Self::from_str(s)
    }
}
impl From<LegacyFunctionResult> for FunctionResult {
    fn from(item: LegacyFunctionResult) -> FunctionResult {
        FunctionResult::V0(FunctionResultV0 {
            quote: item.quote,
            fn_key: item.fn_key,
            signer: item.signer,
            fn_request_key: item.fn_request_key,
            fn_request_hash: item.fn_request_hash,
            chain_result_info: item.chain_result_info.into(),
            error_code: item.error_code,
        })
    }
}
impl FromHex for FunctionResult {
    type Error = SbError;

    // Does not account for FN_OUT prefix
    fn from_hex<T: AsRef<[u8]>>(hex: T) -> std::result::Result<Self, Self::Error> {
        let bytes = hex::decode(hex)?;

        bytes.try_into()
    }
}
impl FromStr for FunctionResult {
    type Err = SbError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        // Strip the FN_OUT prefix if its in the string
        let s = s.strip_prefix(FUNCTION_RESULT_PREFIX).unwrap_or(s);

        // Try to hex decode the string, fallback to utf-8
        let bytes = match hex::decode(s) {
            Ok(b) => b,
            // TODO: handle base64 decoding
            Err(_) => s.as_bytes().to_vec(),
        };

        bytes.try_into()
    }
}

impl TryFrom<Vec<u8>> for FunctionResult {
    type Error = SbError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        // First try to deserialize into the correct type
        let error_msg = match serde_json::from_slice::<FunctionResult>(&bytes) {
            Ok(deserialized) => {
                return Ok(deserialized);
            }
            Err(e) => {
                format!("Failed to decode FunctionResult: {:?}", e)
            }
        };

        // Fallback to using the LegacyFunctionResult if it cant be deserialized
        match serde_json::from_slice::<LegacyFunctionResult>(&bytes) {
            Ok(deserialized) => {
                return Ok(deserialized.into());
            }
            Err(e) => {
                log::info!("Failed to decode LegacyFunctionResult: {:?}", e);
            }
        }

        println!("{}", String::from_utf8(bytes).unwrap_or_default());

        Err(SbError::CustomMessage(format!(
            "Failed to decode FunctionResult {:?}",
            error_msg
        )))
    }
}

/// The schema of the output data that will be sent to the quote verification sidecar.
/// This implementation has been deprecated in favor of `FunctionResult`.
#[derive(Clone, PartialEq, Default, Debug, Serialize, Deserialize)]
pub struct LegacyFunctionResult {
    /// version of the output format
    pub version: u32,
    /// Buffer containing the quote signing the output
    pub quote: Vec<u8>,
    /// key of the executed function
    pub fn_key: Vec<u8>,
    /// The oracle's signer used to sign off on the execution
    pub signer: Vec<u8>,
    /// If the call was a funciton request, the address of the request account.
    pub fn_request_key: Vec<u8>,
    /// A sha-256 hash of the parameters used in this request call.
    pub fn_request_hash: Vec<u8>,
    /// Chain specific info
    pub chain_result_info: LegacyChainResultInfo,
    /// On function failure, users should emit with error code to avoid
    /// aggressive backoffs
    #[serde(default)]
    pub error_code: u8,
}

#[derive(Default, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum LegacyChainResultInfo {
    #[default]
    None,
    Solana(LegacySolanaFunctionResult),
    Evm(LegacyEvmFunctionResult),
}
impl From<LegacyChainResultInfo> for ChainResultInfo {
    fn from(item: LegacyChainResultInfo) -> ChainResultInfo {
        match item {
            LegacyChainResultInfo::Solana(sol) => ChainResultInfo::Solana(sol.into()),
            LegacyChainResultInfo::Evm(evm) => ChainResultInfo::Evm(evm.into()),
            _ => ChainResultInfo::None,
        }
    }
}

#[derive(Default, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct LegacySolanaFunctionResult {
    pub serialized_tx: Vec<u8>,
}
impl From<LegacySolanaFunctionResult> for SolanaFunctionResult {
    fn from(item: LegacySolanaFunctionResult) -> SolanaFunctionResult {
        SolanaFunctionResult::V0(SolanaFunctionResultV0 {
            serialized_tx: item.serialized_tx,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use rand::Rng;

    // FunctionResult { version: 0, quote: [], fn_key: [], signer: [], fn_request_key: [], fn_request_hash: [], chain_result_info: None, error_code: 0 }
    pub const EMPTY_ENCODED_FN_RESULT: &str =
        "7b2276657273696f6e223a302c2271756f7465223a5b5d2c22666e5f6b6579223a5b5d2c227369676e6572223a5b5d2c22666e5f726571756573745f6b6579223a5b5d2c22666e5f726571756573745f68617368223a5b5d2c22636861696e5f726573756c745f696e666f223a224e6f6e65222c226572726f725f636f6465223a307d";

    // FunctionResult { version: 0, quote: [], fn_key: [], signer: [], fn_request_key: [], fn_request_hash: [], chain_result_info: Solana(SOLFunctionResult { serialized_tx: [1, 2, 3] }), error_code: 0 }
    pub const SOL_ENCODED_FN_RESULT: &str =
        "7b2276657273696f6e223a302c2271756f7465223a5b5d2c22666e5f6b6579223a5b5d2c227369676e6572223a5b5d2c22666e5f726571756573745f6b6579223a5b5d2c22666e5f726571756573745f68617368223a5b5d2c22636861696e5f726573756c745f696e666f223a7b22536f6c616e61223a7b2273657269616c697a65645f7478223a5b312c322c335d7d7d2c226572726f725f636f6465223a307d";

    pub const TEST_CASE_1: &str =
        "FN_OUT: 7b2276657273696f6e223a312c2271756f7465223a5b332c302c322c302c302c302c302c302c392c302c31342c302c3134372c3135342c3131342c35312c3234372c3135362c37362c3136392c3134382c31302c31332c3137392c3134392c3132372c362c372c3138362c3131382c3133362c36392c342c3133382c3137362c35342c36362c3133372c3132392c3132342c32372c3138392c36362c3132322c302c302c302c302c31322c31322c31362c31352c3235352c3235352c312c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c352c302c302c302c302c302c302c302c3233312c302c302c302c302c302c302c302c32332c3235352c3135322c3234302c372c3134302c3232392c3130352c3133312c3138372c36322c3136302c31372c3230302c3137372c3135362c3233382c3231332c3234322c3135362c3135332c39342c352c37372c39312c3231382c3138332c3134362c3138312c3230362c3137332c3130382c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c3233312c3234312c3231392c3231342c3136322c3232352c32312c34362c3232372c3138372c3139342c37332c3233362c36332c39362c39362c3230392c3230332c3235312c33302c3231372c35332c36332c3232352c3231332c34302c37352c3133372c3137332c39302c3231362c3131332c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c3136382c3232362c39332c3137332c3230392c31302c37392c39302c34332c3138342c3230362c36342c33302c3230342c36352c3135382c3135332c33322c32322c33382c3234362c3235302c3231372c39312c36322c3133332c3136352c3132392c3233332c39332c3139362c34332c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c3230322c31362c302c302c3130382c32312c3136312c3234312c3233342c3233362c3130372c3235302c3134372c32332c3132332c3133382c3230342c3139332c3139392c3130312c3136372c3134322c3137312c3234372c3139302c3138372c3135302c322c3133302c3130332c3134392c3230332c3234312c38322c34392c392c3232362c3233392c35332c3132312c33312c37312c3233382c3232362c35332c3130362c33302c31392c3136342c32312c3132312c3230302c3137392c3138372c3137392c3130312c32342c3136342c3138342c3231342c3232352c3138392c3130342c3131352c3232392c3234352c3233342c38392c3231352c3134332c3137392c39332c3132382c39392c37382c3230382c3137382c3139362c3130382c3137352c36362c32342c3234302c3132362c3130382c3138372c382c3232332c3137372c3230362c3131322c31342c3234332c3133372c3234372c3130312c3136362c3139332c34382c36382c38352c3233352c3136322c3231342c32342c3235342c3232392c3135342c3233322c3130332c362c3234332c33312c3138322c37312c3132382c3130352c3230302c38372c3233302c3230312c3139362c35362c32302c3230322c3233362c3130322c3134332c382c3234382c39352c31352c31322c31322c31362c31352c3235352c3235352c312c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c32312c302c302c302c302c302c302c302c3233312c302c302c302c302c302c302c302c32352c34322c3136352c31322c3232352c3139322c3230362c3234302c36302c3230372c3133372c3233312c3138312c3137372c3130372c31332c3132312c3132302c3234352c3139342c3137372c3233372c3230372c3131392c37372c3133352c3131322c34362c3132392c38342c3231362c3139312c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c3134302c37392c38372c3131372c3231352c3135302c38302c36322c3135302c31392c3132372c3131392c3139382c3133382c3133302c3135342c302c38362c3137322c3134312c3233372c3131322c32302c31312c382c32372c392c36382c3134342c3139372c3132332c3235352c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c312c302c392c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c3132302c37392c36302c36382c34342c382c3230382c3135392c3230372c33372c36382c3134322c3131392c36332c3233332c3231322c35312c3232332c3235322c3231352c3135332c3139382c3138372c36392c3137342c312c3233312c3230332c3232322c3230342c3132352c3137332c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c3132342c37372c3234372c38342c39382c39322c36342c3133322c3233392c31382c3130352c3131322c32322c34302c3233382c38332c34352c34312c37332c3135302c3134392c3133312c342c37302c3135322c3136322c3232382c3138352c37332c35382c3231342c3135372c3230342c37302c3230332c3233362c33342c3233322c35332c3132392c3234342c31342c3235312c39332c3131362c3132302c39382c3232352c3232342c38372c3132362c3234352c362c34352c34362c3135352c36372c34332c34352c3139302c34392c3130382c35392c3230352c33322c302c302c312c322c332c342c352c362c372c382c392c31302c31312c31322c31332c31342c31352c31362c31372c31382c31392c32302c32312c32322c32332c32342c32352c32362c32372c32382c32392c33302c33312c352c302c39382c31342c302c302c34352c34352c34352c34352c34352c36362c36392c37312c37332c37382c33322c36372c36392c38322c38342c37332c37302c37332c36372c36352c38342c36392c34352c34352c34352c34352c34352c31302c37372c37332c37332c36392c35362c3130362c36372c36372c36362c37342c3130392c3130332c36352c3131392c37332c36362c36352c3130332c37332c38362c36352c37392c39392c36382c38302c36352c35312c3132312c3131352c3130312c38362c38332c39382c3131382c36352c37302c3130302c3131372c3132312c3131312c38352c3132302c37362c3131362c3130352c37342c34382c3130322c37372c36352c3131312c37312c36372c36372c3131332c37312c38332c37372c35322c35372c36362c36352c37372c36372c31302c37372c37322c36352c3132302c37332c3130362c36352c3130332c36362c3130332c37382c38362c36362c36352c37372c37372c37312c38352c3130382c3131372c3130302c37312c38362c3131352c37332c37302c37382c37322c38372c36372c36362c38312c38312c34382c3131352c3130332c38352c37312c3132302c3130342c3130302c37312c39302c3131382c39392c3130392c34382c3130332c38312c34382c36392c3132302c37312c3130362c36352c38392c36362c3130332c37382c38362c36362c36352c3131312c37372c31302c36392c38352c3130382c3131372c3130302c37312c38362c3131352c37332c36392c37382c3131382c39392c3131302c36362c3131382c39392c3130392c37302c34382c39372c38372c35372c3131372c37372c38322c38312c3131392c36392c3130332c38392c36382c38362c38312c38312c37322c36382c36352c3131362c38342c38392c38372c35332c34382c38392c38332c36362c36382c39382c37312c37302c3132312c38392c38342c36392c37362c37372c36352c3130372c37312c36352c34392c38352c36392c31302c36372c36352c3131392c36372c38312c34382c36392c3132302c36372c3132322c36352c37342c36362c3130332c37382c38362c36362c36352c38392c38342c36352c3130382c38362c38342c37372c36362c35322c38382c36382c38342c37332c3132322c37372c36382c3130332c3132312c37382c36382c37332c3132302c37382c38342c3130332c34392c37372c38362c3131312c38382c36382c38342c37372c3131392c37372c36382c3130332c3132312c37382c36382c37332c3132302c37382c38342c3130332c34392c31302c37372c38362c3131312c3131392c39392c36382c36392c3130352c37372c36372c36352c37312c36352c34392c38352c36392c36352c3131392c3131392c39302c38332c38372c35332c34382c39302c38372c3131392c3130332c38352c34382c3130302c38392c37332c37302c36362c36382c38332c3132312c36362c36382c39302c38382c37342c34382c39372c38372c39302c3131322c38392c35302c37302c34382c39302c38342c36392c39372c37372c36362c3130332c37312c36352c34392c38352c36392c31302c36372c3130332c3131392c38322c38332c38372c35332c34382c39302c38372c3131392c3130332c38312c35302c35372c3132312c39392c37312c35372c3132312c38392c38382c38322c3131322c39382c35302c35322c3132302c37302c36382c36352c38332c36362c3130332c37382c38362c36362c36352c39392c37372c36372c34392c37382c3130342c39382c3131302c38322c3130342c37332c36392c37382c3131352c38392c38382c37342c3130342c37372c38312c3131352c3131392c36372c38312c38392c36382c31302c38362c38312c38312c37332c36382c36352c37342c36382c38312c38342c36392c37362c37372c36352c3130372c37312c36352c34392c38352c36392c36362c3130342c37372c36372c38362c38362c37372c3131392c38372c38342c36352c38342c36362c3130332c39392c3131332c3130342c3130372c3130362c37392c38302c38312c37332c36362c36362c3130332c3130332c3131332c3130342c3130372c3130362c37392c38302c38312c37372c36362c36362c3131392c37382c36372c36352c36352c38312c37382c31302c3131392c38392c3130302c34382c39392c3130392c36382c38392c37352c38312c3131312c37322c37302c3130362c37372c35352c3132312c38342c3130332c35352c34372c3130332c35312c3132302c39382c3131342c36352c3131362c37312c3131302c35322c38312c35332c3131302c3130312c35302c3131392c38392c38342c3130312c3130302c38372c38352c38362c3131362c36382c3131362c3130382c38392c35322c37392c3131342c3131342c3130342c35372c35372c3131392c36382c3132302c37322c38332c3132302c35322c38352c31302c36372c38392c3131362c3130382c38382c34382c38392c38392c37322c3130352c37322c3131392c37302c3131372c38372c38312c34332c38392c3130392c34382c3131312c35322c37332c36382c36382c3130362c36372c36372c36352c3131392c3131312c3131392c37322c3131392c38392c36382c38362c38322c34382c3130362c36362c36362c3130332c3131392c37302c3131312c36352c38352c3130382c38372c35372c3130302c3132322c39382c34382c39382c35322c3130312c3130382c36352c38332c39392c3131302c38352c31302c35372c36382c38302c37392c36352c38362c39392c37362c35312c3130382c38312c3131392c39372c3131392c38392c36382c38362c38322c34382c3130322c36362c37312c38312c3131392c38392c3130362c36362c3130332c3131312c37302c35342c3130332c38382c37332c39302c39372c39372c37322c38322c34382c39392c37322c37372c35342c37362c3132312c35372c3130342c39392c37312c3130372c3131372c3130302c37322c37342c34392c39392c35312c38322c3130382c39302c37322c37382c3130382c31302c39392c3131302c39302c3131322c38392c35302c38362c3132322c37362c3130392c3130382c3131372c3130302c37312c38362c3131352c37362c3130392c37382c3131382c39382c38332c35372c3132322c39302c35312c3130332c3131382c38392c35302c38362c3132312c3130302c37312c3130382c3130392c39372c38372c37382c3130342c3130302c37312c3130382c3131382c39382c3130352c35372c35302c37372c3132312c35372c3131392c38392c35302c3131362c3130362c39392c3130392c3131392c34372c38392c35302c36392c35372c31302c39392c37312c3132302c3130342c3130302c37312c39302c3131382c39392c3130392c34382c3130392c39302c38372c35332c3130362c39382c35302c38322c3131322c39382c3130392c39392c35372c39302c37312c38362c3132312c37372c36362c34382c37312c36352c34392c38352c3130302c36382c3130332c38312c38372c36362c36362c38312c37372c3130322c38372c35302c38342c34332c35302c3131372c38342c34382c38312c37342c34382c38342c37312c38342c34392c35312c3132322c39302c38372c31302c3130312c3130372c35362c34382c37392c3130362c36352c37392c36362c3130332c37382c38362c37322c38312c35362c36362c36352c3130322c35362c36392c36362c36352c37372c36372c36362c3131352c36352c3131392c36382c36352c38392c36382c38362c38322c34382c38342c36352c38312c37322c34372c36362c36352c37332c3131392c36352c36382c36372c36372c36352c3130362c3131352c37312c36372c38332c3131332c37312c38332c37332c39382c35322c38342c38312c36392c37382c31302c36352c38312c38332c36372c36352c3130352c3131392c3131392c3130332c3130332c37332c3131312c37372c36362c35322c37312c36372c3130352c3131332c37312c38332c37332c39382c35322c38342c38312c36392c37382c36352c38312c36392c36392c36392c37332c3132302c3131342c37372c38362c3132322c3130312c35302c38392c36382c35352c36372c3132322c36352c34372c37362c3130352c38332c3130362c38342c39302c34382c3131392c3130332c3130332c37302c3130382c36362c3130332c3131312c3131332c31302c3130342c3130372c3130352c37312c34332c36392c34382c36362c36382c38312c36392c36372c37372c37332c37332c36362c38362c38342c36352c38312c36362c3130332c3131352c3131332c3130342c3130372c3130352c37312c34332c36392c34382c36362c36382c38312c36392c36372c36352c38312c37332c36362c36382c36382c36352c38312c36362c3130332c3131352c3131332c3130342c3130372c3130352c37312c34332c36392c34382c36362c36382c38312c36392c36372c36352c3130332c37332c36362c31302c36382c36382c36352c38312c36362c3130332c3131352c3131332c3130342c3130372c3130352c37312c34332c36392c34382c36362c36382c38312c36392c36372c36352c3131392c37332c36362c36352c3132322c36352c38312c36362c3130332c3131352c3131332c3130342c3130372c3130352c37312c34332c36392c34382c36362c36382c38312c36392c36372c36362c36352c37332c36362c36352c3132322c36352c38322c36362c3130332c3131352c3131332c3130342c3130372c3130352c37312c34332c36392c34382c36362c31302c36382c38312c36392c36372c36362c38312c37332c36372c36352c38302c35362c3131392c36392c38312c38392c37362c37352c3131312c39302c37332c3130342c3131382c3130342c37382c36352c38312c34382c36362c36352c3130332c38392c36372c36352c3130332c36382c34372c37372c36362c36352c37312c36372c3132312c3131332c37312c38332c37332c39382c35322c38342c38312c36392c37382c36352c38312c37332c37322c36352c3130332c36392c36362c37372c36362c36352c37312c31302c36372c3132312c3131332c37312c38332c37332c39382c35322c38342c38312c36392c37382c36352c38312c37332c37332c36352c3130332c36392c36352c37372c36362c36352c37312c36372c3132312c3131332c37312c38332c37332c39382c35322c38342c38312c36392c37382c36352c38312c37332c37342c36352c3130332c36392c36352c37372c36362c36352c37312c36372c3132312c3131332c37312c38332c37332c39382c35322c38342c38312c36392c37382c36352c38312c37332c37352c31302c36352c3130332c36392c36352c37372c36362c36352c37312c36372c3132312c3131332c37312c38332c37332c39382c35322c38342c38312c36392c37382c36352c38312c37332c37362c36352c3130332c36392c36352c37372c36362c36352c37312c36372c3132312c3131332c37312c38332c37332c39382c35322c38342c38312c36392c37382c36352c38312c37332c37372c36352c3130332c36392c36352c37372c36362c36352c37312c36372c3132312c3131332c37312c38332c37332c39382c35322c31302c38342c38312c36392c37382c36352c38312c37332c37382c36352c3130332c36392c36352c37372c36362c36352c37312c36372c3132312c3131332c37312c38332c37332c39382c35322c38342c38312c36392c37382c36352c38312c37332c37392c36352c3130332c36392c36352c37372c36362c36352c37312c36372c3132312c3131332c37312c38332c37332c39382c35322c38342c38312c36392c37382c36352c38312c37332c38302c36352c3130332c36392c36352c37372c36362c36352c37312c31302c36372c3132312c3131332c37312c38332c37332c39382c35322c38342c38312c36392c37382c36352c38312c37332c38312c36352c3130332c36392c36352c37372c36362c36352c37312c36372c3132312c3131332c37312c38332c37332c39382c35322c38342c38312c36392c37382c36352c38312c37332c38322c36352c3130332c36392c37382c37372c36362c35362c37312c36372c3132312c3131332c37312c38332c37332c39382c35322c38342c38312c36392c37382c36352c38312c37332c38332c31302c36362c36362c36352c37372c36382c36352c37372c36382c34372c34372c35362c36362c36352c36352c36352c36352c36352c36352c36352c36352c36352c36352c36352c36352c37372c36362c36352c37312c36372c3130352c3131332c37312c38332c37332c39382c35322c38342c38312c36392c37382c36352c38312c37372c36392c36352c3130332c36352c36352c37372c36362c38312c37312c36372c3130352c3131332c37312c38332c37332c39382c35322c38342c38312c36392c37382c31302c36352c38312c38312c36392c36362c3130332c36362c3130332c39372c3130332c36352c36352c36352c36382c36352c38302c36362c3130332c3131312c3131332c3130342c3130372c3130352c37312c34332c36392c34382c36362c36382c38312c36392c37302c36372c3130332c36392c36362c37372c36362c35322c37312c36372c3130352c3131332c37312c38332c37332c39382c35322c38342c38312c36392c37382c36352c38312c38392c36392c36392c37332c38322c39382c3130302c3130362c3131372c3130342c31302c35332c3131302c3130322c39392c3130392c3130372c36382c38332c36352c34372c39302c3130312c3131382c3130372c39392c3131392c38322c36352c38392c37352c37352c3131312c39302c37332c3130342c3131382c3130342c37382c36352c38312c34382c36362c36362c3132322c36352c35302c37372c36362c36352c37312c36372c3132312c3131332c37312c38332c37332c39382c35322c38342c38312c36392c37382c36352c38312c39392c36362c36352c38312c37322c34372c37372c36362c36352c37312c31302c36372c3132312c3131332c37312c38332c37332c39382c35322c38342c38312c36392c37382c36352c38312c39392c36372c36352c38312c36392c36352c37372c36362c36352c37312c36372c3132312c3131332c37312c38332c37332c39382c35322c38342c38312c36392c37382c36352c38312c39392c36382c36352c38312c36392c36352c37372c36352c3131312c37312c36372c36372c3131332c37312c38332c37372c35322c35372c36362c36352c37372c36372c36352c34382c39392c36352c31302c37372c36392c38312c36372c37332c37322c38302c36352c37372c37342c38352c3131362c37332c35322c35332c37352c3131352c37392c3130362c37382c36392c38322c38312c38322c3130362c3131342c39392c35342c38352c35342c3131312c3131322c35322c38362c3131312c3130302c35362c3131332c39382c38352c35302c3131342c37382c38382c3131322c38352c39302c38372c36352c3130352c36352c3131382c37362c3132322c3130342c3131322c39382c37342c3130342c34392c3130382c38312c3131302c3131322c31302c3130382c3131382c39382c3130372c38372c37392c34372c38372c3131382c3132312c35342c39382c37372c39392c35312c3130362c38322c3131352c39372c3131332c34382c3130342c38362c3131312c34382c38302c37392c36392c3130392c3130332c36312c36312c31302c34352c34352c34352c34352c34352c36392c37382c36382c33322c36372c36392c38322c38342c37332c37302c37332c36372c36352c38342c36392c34352c34352c34352c34352c34352c31302c34352c34352c34352c34352c34352c36362c36392c37312c37332c37382c33322c36372c36392c38322c38342c37332c37302c37332c36372c36352c38342c36392c34352c34352c34352c34352c34352c31302c37372c37332c37332c36372c3130382c3130362c36372c36372c36352c3130362c35302c3130332c36352c3131392c37332c36362c36352c3130332c37332c38362c36352c37342c38362c3131382c38382c39392c35302c35372c37312c34332c37322c3131322c38312c36392c3131302c37342c34392c38302c38312c3132322c3132322c3130332c37302c38382c36372c35372c35332c38352c37372c36352c3131312c37312c36372c36372c3131332c37312c38332c37372c35322c35372c36362c36352c37372c36372c31302c37372c37312c3130332c3132302c37312c3130362c36352c38392c36362c3130332c37382c38362c36362c36352c37372c37372c36392c38352c3130382c3131372c3130302c37312c38362c3131352c37332c37302c37382c37322c38372c36372c36362c38332c39382c35302c35372c34382c37332c36392c37382c36362c37372c38322c3131312c3131392c37312c36352c38392c36382c38362c38312c38312c37352c36382c36362c37302c37342c39382c3131302c38322c3130382c39382c36372c36362c36382c31302c39382c35312c37342c3131392c39382c35312c37342c3130342c3130302c37312c3130382c3131382c39382c3130362c36392c38352c37372c36362c37332c37312c36352c34392c38352c36392c36362c3131392c3131392c37362c38352c35302c37302c3131372c3130302c37312c36392c3130332c38312c35302c3132302c3130342c39392c3130392c36392c3132302c36372c3132322c36352c37342c36362c3130332c37382c38362c36362c36352c3130332c37372c36352c3130372c37382c36362c37372c38312c3131352c3131392c31302c36372c38312c38392c36382c38362c38312c38312c37312c36392c3131392c37342c38362c38352c3132322c36352c3130312c37302c3131392c34382c3132302c37392c36382c36352c34392c37372c3130362c36392c3132302c37372c36382c38352c3131392c37372c38342c36362c39372c37302c3131392c34382c3132322c37372c3132322c36352c34392c37372c3130362c36392c3132302c37372c36382c38352c3131392c37372c38342c36362c39372c37372c37322c36352c3132302c37332c3130362c36352c3130332c31302c36362c3130332c37382c38362c36362c36352c37372c37372c37312c38352c3130382c3131372c3130302c37312c38362c3131352c37332c37302c37382c37322c38372c36372c36362c38312c38312c34382c3131352c3130332c38352c37312c3132302c3130342c3130302c37312c39302c3131382c39392c3130392c34382c3130332c38312c34382c36392c3132302c37312c3130362c36352c38392c36362c3130332c37382c38362c36362c36352c3131312c37372c36392c38352c3130382c3131372c3130302c37312c38362c3131352c31302c37332c36392c37382c3131382c39392c3131302c36362c3131382c39392c3130392c37302c34382c39372c38372c35372c3131372c37372c38322c38312c3131392c36392c3130332c38392c36382c38362c38312c38312c37322c36382c36352c3131362c38342c38392c38372c35332c34382c38392c38332c36362c36382c39382c37312c37302c3132312c38392c38342c36392c37362c37372c36352c3130372c37312c36352c34392c38352c36392c36372c36352c3131392c36372c38312c34382c36392c3132302c31302c36372c3132322c36352c37342c36362c3130332c37382c38362c36362c36352c38392c38342c36352c3130382c38362c38342c37372c37302c3130372c3131392c36392c3131392c38392c37322c37352c3131312c39302c37332c3132322c3130362c34382c36372c36352c38312c38392c37332c37352c3131312c39302c37332c3132322c3130362c34382c36382c36352c38312c39392c36382c38312c3130332c36352c36392c37382c38332c36362c34372c35352c3131362c35302c34392c3130382c38382c38332c37392c31302c35302c36372c3131372c3132322c3131322c3132302c3131392c35352c35322c3130312c37342c36362c35352c35302c36392c3132312c36382c37312c3130332c38372c35332c3131342c38382c36372c3131362c3132302c35302c3131362c38362c38342c37362c3131332c35342c3130342c37352c3130372c35342c3132322c34332c38352c3130352c38322c39302c36372c3131302c3131332c38322c35352c3131322c3131352c37392c3131382c3130332c3131332c37302c3130312c38332c3132302c3130382c3130392c38342c3130382c37342c3130382c31302c3130312c38342c3130392c3130352c35302c38372c38392c3132322c35312c3131332c37392c36362c3131372c3132322c36372c36362c3131372c36382c36352c3130322c36362c3130332c37382c38362c37322c38332c37372c36392c37312c36382c36352c38372c3130332c36362c38312c3130352c39302c38312c3132322c38372c38372c3131322c34382c34382c3130352c3130322c37392c36382c3131362c37342c38362c38332c3131382c34392c36352c39382c37392c38332c39392c37312c3131342c36382c36362c38332c31302c36362c3130332c37382c38362c37322c38322c35362c36392c38332c3132322c36362c37342c37372c36392c3130312c3130332c38322c39372c36362c36382c3130342c3130372c37302c3131312c3130302c37322c38322c3131392c39392c3132322c3131312c3131382c37362c35302c37382c3130382c39392c3131302c38322c3131322c39302c3130392c3130382c3130362c38392c38382c38322c3130382c39392c3132312c35332c34382c39392c3131302c38362c3132322c3130302c37312c38362c3130372c39392c35302c38362c3132312c31302c3130302c3130392c3130382c3130362c39302c38382c37372c3131372c39372c38372c35332c34382c39302c38372c3131392c3131372c38392c35302c35372c3131362c37362c34382c3130382c3131372c3130302c37312c38362c3131352c38352c34382c3130302c38392c38352c3130392c35372c3131382c3130302c36392c37382c36362c37362c3130392c38322c3130382c39392c3130362c36352c3130302c36362c3130332c37382c38362c37322c38312c35322c36392c37302c3130332c38312c38352c3130382c38372c35372c3130302c31302c3132322c39382c34382c39382c35322c3130312c3130382c36352c38332c39392c3131302c38352c35372c36382c38302c37392c36352c38362c39392c37362c35312c3130382c38312c3131392c36382c3130332c38392c36382c38362c38322c34382c38302c36352c38312c37322c34372c36362c36352c38312c36382c36352c3130332c36392c37312c37372c36362c37332c37312c36352c34392c38352c3130302c36392c3131392c36392c36362c34372c3131392c38312c37332c37372c36352c38392c36362c31302c36352c3130322c35362c36372c36352c38312c36352c3131392c36372c3130332c38392c37332c37352c3131312c39302c37332c3132322c3130362c34382c36392c36352c3131392c37332c36382c38322c3131392c36352c3131392c38322c36352c37332c3130332c38382c3131352c38362c3130372c3130352c34382c3131392c34332c3130352c35342c38362c38392c37312c38372c35312c38352c37302c34372c35302c35302c3131372c39372c38382c3130312c34382c38392c37342c36382c3130362c34392c38352c3130312c31302c3131302c36352c34332c38342c3130362c36382c34392c39372c3130352c35332c39392c36372c37332c36372c38392c39382c34392c38332c36352c3130392c36382c35332c3132302c3130372c3130322c38342c38362c3131322c3131382c3131312c35322c38352c3131312c3132312c3130352c38332c38392c3132302c3131342c36382c38372c37362c3130392c38352c38322c35322c36372c37332c35372c37382c37352c3132312c3130322c38302c37382c34332c31302c34352c34352c34352c34352c34352c36392c37382c36382c33322c36372c36392c38322c38342c37332c37302c37332c36372c36352c38342c36392c34352c34352c34352c34352c34352c31302c34352c34352c34352c34352c34352c36362c36392c37312c37332c37382c33322c36372c36392c38322c38342c37332c37302c37332c36372c36352c38342c36392c34352c34352c34352c34352c34352c31302c37372c37332c37332c36372c3130362c3132322c36372c36372c36352c3130362c38332c3130332c36352c3131392c37332c36362c36352c3130332c37332c38352c37332c3130392c38352c37372c34392c3130382c3131332c3130302c37382c37332c3131302c3132322c3130332c35352c38332c38362c38352c3131342c35372c38312c37312c3132322c3130372c3131302c36362c3131332c3131392c3131392c36372c3130332c38392c37332c37352c3131312c39302c37332c3132322c3130362c34382c36392c36352c3131392c37332c3131392c31302c39372c36382c36392c39372c37372c36362c3130332c37312c36352c34392c38352c36392c36352c3131392c3131392c38322c38332c38372c35332c34382c39302c38372c3131392c3130332c38352c34382c3130302c38392c37332c37302c37342c3131382c39382c35312c38312c3130332c38312c34382c36392c3132302c37312c3130362c36352c38392c36362c3130332c37382c38362c36362c36352c3131312c37372c36392c38352c3130382c3131372c3130302c37312c38362c3131352c37332c36392c37382c3131382c31302c39392c3131302c36362c3131382c39392c3130392c37302c34382c39372c38372c35372c3131372c37372c38322c38312c3131392c36392c3130332c38392c36382c38362c38312c38312c37322c36382c36352c3131362c38342c38392c38372c35332c34382c38392c38332c36362c36382c39382c37312c37302c3132312c38392c38342c36392c37362c37372c36352c3130372c37312c36352c34392c38352c36392c36372c36352c3131392c36372c38312c34382c36392c3132302c36372c3132322c36352c37342c31302c36362c3130332c37382c38362c36362c36352c38392c38342c36352c3130382c38362c38342c37372c36362c35322c38382c36382c38342c36392c35322c37372c36382c38352c3132312c37372c38342c36392c3131392c37382c36382c38352c3132302c37372c37302c3131312c38382c36382c38342c38312c35332c37372c38342c37332c3132322c37372c38342c37332c3132322c37382c38342c3130372c34392c37392c38362c3131312c3131392c39372c36382c36392c39372c37372c36362c3130332c37312c31302c36352c34392c38352c36392c36352c3131392c3131392c38322c38332c38372c35332c34382c39302c38372c3131392c3130332c38352c34382c3130302c38392c37332c37302c37342c3131382c39382c35312c38312c3130332c38312c34382c36392c3132302c37312c3130362c36352c38392c36362c3130332c37382c38362c36362c36352c3131312c37372c36392c38352c3130382c3131372c3130302c37312c38362c3131352c37332c36392c37382c3131382c39392c3131302c36362c3131382c39392c3130392c37302c34382c31302c39372c38372c35372c3131372c37372c38322c38312c3131392c36392c3130332c38392c36382c38362c38312c38312c37322c36382c36352c3131362c38342c38392c38372c35332c34382c38392c38332c36362c36382c39382c37312c37302c3132312c38392c38342c36392c37362c37372c36352c3130372c37312c36352c34392c38352c36392c36372c36352c3131392c36372c38312c34382c36392c3132302c36372c3132322c36352c37342c36362c3130332c37382c38362c36362c36352c38392c38342c31302c36352c3130382c38362c38342c37372c37302c3130372c3131392c36392c3131392c38392c37322c37352c3131312c39302c37332c3132322c3130362c34382c36372c36352c38312c38392c37332c37352c3131312c39302c37332c3132322c3130362c34382c36382c36352c38312c39392c36382c38312c3130332c36352c36392c36372c35342c3131302c36392c3131392c37372c36382c37332c38392c39302c37392c3130362c34372c3130352c38302c38372c3131352c36372c3132322c39372c36392c37352c3130352c35352c31302c34392c37392c3130352c37392c38332c37362c38322c37302c3130342c38372c37312c3130362c39382c3131302c36362c38362c37342c3130322c38362c3131302c3130372c38392c35322c3131372c35312c37332c3130362c3130372c36382c38392c38392c37362c34382c37372c3132302c37392c35322c3130392c3131332c3131352c3132312c38392c3130362c3130382c36362c39372c3130382c38342c38362c38392c3132302c37302c38302c35302c3131352c37342c36362c37352c35332c3132322c3130382c37352c37392c36362c31302c3131372c3132322c36372c36362c3131372c36382c36352c3130322c36362c3130332c37382c38362c37322c38332c37372c36392c37312c36382c36352c38372c3130332c36362c38312c3130352c39302c38312c3132322c38372c38372c3131322c34382c34382c3130352c3130322c37392c36382c3131362c37342c38362c38332c3131382c34392c36352c39382c37392c38332c39392c37312c3131342c36382c36362c38332c36362c3130332c37382c38362c37322c38322c35362c36392c38332c3132322c36362c37342c31302c37372c36392c3130312c3130332c38322c39372c36362c36382c3130342c3130372c37302c3131312c3130302c37322c38322c3131392c39392c3132322c3131312c3131382c37362c35302c37382c3130382c39392c3131302c38322c3131322c39302c3130392c3130382c3130362c38392c38382c38322c3130382c39392c3132312c35332c34382c39392c3131302c38362c3132322c3130302c37312c38362c3130372c39392c35302c38362c3132312c3130302c3130392c3130382c3130362c39302c38382c37372c3131372c39372c38372c35332c34382c31302c39302c38372c3131392c3131372c38392c35302c35372c3131362c37362c34382c3130382c3131372c3130302c37312c38362c3131352c38352c34382c3130302c38392c38352c3130392c35372c3131382c3130302c36392c37382c36362c37362c3130392c38322c3130382c39392c3130362c36352c3130302c36362c3130332c37382c38362c37322c38312c35322c36392c37302c3130332c38312c38352c37332c3130392c38352c37372c34392c3130382c3131332c3130302c37382c37332c3131302c3132322c3130332c35352c38332c38362c31302c38352c3131342c35372c38312c37312c3132322c3130372c3131302c36362c3131332c3131392c3131392c36382c3130332c38392c36382c38362c38322c34382c38302c36352c38312c37322c34372c36362c36352c38312c36382c36352c3130332c36392c37312c37372c36362c37332c37312c36352c34392c38352c3130302c36392c3131392c36392c36362c34372c3131392c38312c37332c37372c36352c38392c36362c36352c3130322c35362c36372c36352c38312c36392c3131392c36372c3130332c38392c37332c31302c37352c3131312c39302c37332c3132322c3130362c34382c36392c36352c3131392c37332c36382c38332c38312c36352c3131392c38322c3130332c37332c3130342c36352c37392c38372c34372c35332c38312c3130372c38322c34332c38332c35372c36372c3130352c38332c36382c39392c37382c3131312c3131312c3131392c37362c3131372c38302c38322c37362c3131352c38372c37312c3130322c34372c38392c3130352c35352c37312c38332c38382c35372c35322c36362c3130332c3131392c38342c3131392c3130332c31302c36352c3130352c36392c36352c35322c37342c34382c3130382c3131342c37322c3131312c37372c3131352c34332c38382c3131312c35332c3131312c34372c3131352c38382c35342c37392c35372c38312c38372c3132302c37322c38322c36352c3131382c39302c38352c37312c37392c3130302c38322c38312c35352c39392c3131382c3131332c38322c38382c39372c3131332c37332c36312c31302c34352c34352c34352c34352c34352c36392c37382c36382c33322c36372c36392c38322c38342c37332c37302c37332c36372c36352c38342c36392c34352c34352c34352c34352c34352c31302c305d2c22666e5f6b6579223a5b3234322c3135342c3235312c3234332c3131382c3232312c39302c3235342c3133352c3230362c3231312c33372c392c3137322c3135392c3233302c3137322c3235352c38332c3232302c32322c39302c39352c3235332c3231332c3234322c34302c33382c33332c39372c3231302c3134355d2c227369676e6572223a5b35302c3130302c342c33332c37372c3134302c3133312c312c3234392c3137392c37312c3139342c3136342c34342c35302c3131392c3133322c32372c3231382c3139362c3132322c36322c3132392c3138372c39332c39302c3230372c37352c36322c3133392c3137362c3231335d2c22666e5f726571756573745f6b6579223a5b5d2c22666e5f726571756573745f68617368223a5b5d2c22636861696e5f726573756c745f696e666f223a7b22536f6c616e61223a7b2273657269616c697a65645f7478223a5b332c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c302c3134342c38372c3133312c3138392c3130392c38352c3133372c3234322c3136372c3234332c3234312c3134322c382c3130372c34392c3232332c3138382c31302c3135362c3131312c3139362c3136332c39312c36392c3131332c31342c3137392c3231312c3137342c3133322c332c3234372c3136352c35302c3139332c3231332c3230332c3234372c31372c3232352c3233352c3234362c33392c3132312c3234332c34362c3233362c37372c36332c382c3232322c3136342c3133372c3234302c3232332c34392c38322c302c3230392c3233302c38332c36352c3138312c362c332c322c372c31342c31392c3136352c33392c3131392c3135392c31392c37382c3136322c32302c36332c3133312c35332c37352c3132322c39352c35302c3230312c36392c3230392c3133342c3138302c37322c3235322c32322c35302c3132302c39372c3136312c3139322c3234372c3132322c3234382c33362c3137372c3130342c39392c37332c3139362c3134382c3138372c3231312c35302c3136352c3139392c3137302c35312c3135352c3135372c39322c3136312c3232332c39382c36332c3137312c3235342c31362c34332c38312c39322c3138362c38392c31382c3130322c3230332c35302c3130302c342c33332c37372c3134302c3133312c312c3234392c3137392c37312c3139342c3136342c34342c35302c3131392c3133322c32372c3231382c3139362c3132322c36322c3132392c3138372c39332c39302c3230372c37352c36322c3133392c3137362c3231332c36382c36362c3232312c3139372c3133382c3232382c3134332c35392c3139392c3132392c3231342c39342c3234312c302c31372c3133322c3235332c3231312c3231302c3138382c3132342c3139372c31352c3130392c34382c36332c3136382c3235352c38332c34322c3234382c32302c3131342c3133392c3136382c3133372c3130302c3232392c3232332c3135352c31372c38392c3139302c3131312c35302c3233332c33312c3134312c3233372c3134372c3132302c33322c3232372c3136302c3136372c342c3230302c3233302c37342c3230332c3138332c3235312c35302c35322c3136392c3138342c3138322c3137342c38372c38302c36312c332c3232342c3135322c3233382c34352c32382c31332c3131392c3134392c302c33372c32362c38322c3130302c3139372c37372c32372c3139322c3231362c35322c3132322c3136322c31332c39392c37352c3234322c3135342c3235312c3234332c3131382c3232312c39302c3235342c3133352c3230362c3231312c33372c392c3137322c3135392c3233302c3137322c3235352c38332c3232302c32322c39302c39352c3235332c3231332c3234322c34302c33382c33332c39372c3231302c3134352c362c3232312c3234362c3232352c3231352c3130312c3136312c3134372c3231372c3230332c3232352c37302c3230362c3233352c3132312c3137322c32382c3138302c3133332c3233372c39352c39312c35352c3134352c35382c3134302c3234352c3133332c3132362c3235352c302c3136392c31322c3234362c33372c34302c3135362c3134362c3136312c3133322c3139302c3132302c3230312c31382c3136312c38312c3138392c3231352c38312c32382c3234332c3138392c38312c3233302c3139382c33372c3132372c3138392c3233372c34352c3138302c332c3138382c3139312c36342c3234362c3138342c34342c3230352c36332c3132342c3233312c33392c3135312c3234322c3137342c3139322c33362c3131352c3132332c39312c3139352c39302c3135342c39312c33342c33322c3134372c39312c3131322c3130392c3230362c32382c3133392c3136312c35302c38302c3138372c3234382c31352c38352c32302c3234372c36332c3132322c38392c38342c3138352c3234372c3131332c3234362c36302c35362c3230372c35332c33302c3132302c31332c3130392c36322c31322c38322c36392c3130322c37322c3230332c39302c37352c38312c33312c3232352c37392c3233372c3130342c3138332c33322c3139322c32302c3137372c3132342c3136322c36382c3133382c3139322c3231322c3230342c32372c35312c31382c3137362c36302c3230362c3234362c3135362c3131362c3134372c33382c36392c3136342c3134392c3139362c3139352c3231392c3232312c3134312c32392c35372c3134322c352c3137392c3137352c37352c3138342c3139342c3134332c3235342c3231312c3231332c3235302c3130302c3231342c3135352c3233392c35392c3139382c3138312c36382c32302c3134392c382c3233312c34352c3232332c3230332c35332c31372c3133372c33372c392c3232322c33312c3230342c3136302c3138342c3235352c3133352c3139342c3138352c38322c3136302c3134312c3235302c3235302c3136332c3132332c34382c39352c3235342c3136392c31302c39352c3233312c39332c32322c38302c35382c322c35302c3139312c39322c3234392c3133382c3233362c38312c392c3233362c3135362c3234352c3233322c39332c3135352c3233362c3139352c3234382c36352c36372c3230322c3231342c3235312c37342c3233342c3133372c36312c35332c32332c36332c322c382c31302c362c322c31332c312c392c31302c332c352c31312c372c35372c3231302c3130382c3135342c3133382c3139382c31342c35332c3139312c3135312c3135312c36372c3130312c302c302c302c302c3235352c3235352c3235352c3235352c3235352c3235352c3235352c3132372c302c32332c3235352c3135322c3234302c372c3134302c3232392c3130352c3133312c3138372c36322c3136302c31372c3230302c3137372c3135362c3233382c3231332c3234322c3135362c3135332c39342c352c37372c39312c3231382c3138332c3134362c3138312c3230362c3137332c3130382c31322c332c342c362c322c3135312c322c32302c3231362c3234362c35312c37322c3232362c3230372c3136302c332c302c302c302c312c3135312c3135312c36372c3130312c302c302c302c302c3132382c35382c3231302c35312c34362c33322c302c302c302c302c302c302c302c302c302c302c3132382c3135352c3135322c32322c3233332c302c302c302c302c302c302c302c302c302c302c302c33322c3230352c34382c3136392c33322c35392c302c302c302c302c302c302c302c302c302c302c37342c38312c3232312c3234302c34322c33322c302c302c302c302c302c302c302c302c302c302c3234362c3133382c3130362c3231392c3231352c33312c302c302c302c302c302c302c302c302c302c302c322c3135312c3135312c36372c3130312c302c302c302c302c302c392c37392c3138352c3137312c312c302c302c302c302c302c302c302c302c302c302c39362c33362c3231392c3132322c3130382c392c302c302c302c302c302c302c302c302c302c302c33322c3130392c38332c35332c37342c3234332c312c302c302c302c302c302c302c302c302c302c3138382c36352c34312c3135392c3137312c312c302c302c302c302c302c302c302c302c302c302c34382c39382c3134312c3134322c3137302c312c302c302c302c302c302c302c302c302c302c302c332c3135312c3135312c36372c3130312c302c302c302c302c3232342c34302c3134372c35392c302c302c302c302c302c302c302c302c302c302c302c302c302c3234302c3230362c3130342c3135362c3131302c3137342c302c302c302c302c302c302c302c302c302c302c32382c3232322c3135312c3138362c3230302c38362c372c302c302c302c302c302c302c302c302c38322c38342c3134352c35392c302c302c302c302c302c302c302c302c302c302c302c302c3232302c3233382c3134382c35392c302c302c302c302c302c302c302c302c302c302c302c305d7d7d2c226572726f725f636f6465223a307d";

    #[test]
    fn test_legacy_decode() {
        let _ = simple_logger::init_with_level(log::Level::Debug);

        let decoded =
            FunctionResult::decode(&format!("FN_OUT: {}", EMPTY_ENCODED_FN_RESULT)).unwrap();

        assert_eq!(decoded, FunctionResult::V0(FunctionResultV0::default()));
    }

    #[test]
    fn test_legacy_quote() {
        let _ = simple_logger::init_with_level(log::Level::Debug);

        let mut rng = rand::thread_rng();

        let quote: Vec<u8> = (0..1456).map(|_| rng.gen::<u8>()).collect();
        let fn_key: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();
        let signer: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();

        let legacy = LegacyFunctionResult {
            fn_key: fn_key.clone(),
            version: 1,
            quote: quote.clone(),
            signer: signer.clone(),
            fn_request_key: vec![],
            fn_request_hash: vec![],
            chain_result_info: LegacyChainResultInfo::default(),
            error_code: 1,
        };

        let function_result: FunctionResult = legacy.into();

        // println!("Quote = {:#?}", quote);

        assert_eq!(quote, function_result.quote_bytes().to_vec());
        assert_eq!(fn_key, function_result.fn_key().unwrap());
        assert_eq!(signer, function_result.signer().to_vec());
    }

    #[test]
    fn test_decode() {
        let _ = simple_logger::init_with_level(log::Level::Debug);

        let fr = FunctionResult::default();

        let encoded = format!(
            "FN_OUT: {}",
            hex::encode(serde_json::to_string(&fr).unwrap())
        );
        // println!("Encoded: {:?}", encoded);

        let decoded = FunctionResult::decode(&encoded).unwrap();
        // println!("Decoded: {:?}", decoded);

        assert_eq!(decoded, FunctionResult::default());
    }

    #[test]
    fn test_case_1() {
        let _ = simple_logger::init_with_level(log::Level::Debug);
        let _decoded = FunctionResult::decode(TEST_CASE_1).unwrap();
        // assert!(decoded_result.is_ok())
    }

    #[test]
    fn test_evm_v0_decode() {
        let _ = simple_logger::init_with_level(log::Level::Debug);

        let evm_result = EvmFunctionResultV0::default();
        let fr = FunctionResult::V0(FunctionResultV0 {
            quote: vec![],
            fn_key: vec![],
            signer: vec![],
            fn_request_key: vec![],
            fn_request_hash: vec![],
            chain_result_info: ChainResultInfo::Evm(EvmFunctionResult::V0(evm_result)),
            error_code: 0,
        });

        let encoded = format!(
            "FN_OUT: {}",
            hex::encode(serde_json::to_string(&fr).unwrap())
        );
        // println!("Encoded: {:?}", encoded);

        let decoded = FunctionResult::decode(&encoded).unwrap();
        // println!("Decoded: {:?}", decoded);

        match decoded {
            FunctionResult::V0(FunctionResultV0 {
                chain_result_info:
                    ChainResultInfo::Evm(EvmFunctionResult::V0(decoded_evm_v0_result)),
                ..
            }) => {
                assert_eq!(decoded_evm_v0_result, EvmFunctionResultV0::default());
            }
            _ => panic!("Expected EVMFunctionResultV0"),
        }
    }
}
