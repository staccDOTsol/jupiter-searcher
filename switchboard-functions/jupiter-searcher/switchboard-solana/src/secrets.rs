use crate::*;
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use rand::rngs::OsRng;
use rsa::{pkcs8::ToPublicKey, PaddingScheme, RsaPrivateKey, RsaPublicKey};
use serde::Deserialize;
use serde_json;
use serde_json::json;
use std::collections::HashMap;
use std::result::Result;

#[derive(Debug, Deserialize)]
pub struct Secrets {
    pub keys: HashMap<String, String>,
}

/// Represents encrypted data containing a key, nonce, and data.
///
/// This structure holds information necessary for decrypting an AES-encrypted payload.
#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
struct EncryptedSecretsData {
    /// A base64 encoded string containing the key used to decrypt the `data`.
    ///
    /// This key is itself encrypted with the request's public key and can be decrypted using the
    /// corresponding private key.
    key: String,
    /// An AES nonce needed to decrypt the `data`.
    ///
    /// This value is used alongside the key to ensure secure decryption.
    nonce: String,
    /// The response payload that has been encrypted with AES.
    ///
    /// This data can be of any type, but using a binary format is recommended for efficiency.
    data: String,
}

fn handle_reqwest_err(e: reqwest::Error) -> SbError {
    let status = e.status().unwrap_or(reqwest::StatusCode::default());
    SbError::CustomError {
        message: format!(
            "reqwest_error: code = {}, message = {}",
            status,
            status.canonical_reason().unwrap_or("Unknown")
        ),
        source: std::sync::Arc::new(e),
    }
}

/// `fetch_secrets`: to be used in conjunction with the Switchboard Secrets Server stack.
///
/// When hosting your own secrets server, you may list the MR_ENCLAVE of the
/// functions you wish to reveal your secrets to.  This will only ever expose
/// your secrets to your code. Unless exported in your code, no chain or oracle
/// will be able to view these secrets:
///
/// # Relevant Materials:
/// - [Secret Server Github Repository](https://github.com/switchboard-xyz/secrets-server)
///
/// # Parameters:
/// - `fn_authority`: the authority of the function you wish to retrieve secrets for
/// - `url`: the url or ip address of the secrets server to use. If none are provided, the default
///   behavior will be to use Switchboard's hosted https://api.secrets.switchboard.xyz.
///
/// # Returns
/// - `Map<String, String>`: The key-value store of your secrets.
pub async fn fetch_secrets(fn_authority: &str, url: Option<&str>) -> Result<Secrets, SbError> {
    // Unwrap the user-provided URL for a self-hosted secrets server, or default to
    // https://api.secrets.switchboard.xyz.
    let secrets_server_url = match url {
        Some(value) => value,
        None => "https://api.secrets.switchboard.xyz/",
    };

    // Generate quote for secure request with user's public key
    let mut os_rng = OsRng::default();
    let priv_key = RsaPrivateKey::new(&mut os_rng, 2048).map_err(|_| SbError::KeyParseError)?;
    let pub_key = RsaPublicKey::from(&priv_key)
        .to_public_key_der()
        .map_err(|_| SbError::KeyParseError)?;
    // The quote is generated around the public encryption key so that the server can validate
    // that the request has not been tampered with.
    let secrets_quote = Gramine::generate_quote(pub_key.as_ref()).map_err(|_| SbError::SgxError)?;
    // Build and send request to fetch encrypted secrets
    let payload = json!({
        "user_pubkey": fn_authority,
        "ciphersuite": "ed25519",
        "encryption_key": pub_key.to_pem().as_str(),
        "quote": &secrets_quote,
    });
    let response = reqwest::Client::new()
        .post(secrets_server_url)
        .json(&payload)
        .send()
        .await
        .map_err(handle_reqwest_err)?
        .error_for_status()
        .map_err(handle_reqwest_err)?;
    let encrypted_data = response
        .json::<EncryptedSecretsData>()
        .await
        .map_err(handle_reqwest_err)?;

    // First we need to decode and decrypt the encryption key.
    let key = match base64::decode(encrypted_data.key) {
        Ok(value) => value,
        Err(err) => {
            let error_msg = format!("Base64DecodeError: {:#?}", err);
            return Err(SbError::CustomMessage(error_msg));
        }
    };
    let key = match priv_key.decrypt(PaddingScheme::PKCS1v15Encrypt, &key) {
        Ok(value) => Key::<Aes256Gcm>::clone_from_slice(&value),
        Err(err) => {
            let error_msg = format!("DecryptKeyError: {:#?}", err);
            return Err(SbError::CustomMessage(error_msg));
        }
    };
    // Second we need to decode the nonce value from the encrypted data.
    let nonce = match base64::decode(encrypted_data.nonce) {
        Ok(value) => Nonce::clone_from_slice(&value),
        Err(err) => {
            let error_msg = format!("Base64DecodeError: {:#?}", err);
            return Err(SbError::CustomMessage(error_msg));
        }
    };
    // Lastly, we can use our decrypted key and nonce values to decode and decrypt the payload.
    let data = match base64::decode(encrypted_data.data) {
        Ok(value) => value,
        Err(err) => {
            let error_msg = format!("Base64DecodeError: {:#?}", err);
            return Err(SbError::CustomMessage(error_msg));
        }
    };
    let data = match Aes256Gcm::new(&key).decrypt(&nonce, data.as_ref()) {
        Ok(value) => value,
        Err(err) => {
            let error_msg = format!("Aes256GcmError: {:#?}", err);
            return Err(SbError::CustomMessage(error_msg));
        }
    };

    // The data can be parsed into a hashmap and returned.
    let keys: HashMap<String, String> = serde_json::from_slice(&data)?;
    Ok(Secrets { keys })
}
