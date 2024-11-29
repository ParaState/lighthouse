use serde::{Deserialize, Serialize};
use url::Url;
use reqwest::{Client, Error};
use std::{fs::File, time::Duration};
use safestake_crypto::secp::{SecretKey, Signature, Digest};
use keccak_hash::keccak;
#[derive(Debug, PartialEq, Serialize)]
pub struct DvfPerformanceRequest {
    #[serde(rename = "publicKey")]
    pub validator_pk: String,
    #[serde(rename = "operatorId")]
    pub operator_id: u32,
    pub operators: Vec<u64>,
    pub slot: u64,
    pub epoch: u64,
    pub duty: String,
    pub time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_hex: Option<String>,
}

impl SignDigest for DvfPerformanceRequest {}

pub trait SignDigest {
    fn sign_digest(&self, secret: &SecretKey) -> Result<String, String>
    where
        Self: Serialize,
    {
        let ser_json =
            serde_json::to_string(self).map_err(|e| format!("failed to serialize {:?}", e))?;
        let digest = keccak(ser_json.as_bytes());
        let sig = Signature::new(&Digest::from(digest.as_fixed_bytes()), secret).map_err(|e| {
            format!("failed to sign {:?}", e)
        })?;
        Ok(hex::encode(sig.flatten()))
    }
}

#[derive(Deserialize, Serialize, Debug)]
struct ApiResponse {
    code: usize,
    message: String,
}

pub async fn request_to_api<T: Serialize>(body: T, url_str: &str) -> Result<(), String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let url = Url::parse(url_str).map_err(|_e| format!("Can't parse url {}", url_str))?;
    for _ in 0..3 {
        match client.post(url.clone()).json(&body).send().await {
            Ok(result) => {
                let response: Result<ApiResponse, Error> = result.json().await;
                match response {
                    Ok(res) => {
                        if res.code == 200 {
                            break;
                        }
                    }
                    Err(_) => {}
                }
            }
            Err(_) => {}
        };
    }
    Ok(())
}