use serde::{Deserialize, Serialize};
use slog::{Logger, info};
use url::Url;
use reqwest::{Client, Error};
use std::time::Duration;
use safestake_crypto::secp::{SecretKey, Signature, Digest};
use keccak_hash::keccak;
use crate::config::Config;
use task_executor::TaskExecutor;
use crate::http_metrics::metrics;
use dvf_utils::SOFTWARE_VERSION;
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

#[derive(Debug, Serialize)]
pub struct DvfStatusReportRequest {
    #[serde(rename = "operatorId")]
    pub operator_id: u32,
    pub address: String,
    #[serde(rename = "validatorEnabled")]
    pub validator_enabled: usize,
    #[serde(rename = "validatorTotal")]
    pub validator_total: usize,
    #[serde(rename = "signedBlocks")]
    pub signed_blocks: usize,
    #[serde(rename = "signedAttestation")]
    pub signed_attestation: usize,
    pub version: usize,
    #[serde(rename = "connectedNodes")]
    pub connected_nodes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_hex: Option<String>,
}

impl SignDigest for DvfStatusReportRequest {}


pub trait SignDigest {
    fn sign_digest(&self, secret: &SecretKey) -> Result<String, String>
    where
        Self: Serialize,
    {
        let ser_json =
            serde_json::to_string(self).map_err(|e| format!("failed to serialize {:?}", e))?;
        let digest = keccak(ser_json.as_bytes());
        let sig = Signature::new(&Digest::from(&digest.0), secret).map_err(|e| {
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

pub fn status_report(config: Config, logger: Logger, exexutor: &TaskExecutor) {
    exexutor.spawn( async move {
        let mut report_interval = tokio::time::interval(Duration::from_secs(60 * 5));
        loop {
            report_interval.tick().await;
            let mut report_body = DvfStatusReportRequest {
                operator_id: config.operator_id,
                address: config.ip.to_string(),
                validator_enabled: metrics::ENABLED_VALIDATORS_COUNT.as_ref().unwrap().get() as usize,
                validator_total: metrics::TOTAL_VALIDATORS_COUNT.as_ref().unwrap().get() as usize,
                signed_blocks: metrics::SIGNED_BLOCKS_TOTAL.as_ref().unwrap().get_metric_with_label_values(&[metrics::SUCCESS]).unwrap().get() as usize,
                signed_attestation: metrics::SIGNED_ATTESTATIONS_TOTAL.as_ref().unwrap().get_metric_with_label_values(&[metrics::SUCCESS]).unwrap().get() as usize,
                version: SOFTWARE_VERSION as usize,
                connected_nodes: 0,
                sign_hex: None,
            };
            report_body.sign_hex = Some(report_body.sign_digest(&config.node_secret.secret).unwrap());
            let url_str = format!("{}{}", config.safestake_api, "collect_performance");
            info!(
                logger,
                "status_report";
                "report" => format!("{:?}", report_body)
            );
            let _ = request_to_api(report_body, &url_str).await;
        }
    }, "status_report");
}