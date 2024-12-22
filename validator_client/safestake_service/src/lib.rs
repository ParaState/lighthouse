pub mod config;
pub mod contract_service;
pub mod discovery_service;
pub mod operator_service;

use eth2::{BeaconNodeHttpClient, Timeouts};
use sensitive_url::SensitiveUrl;
use std::{io::Read, time::Duration};
use types::{ChainSpec, DepositData, EthSpec, SignedRoot};
use alloy_primitives::Address;
/// Gets syncing status from beacon node client and returns true if syncing and false otherwise.
async fn is_syncing(client: &BeaconNodeHttpClient) -> Result<bool, String> {
    Ok(client
        .get_node_syncing()
        .await
        .map_err(|e| format!("Failed to get sync status: {:?}", e))?
        .data
        .is_syncing)
}

pub async fn get_valid_beacon_node_http_client(
    beacon_nodes_urls: &Vec<SensitiveUrl>,
    spec: &ChainSpec,
) -> Result<BeaconNodeHttpClient, String> {
    for i in 0..beacon_nodes_urls.len() {
        let client = BeaconNodeHttpClient::new(
            beacon_nodes_urls[i].clone(),
            Timeouts::set_all(Duration::from_secs(spec.seconds_per_slot)),
        );
        match is_syncing(&client).await {
            Ok(b) => {
                if b {
                    return Err("beacon node is syncing!".to_string())
                } else {
                    return Ok(client);
                }
            }
            Err(e) => {
                return Err(format!("Failed to get sync status {}", e));
            }
        }
    }
    return Err("invalid beacon nodes".to_string());
}

pub fn convert_address_to_withdraw_crendentials(address: Address) -> [u8; 32] {
    let mut credentials = [0; 32];
    credentials[0] = 0x01;
    let address_bytes = address.as_slice();
    for i in 12..32 {
        credentials[i] = address_bytes[i - 12];
    }
    credentials
}