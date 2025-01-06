pub mod config;
pub mod contract_service;
pub mod discovery_service;
pub mod operator_service;
// pub mod liveness_service;

use types::{PublicKey, Epoch, Fork};
use eth2::{BeaconNodeHttpClient, Timeouts, types::{ValidatorStatus, ValidatorData, StateId, ValidatorId }};
use sensitive_url::SensitiveUrl;
use std::time::Duration;
use types::ChainSpec;
use safe_arith::SafeArith;
use alloy_primitives::Address;
use slot_clock::SlotClock;
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

/// Get the validator index of a given the validator public key by querying the beacon node endpoint.
///
/// Returns an error if the beacon endpoint returns an error or given validator is not eligible for an exit.
async fn get_validator_index_for_exit(
    client: &BeaconNodeHttpClient,
    validator_pubkey: &PublicKey,
    epoch: Epoch,
    spec: &ChainSpec,
) -> Result<u64, String> {
    let validator_data = get_validator_data(client, validator_pubkey).await?;

    match validator_data.status {
        ValidatorStatus::ActiveOngoing => {
            let eligible_epoch = validator_data
                .validator
                .activation_epoch
                .safe_add(spec.shard_committee_period)
                .map_err(|e| format!("Failed to calculate eligible epoch, validator activation epoch too high: {:?}", e))?;

            if epoch >= eligible_epoch {
                Ok(validator_data.index)
            } else {
                Err(format!(
                    "Validator {:?} is not eligible for exit. It will become eligible on epoch {}",
                    validator_pubkey, eligible_epoch
                ))
            }
        }
        status => Err(format!(
            "Validator {:?} is not eligible for voluntary exit. Validator status: {:?}",
            validator_pubkey, status
        )),
    }
}

/// Returns the validator data by querying the beacon node client.
async fn get_validator_data(
    client: &BeaconNodeHttpClient,
    validator_pubkey: &PublicKey,
) -> Result<ValidatorData, String> {
    Ok(client
        .get_beacon_states_validator_id(
            StateId::Head,
            &ValidatorId::PublicKey(validator_pubkey.into()),
        )
        .await
        .map_err(|e| format!("Failed to get validator details: {:?}", e))?
        .ok_or_else(|| {
            format!(
                "Validator {} is not present in the beacon state. \
                Please ensure that your beacon node is synced and the validator has been deposited.",
                validator_pubkey
            )
        })?
        .data)
}

/// Get fork object for the current state by querying the beacon node client.
async fn get_beacon_state_fork(client: &BeaconNodeHttpClient) -> Result<Fork, String> {
    Ok(client
        .get_beacon_states_fork(StateId::Head)
        .await
        .map_err(|e| {
            format!("Failed to get get fork: {:?}", e)
        })?
        .ok_or(
            "Failed to get fork, state not found".to_string()
        )?
        .data)
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