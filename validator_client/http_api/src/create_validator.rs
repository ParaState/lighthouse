use account_utils::validator_definitions::{PasswordStorage, ValidatorDefinition};
use account_utils::{
    eth2_keystore::Keystore,
    eth2_wallet::{bip39::Mnemonic, WalletBuilder},
    random_mnemonic, random_password, ZeroizeString,
};
use eth2::lighthouse_vc::types::{self as api_types};
use slot_clock::SlotClock;
use std::path::{Path, PathBuf};
use types::ChainSpec;
use types::EthSpec;
use validator_dir::{keystore_password_path, Builder as ValidatorDirBuilder};
use validator_store::ValidatorStore;

/// Create some validator EIP-2335 keystores and store them on disk. Then, enroll the validators in
/// this validator client.
///
/// Returns the list of created validators and the mnemonic used to derive them via EIP-2334.
///
/// ## Detail
///
/// If `mnemonic_opt` is not supplied it will be randomly generated and returned in the response.
///
/// If `key_derivation_path_offset` is supplied then the EIP-2334 validator index will start at
/// this point.
pub async fn create_validators_mnemonic<P: AsRef<Path>, T: 'static + SlotClock, E: EthSpec>(
    mnemonic_opt: Option<Mnemonic>,
    key_derivation_path_offset: Option<u32>,
    validator_requests: &[api_types::ValidatorRequest],
    validator_dir: P,
    secrets_dir: Option<PathBuf>,
    validator_store: &ValidatorStore<T, E>,
    spec: &ChainSpec,
) -> Result<(Vec<api_types::CreatedValidator>, Mnemonic), warp::Rejection> {
    let mnemonic = mnemonic_opt.unwrap_or_else(random_mnemonic);

    let wallet_password = random_password();
    let mut wallet =
        WalletBuilder::from_mnemonic(&mnemonic, wallet_password.as_bytes(), String::new())
            .and_then(|builder| builder.build())
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "unable to create EIP-2386 wallet: {:?}",
                    e
                ))
            })?;

    if let Some(nextaccount) = key_derivation_path_offset {
        wallet.set_nextaccount(nextaccount).map_err(|e| {
            warp_utils::reject::custom_server_error(format!(
                "unable to set wallet nextaccount: {:?}",
                e
            ))
        })?;
    }

    let mut validators = Vec::with_capacity(validator_requests.len());

    for request in validator_requests {
        let voting_password = random_password();
        let withdrawal_password = random_password();
        let voting_password_string = ZeroizeString::from(
            String::from_utf8(voting_password.as_bytes().to_vec()).map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "locally generated password is not utf8: {:?}",
                    e
                ))
            })?,
        );

        let mut keystores = wallet
            .next_validator(
                wallet_password.as_bytes(),
                voting_password.as_bytes(),
                withdrawal_password.as_bytes(),
            )
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "unable to create validator keys: {:?}",
                    e
                ))
            })?;

        keystores
            .voting
            .set_description(request.description.clone());
        keystores
            .withdrawal
            .set_description(request.description.clone());

        let voting_pubkey = format!("0x{}", keystores.voting.pubkey())
            .parse()
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "created invalid public key: {:?}",
                    e
                ))
            })?;

        let voting_password_storage =
            get_voting_password_storage(&secrets_dir, &keystores.voting, &voting_password_string)?;

        let validator_dir = ValidatorDirBuilder::new(validator_dir.as_ref().into())
            .password_dir_opt(secrets_dir.clone())
            .voting_keystore(keystores.voting, voting_password.as_bytes())
            .withdrawal_keystore(keystores.withdrawal, withdrawal_password.as_bytes())
            .create_eth1_tx_data(request.deposit_gwei, spec)
            .store_withdrawal_keystore(false)
            .build()
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "failed to build validator directory: {:?}",
                    e
                ))
            })?;

        let eth1_deposit_data = validator_dir
            .eth1_deposit_data()
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "failed to read local deposit data: {:?}",
                    e
                ))
            })?
            .ok_or_else(|| {
                warp_utils::reject::custom_server_error(
                    "failed to create local deposit data: {:?}".to_string(),
                )
            })?;

        if eth1_deposit_data.deposit_data.amount != request.deposit_gwei {
            return Err(warp_utils::reject::custom_server_error(format!(
                "invalid deposit_gwei {}, expected {}",
                eth1_deposit_data.deposit_data.amount, request.deposit_gwei
            )));
        }

        // Drop validator dir so that `add_validator_keystore` can re-lock the keystore.
        let voting_keystore_path = validator_dir.voting_keystore_path();
        drop(validator_dir);

        validator_store
            .add_validator_keystore(
                voting_keystore_path,
                voting_password_storage,
                request.enable,
                request.graffiti.clone(),
                request.suggested_fee_recipient,
                request.gas_limit,
                request.builder_proposals,
                request.builder_boost_factor,
                request.prefer_builder_proposals,
            )
            .await
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "failed to initialize validator: {:?}",
                    e
                ))
            })?;

        validators.push(api_types::CreatedValidator {
            enabled: request.enable,
            description: request.description.clone(),
            graffiti: request.graffiti.clone(),
            suggested_fee_recipient: request.suggested_fee_recipient,
            gas_limit: request.gas_limit,
            builder_proposals: request.builder_proposals,
            voting_pubkey,
            eth1_deposit_tx_data: serde_utils::hex::encode(&eth1_deposit_data.rlp),
            deposit_gwei: request.deposit_gwei,
        });
    }

    Ok((validators, mnemonic))
}

pub async fn create_validators_web3signer<T: 'static + SlotClock, E: EthSpec>(
    validators: Vec<ValidatorDefinition>,
    validator_store: &ValidatorStore<T, E>,
) -> Result<(), warp::Rejection> {
    for validator in validators {
        validator_store
            .add_validator(validator)
            .await
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "failed to initialize validator: {:?}",
                    e
                ))
            })?;
    }

    Ok(())
}

/// Attempts to return a `PasswordStorage::File` if `secrets_dir` is defined.
/// Otherwise, returns a `PasswordStorage::ValidatorDefinitions`.
pub fn get_voting_password_storage(
    secrets_dir: &Option<PathBuf>,
    voting_keystore: &Keystore,
    voting_password_string: &ZeroizeString,
) -> Result<PasswordStorage, warp::Rejection> {
    if let Some(secrets_dir) = &secrets_dir {
        let password_path = keystore_password_path(secrets_dir, voting_keystore);
        if password_path.exists() {
            Err(warp_utils::reject::custom_server_error(
                "Duplicate keystore password path".to_string(),
            ))
        } else {
            Ok(PasswordStorage::File(password_path))
        }
    } else {
        Ok(PasswordStorage::ValidatorDefinitions(
            voting_password_string.clone(),
        ))
    }
}
