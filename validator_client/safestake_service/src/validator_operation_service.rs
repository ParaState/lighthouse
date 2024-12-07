use safestake_database::{models::ValidatorOperation, SafeStakeDatabase};
use slog::{Logger, error, info, debug};
use task_executor::TaskExecutor;
use std::path::PathBuf;
use validator_store::ValidatorStore;
use types::EthSpec;
use slot_clock::SlotClock;
use std::sync::Arc;
use account_utils::{
    keystore_share_password_path, default_operator_committee_definition_path,
};
use validator_dir::keystore_share_path;
use types::Address as H160;
use safestake_operator::SafeStakeGraffiti;

pub fn spawn_validator_operation_service<T: SlotClock + 'static, E: EthSpec>(
    logger: Logger,
    operator_id: u32,
    validator_dir: PathBuf,
    secrets_dir: PathBuf,
    validator_store: Arc<ValidatorStore<T, E>>,
    db: SafeStakeDatabase,
    task_executor: &TaskExecutor
) {
    let executor = task_executor.clone();

    let fut = async move {
        tokio::task::spawn_blocking(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(10));
                if let Some(handle) = executor.handle() {
                    if let Some(operations) = db.with_transaction(|txn| {
                        db.handle_validator_operation(txn)
                    }).ok() {
                        for (id, validator_public_key, operation) in operations {
                            let _ = db.with_transaction(|txn| {
                                db.update_validator_operation(txn, id)
                            });
                            match operation {
                                ValidatorOperation::Add => {
                                    let voting_keystore_share_path =
                                    keystore_share_path(&validator_dir, &validator_public_key, operator_id);
                                    let voting_keystore_share_password_path =
                                    keystore_share_password_path(&secrets_dir, &validator_public_key, operator_id);
                                    let committee_def_path = default_operator_committee_definition_path(
                                        &validator_public_key,
                                        &validator_dir,
                                    );
    
                                    let fee_recipient = match db.with_transaction(|t| db.query_validator_fee_recipient(t, &validator_public_key)) {
                                        Ok(a) => a,
                                        Err(e) => {
                                            error!(
                                                logger,
                                                "add validator failed: unkown fee recipient";
                                                "error" => %e
                                            );
                                            continue;
                                        },
                                    };
                                    if let Err(e) = handle.block_on(
                                        validator_store
                                        .add_validator_keystore_share(
                                            voting_keystore_share_path,
                                            voting_keystore_share_password_path,
                                            true,
                                            Some(SafeStakeGraffiti.clone()),
                                            Some(H160::from_slice(fee_recipient.as_slice())),
                                            None,
                                            None,
                                            None,
                                            None,
                                            committee_def_path,
                                            operator_id,
                                        )
                                    ) {
                                        debug!(
                                            logger,
                                            "add validator keystore share";
                                            "error" => %e
                                        );
                                        continue;
                                    }
                                }
                                ValidatorOperation::Remove => {
                                    
                                    handle.block_on(
                                        validator_store
                                        .remove_validator_keystore(
                                            &validator_public_key
                                        )
                                    );
                                }
                                ValidatorOperation::Enable => {
                                    handle.block_on(
                                        validator_store.enable_keystore
                                        (
                                            &validator_public_key
                                        )
                                    );
                                }
                                ValidatorOperation::Disable => {
                                    handle.block_on(
                                        validator_store.disable_keystore
                                        (
                                            &validator_public_key
                                        )
                                    );
                                }
                                ValidatorOperation::Restart => {
                                    handle.block_on(
                                        validator_store.enable_keystore
                                        (
                                            &validator_public_key
                                        )
                                    );
                                    handle.block_on(
                                        validator_store.disable_keystore
                                        (
                                            &validator_public_key
                                        )
                                    );
                                }
                                ValidatorOperation::Unkown => {
                                    error!(
                                        logger,
                                        "unkown validator operation";
                                    );
                                }
                            }
                        }
                    } 
    
                }
                else {
                    info!(
                        logger,
                        "exexutor exit";
                    );
                }
            }
            
        });
    };
    task_executor.spawn(fut, "validator_operation_service");
}