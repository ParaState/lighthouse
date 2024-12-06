use alloy_primitives::Address;
use safestake_crypto::secp::PublicKey;
use safestake_database::SafeStakeDatabase;
use safestake_database::models::{Operator, Validator};
use std::fs::remove_file;
use types::test_utils::TestRandom;
use types::PublicKey as BlsPublicKey;
#[test]
fn test_safestake_database() {
    remove_file("/tmp/safestake.sqlite").unwrap();
    let db =
        SafeStakeDatabase::open_or_create(std::path::Path::new("/tmp/safestake.sqlite")).unwrap();
    let _ = db.with_transaction(|tx| {
        for i in 0..4 {
            db.insert_operator(
                tx,
                &Operator {
                    id: i,
                    name: i.to_string(),
                    owner: Address::random(),
                    public_key: PublicKey::default(),
                },
            )
            .unwrap();
        }

        let validator_owner = Address::random();
        let mut rng = rand::thread_rng();
        let validator_public_key = BlsPublicKey::random_for_test(&mut rng);
        db.insert_validator(
            tx,
            &Validator {
                owner: validator_owner.clone(),
                public_key: validator_public_key.clone(),
                releated_operators: vec![0, 1, 2, 3],
                active: true,
                registration_timestamp: 1789799879,
            },
        )
        .unwrap();

        let f = db
            .query_validator_fee_recipient(tx, &validator_public_key)
            .unwrap();
        assert_eq!(f, validator_owner);
        let fee_recipient = Address::random();
        db.upsert_owner_fee_recipient(tx, validator_owner, fee_recipient)
            .unwrap();
        let f = db
            .query_validator_fee_recipient(tx, &validator_public_key)
            .unwrap();
        assert_eq!(f, fee_recipient);
        db.query_all_validators(tx)
    });
}

#[test]
fn test_safestake_database_socket_address() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    let _ = remove_file("/tmp/safestake.sqlite");
    let db =
        SafeStakeDatabase::open_or_create(std::path::Path::new("/tmp/safestake.sqlite")).unwrap();

    let _ = db.with_transaction(|tx| {
        let _ = db.upsert_operator_socket_address(
            tx,
            &PublicKey([0; 33]),
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            1,
        );
        db.upsert_operator_socket_address(
            tx,
            &PublicKey([0; 33]),
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            1,
        )
    });
}
