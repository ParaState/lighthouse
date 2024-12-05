use super::models::{Operator, Validator};
use alloy_primitives::Address;
use bls::PublicKey;
use filesystem::restrict_file_permissions;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Transaction};
use safestake_crypto::secp::PublicKey as SecpPublicKey;
use slashing_protection::NotSafe;
use std::fs::File;
use std::time::Duration;
use std::{path::Path, str::FromStr};
type Pool = r2d2::Pool<SqliteConnectionManager>;
use std::net::SocketAddr;
/// We set the pool size to 1 for compatibility with locking_mode=EXCLUSIVE.
///
/// This is perhaps overkill in the presence of exclusive transactions, but has
/// the added bonus of preventing other processes from trying to use our slashing database.
pub const POOL_SIZE: u32 = 1;
#[cfg(not(test))]
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub struct SafeStakeDatabase {
    conn_pool: Pool,
}

impl SafeStakeDatabase {
    /// Open an existing database at the given `path`, or create one if none exists.
    pub fn open_or_create(path: &Path) -> Result<Self, NotSafe> {
        if path.exists() {
            Self::open(path)
        } else {
            Self::create(path)
        }
    }

    /// Open an existing `SafeStakeDatabase` from disk.
    ///
    /// This will automatically check for and apply the latest schema migrations.
    pub fn open(path: &Path) -> Result<Self, NotSafe> {
        let conn_pool = Self::open_conn_pool(path)?;
        let db = Self { conn_pool };
        Ok(db)
    }

    /// Execute a database transaction as a closure, committing if `f` returns `Ok`.
    pub fn with_transaction<T, U, F>(&self, f: F) -> Result<T, U>
    where
        F: FnOnce(&Transaction) -> Result<T, U>,
        U: From<NotSafe>,
    {
        let mut conn = self.conn_pool.get().map_err(NotSafe::from)?;
        let txn = conn.transaction().map_err(NotSafe::from)?;
        let value = f(&txn)?;
        txn.commit().map_err(NotSafe::from)?;
        Ok(value)
    }

    /// Create a safestake database at the given path.
    ///
    /// Error if a database (or any file) already exists at `path`.
    pub fn create(path: &Path) -> Result<Self, NotSafe> {
        let _file = File::options()
            .write(true)
            .read(true)
            .create_new(true)
            .open(path)?;

        restrict_file_permissions(path).map_err(|_| NotSafe::PermissionsError)?;
        let conn_pool = Self::open_conn_pool(path)?;
        let mut conn = conn_pool.get()?;

        conn.execute(
            "CREATE TABLE validators (
                public_key CHARACTER(96) PRIMARY KEY NOT NULL UNIQUE,
                owner_address CHARACTER(40) NOT NULL,
                registration_timestamp INTEGER NOT NULL,
                active INTEGER DEFAULT 1 NOT NULL
            )",
            params![],
        )?;

        conn.execute(
            "CREATE TABLE operators (
                id INTEGER PRIMARY KEY, 
                name VARCHAR(100) NOT NULL, 
                address CHARACTER(40) NOT NULL, 
                public_key VARCHAR(100) NOT NULL
            )",
            params![],
        )?;

        conn.execute(
            "CREATE TABLE validator_operators_mapping(
                id INTEGER NOT NULL  PRIMARY KEY AUTOINCREMENT,
                validator_public_key CHARACTER(96) NOT NULL, 
                operator_id INTEGER NOT NULL,
                CONSTRAINT validator_select_operators_1 FOREIGN KEY (validator_public_key) REFERENCES validators(public_key) ON DELETE CASCADE,
                CONSTRAINT validator_select_operators_2 FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE
            )",
            params![],
        )?;

        conn.execute(
            "CREATE TABLE operator_socket_address(
                public_key VARCHAR(100) NOT NULL PRIMARY KEY,
                socket_address VARCHAR(30) NOT NULL,
                seq INTEGER NOT NULL
            )",
            params![],
        )?;

        conn.execute(
            "CREATE TABLE owner_fee_recipient(
                owner CHARACTER(40) NOT NULL PRIMARY KEY,
                fee_recipient CHARACTER(40) NOT NULL
            )",
            params![],
        )?;

        // The tables created above are for the v0 schema. We immediately update them
        // to the latest schema without dropping the connection.
        let txn = conn.transaction()?;
        txn.commit()?;

        Ok(Self { conn_pool })
    }

    /// Open a new connection pool with all of the necessary settings and tweaks.
    fn open_conn_pool(path: &Path) -> Result<Pool, NotSafe> {
        let manager = SqliteConnectionManager::file(path)
            .with_flags(rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
            .with_init(Self::apply_pragmas);
        let conn_pool = Pool::builder()
            .max_size(POOL_SIZE)
            .connection_timeout(CONNECTION_TIMEOUT)
            .build(manager)
            .map_err(|e| NotSafe::SQLError(format!("Unable to open database: {:?}", e)))?;
        Ok(conn_pool)
    }

    /// Apply the necessary settings to an SQLite connection.
    ///
    /// Most importantly, put the database into exclusive locking mode, so that threads are forced
    /// to serialise all DB access (to prevent slashable data being checked and signed in parallel).
    /// The exclusive locking mode also has the benefit of applying to other processes, so multiple
    /// Lighthouse processes trying to access the same database will also be blocked.
    fn apply_pragmas(conn: &mut rusqlite::Connection) -> Result<(), rusqlite::Error> {
        conn.pragma_update(None, "foreign_keys", true)?;
        conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
        Ok(())
    }

    pub fn insert_operator(&self, txn: &Transaction, op: &Operator) -> Result<(), NotSafe> {
        let mut stmt = txn.prepare("SELECT id FROM operators where id = ?1")?;
        match stmt.query_row(params![op.id], |_| Ok(())) {
            Ok(_) => return Ok(()),
            Err(_) => {}
        }
        let mut stmt = txn.prepare(
            "INSERT INTO operators(id, name, address, public_key) values (?1, ?2, ?3, ?4)",
        )?;
        stmt.execute([
            op.id.to_string(),
            op.name.clone(),
            op.owner.to_string(),
            op.public_key.base64(),
        ])?;
        Ok(())
    }

    pub fn insert_validator(&self, txn: &Transaction, va: &Validator) -> Result<(), NotSafe> {
        txn.execute("INSERT INTO validators(public_key, owner_address, registration_timestamp) values(?1, ?2, ?3)", params![va.public_key.as_hex_string(), va.owner.to_string(), va.registration_timestamp.to_string()])?;
        for operator_id in &va.releated_operators {
            txn.execute("INSERT INTO validator_operators_mapping(validator_public_key, operator_id) values(?1, ?2)", params![va.public_key.as_hex_string(), operator_id])?;
        }
        Ok(())
    }

    pub fn update_validator_registration_timestamp(
        &self,
        txn: &Transaction,
        validator_public_key: &PublicKey,
        registration_timestamp: u64,
    ) -> Result<(), NotSafe> {
        txn.execute(
            "UPDATE validators set registration_timestamp = ?1 where public_key = ?2",
            params![
                validator_public_key.to_string(),
                registration_timestamp.to_string()
            ],
        )?;
        Ok(())
    }

    pub fn delete_validator(
        &self,
        txn: &Transaction,
        validator_public_key: &PublicKey,
    ) -> Result<(), NotSafe> {
        txn.execute(
            "DELETE FROM validators WHERE public_key = ?1",
            params![validator_public_key.as_hex_string()],
        )?;
        Ok(())
    }

    pub fn upsert_owner_fee_recipient(
        &self,
        txn: &Transaction,
        owner: Address,
        fee_recipient: Address,
    ) -> Result<(), NotSafe> {
        txn.execute("insert into owner_fee_recipient(owner, fee_recipient) values(?1, ?2) ON conflict(owner) do update set fee_recipient = (?3)", params![owner.to_string(), fee_recipient.to_string(), fee_recipient.to_string()])?;
        Ok(())
    }

    pub fn upsert_operator_socket_address(
        &self,
        txn: &Transaction,
        operator_public_key: &SecpPublicKey,
        socket_address: &SocketAddr,
        seq: u64,
    ) -> Result<(), NotSafe> {
        txn.execute("INSERT INTO operator_socket_address (public_key, socket_address, seq) VALUES (?1, ?2, ?3) ON CONFLICT (public_key) DO UPDATE SET socket_address = ?2, seq = ?3", params![operator_public_key.base64(), socket_address.to_string(), seq.to_string()])?;
        Ok(())
    }

    pub fn query_operator_socket_address(
        &self,
        txn: &Transaction,
        operator_public_key: &SecpPublicKey,
    ) -> Result<SocketAddr, NotSafe> {
        let mut stmt = txn
            .prepare("SELECT socket_address from operator_socket_address where public_key = ?1")?;
        Ok(
            stmt.query_row(params![operator_public_key.base64()], |row| {
                let socket_address: String = row.get(0).unwrap();
                Ok(SocketAddr::from_str(&socket_address).unwrap())
            })?,
        )
    }

    pub fn query_operator_seq(
        &self,
        txn: &Transaction,
        operator_public_key: &SecpPublicKey,
    ) -> Result<u64, NotSafe> {
        let mut stmt =
            txn.prepare("SELECT seq from operator_socket_address where public_key = ?1")?;
        Ok(
            stmt.query_row(params![operator_public_key.base64()], |row| {
                let seq: u64 = row.get(0).unwrap();
                Ok(seq)
            })?,
        )
    }

    pub fn query_owner_fee_recipient(
        &self,
        txn: &Transaction,
        owner: &Address,
    ) -> Result<Address, NotSafe> {
        let mut stmt =
            txn.prepare("SELECT fee_recipient from owner_fee_recipient where owner = ?1")?;
        Ok(stmt.query_row(params![owner.to_string()], |row| {
            let fee_recipient: String = row.get(0).unwrap();
            Ok(Address::from_str(&fee_recipient).unwrap())
        })?)
    }

    pub fn query_validator_fee_recipient(
        &self,
        txn: &Transaction,
        validator_public_key: &PublicKey,
    ) -> Result<Address, NotSafe> {
        let mut stmt = txn.prepare("select owner_fee_recipient.fee_recipient from validators join owner_fee_recipient on validators.owner_address = owner_fee_recipient.owner where validators.public_key = ?1")?;
        match stmt.query_row(params![validator_public_key.as_hex_string()], |row| {
            let fee_recipient: String = row.get(0).unwrap();
            Ok(Address::from_str(&fee_recipient).unwrap())
        }) {
            Ok(f) => Ok(f),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                let fee_recipient = txn.query_row(
                    "SELECT owner_address from validators where public_key = ?1",
                    params![validator_public_key.as_hex_string()],
                    |row| {
                        let fee_recipient: String = row.get(0).unwrap();
                        Ok(Address::from_str(&fee_recipient).unwrap())
                    },
                )?;
                Ok(fee_recipient)
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn query_all_validators(&self, txn: &Transaction) -> Result<Vec<PublicKey>, NotSafe> {
        txn.prepare("select public_key from validators")?
            .query_and_then(params![], |row| {
                let public_key: String = row.get(0).unwrap();
                Ok(PublicKey::from_str(&public_key).unwrap())
            })?
            .collect()
    }

    pub fn query_validator_public_keys_by_owner(
        &self,
        txn: &Transaction,
        owner: Address,
    ) -> Result<Vec<PublicKey>, NotSafe> {
        txn.prepare("select public_key from validators where owner_address = ?1")?
            .query_and_then(params![owner.to_string()], |row| {
                let public_key: String = row.get(0).unwrap();
                Ok(PublicKey::from_str(&public_key).unwrap())
            })?
            .collect()
    }

    pub fn query_validators_using_operator(
        &self,
        txn: &Transaction,
        operator_id: u32,
    ) -> Result<Vec<PublicKey>, NotSafe> {
        txn.prepare(
            "select validator_public_key from validator_operators_mapping where operator_id =?1",
        )?
        .query_and_then(params![operator_id], |row| {
            let public_key: String = row.get(0).unwrap();
            Ok(PublicKey::from_str(&public_key).unwrap())
        })?
        .collect()
    }

    pub fn query_validator_registration_timestamp(
        &self,
        txn: &Transaction,
        validator_public_key: &PublicKey,
    ) -> Result<u64, NotSafe> {
        Ok(txn
            .prepare("select registration_timestamp from validators where public_key = ?1")?
            .query_row(params![validator_public_key.as_hex_string()], |row| {
                let registration_timestamp: u64 = row.get(0).unwrap();
                Ok(registration_timestamp)
            })?)
    }

    pub fn query_operator_public_key(
        &self,
        txn: &Transaction,
        operator_id: u32,
    ) -> Result<Option<SecpPublicKey>, NotSafe> {
        let mut stmt = txn.prepare("SELECT public_key from operators where id = ?1")?;
        Ok(stmt.query_row(params![operator_id.to_string()], |row| {
            let public_key: String = row.get(0).unwrap();
            Ok(Some(SecpPublicKey::from_base64(&public_key).unwrap()))
        })?)
    }
}
