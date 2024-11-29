use r2d2_sqlite::SqliteConnectionManager;
use std::path::Path;
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use slashing_protection::NotSafe;
use std::fs::File;
use std::time::Duration;
use filesystem::restrict_file_permissions;
use alloy_primitives::Address;
use super::models::{Operator, Validator};
use safestake_crypto::secp::PublicKey;
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
                public_key VARCHAR(100) NOT NULL,
                socket_address VARCHAR(30) NOT NULL,
                seq INTEGER NOT NULL
            )", 
            params![]
        )?;

        conn.execute(
            "CREATE TABLE owner_fee_recipient(
                owner CHARACTER(40) NOT NULL PRIMARY KEY,
                fee_recipient CHARACTER(40) NOT NULL
            )",
            params![]
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

    pub fn insert_operator(
        &self, 
        txn: &Transaction,
        op: &Operator
    ) -> Result<(), NotSafe> {
        let mut stmt = txn.prepare("SELECT id FROM operators where id = ?1")?;
        let rows = stmt.query(params![op.id]).optional()?;
        if rows.is_some() {
            return Ok(());
        }
        let mut stmt =
            txn.prepare("INSERT INTO operators(id, name, address, public_key) values (?1, ?2, ?3, ?4)")?;
        stmt.execute([op.id.to_string(), op.name.clone(), op.owner.to_string(), op.public_key.base64()])?;
        Ok(())
    }

    pub fn insert_validator(
        &self,
        txn: &Transaction,
        va: &Validator
    ) -> Result<(), NotSafe> {
        txn.execute("INSERT INTO validators(public_key, owner_address, registration_timestamp) values(?1, ?2, ?3", params![va.public_key.as_hex_string(), va.owner.to_string(), va.registration_timestamp.to_string()])?;
        for operator_id in &va.releated_operators {
            txn.execute("INSERT INTO validator_operators_mapping(validator_public_key, operator_id) values(?1, ?2)", params![va.public_key.as_hex_string(), operator_id])?;
        }
        Ok(())
    }

    pub fn upsert_owner_fee_recipient(
        &self,
        txn: &Transaction,
        owner: Address, 
        fee_recipient: Address
    ) -> Result<(), NotSafe> {
        txn.execute("insert into owner_fee_recipient(owner, fee_recipient) values(?1, ?2) ON conflict(owner) do update set fee_recipient = (?3)", params![owner.to_string(), fee_recipient.to_string(), fee_recipient.to_string()])?;
        Ok(())
    }

    pub fn upsert_operator_socket_address(
        &self,
        txn: &Transaction,
        operator_public_key: &PublicKey,
        socket_address: &SocketAddr,
        seq: u64
    ) -> Result<(), NotSafe> {
        

        Ok(())
    }
}