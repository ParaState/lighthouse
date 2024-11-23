use eth2_keystore::PlainText;
use eth2_keystore_share::KeystoreShare;
use std::path::{Path, PathBuf};
use crate::{BuilderError, ValidatorDir, write_password_to_file};
use std::fs::{create_dir_all, File};

pub const VOTING_KEYSTORE_SHARE_FILE: &str = "voting-keystore-share.json";

/// A builder for creating a `ValidatorDir` that stores a share of a voting keystore.
pub struct ShareBuilder {
    base_validators_dir: PathBuf,
    password_dir: Option<PathBuf>,
    pub(crate) voting_keystore_share: Option<(KeystoreShare, PlainText)>,
}

impl ShareBuilder {
    /// Instantiate a new builder.
    pub fn new(base_validators_dir: PathBuf) -> Self {
        Self {
            base_validators_dir,
            password_dir: None,
            voting_keystore_share: None,
        }
    }

    /// Supply a directory in which to store the passwords for the validator keystores.
    pub fn password_dir<P: Into<PathBuf>>(mut self, password_dir: P) -> Self {
        self.password_dir = Some(password_dir.into());
        self
    }

    /// Build the `ValidatorDir` use the given `keystore` which can be unlocked with `password`.
    ///
    /// The builder will not necessarily check that `password` can unlock `keystore`.
    pub fn voting_keystore_share(mut self, keystore_share: KeystoreShare, password: &[u8]) -> Self {
        self.voting_keystore_share = Some((keystore_share, password.to_vec().into()));
        self
    }

    /// Return the path to the validator dir to be built, i.e. `base_dir/pubkey/operator_id`.
    pub fn get_dir_path(
        base_validators_dir: &Path,
        voting_keystore_share: &KeystoreShare,
    ) -> PathBuf {
        default_keystore_share_dir(voting_keystore_share, base_validators_dir)
    }

    /// Consumes `self`, returning a `ValidatorDir` if no error is encountered.
    pub fn build(self) -> Result<ValidatorDir, BuilderError> {
        let (voting_keystore_share, voting_password) = self
            .voting_keystore_share
            .ok_or(BuilderError::UninitializedVotingKeystore)?;

        let keystore_share_dir =
            default_keystore_share_dir(&voting_keystore_share, self.base_validators_dir.clone());

        if keystore_share_dir.exists() {
            return Err(BuilderError::DirectoryAlreadyExists(keystore_share_dir));
        } else {
            create_dir_all(&keystore_share_dir).map_err(BuilderError::UnableToCreateDir)?;
        }

        if let Some(password_dir) = self.password_dir.as_ref() {
            // Write the voting password to file.
            write_password_to_file(
                keystore_share_password_path(&password_dir, &voting_keystore_share),
                voting_password.as_bytes(),
            )?;
        }

        // Write the voting keystore share to file.
        write_keystore_share_to_file(
            keystore_share_dir.join(VOTING_KEYSTORE_SHARE_FILE),
            &voting_keystore_share,
        )?;

        ValidatorDir::open(keystore_share_dir).map_err(BuilderError::UnableToOpenDir)
    }
}

pub fn keystore_share_password_path<P: AsRef<Path>>(password_dir: P, keystore: &KeystoreShare) -> PathBuf {
    password_dir
        .as_ref()
        .join(format!("{}_{}", keystore.master_public_key, keystore.share_id))
}

pub fn default_keystore_share_dir<P: AsRef<Path>>(
    keystore_share: &KeystoreShare,
    validators_dir: P,
) -> PathBuf {
    validators_dir
        .as_ref()
        .join(format!("{}", keystore_share.master_public_key))
        .join(format!("{}", keystore_share.share_id))
}


/// Writes a JSON keystore to file.
fn write_keystore_share_to_file(
    path: PathBuf,
    keystore_share: &KeystoreShare,
) -> Result<(), BuilderError> {
    if path.exists() {
        Err(BuilderError::KeystoreAlreadyExists(path))
    } else {
        let file = File::options()
            .write(true)
            .read(true)
            .create_new(true)
            .open(path)
            .map_err(BuilderError::UnableToSaveKeystore)?;

        keystore_share.to_json_writer(file).map_err(Into::into)
    }
}