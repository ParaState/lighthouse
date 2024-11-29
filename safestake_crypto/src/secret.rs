use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::fs::Permissions;
use std::fs::{self, OpenOptions};
use std::io::BufWriter;
use std::io::Write as _;
use std::path::PathBuf;
use serde::de::DeserializeOwned;
use crate::secp::{PublicKey, SecretKey, generate_production_keypair};


#[derive(Serialize, Deserialize, Clone)]
pub struct Secret {
    pub name: PublicKey,
    pub secret: SecretKey,
}

pub trait Export: Serialize + DeserializeOwned {

    fn read(path: &PathBuf) -> Result<Self, String> {
        let reader = || -> Result<Self, std::io::Error> {
            let data = fs::read(path)?;
            Ok(serde_json::from_slice(data.as_slice())?)
        };
        reader().map_err(|e| e.to_string())
    }

    fn write(&self, path: &PathBuf) -> Result<(), String> {
        let writer = || -> Result<(), std::io::Error> {
            let file = OpenOptions::new().create(true).write(true).open(path)?;
            let permissions = Permissions::from_mode(0o600);
            file.set_permissions(permissions)?;
            let mut writer = BufWriter::new(file);
            let data = serde_json::to_string_pretty(self).unwrap();
            writer.write_all(data.as_ref())?;
            writer.write_all(b"\n")?;
            Ok(())
        };
        writer().map_err(|e| e.to_string())
    }
}

impl Export for Secret {}

impl Secret {
    pub fn new() -> Self {
        let (name, secret) = generate_production_keypair();
        Self { name, secret }
    }

    pub fn write_hex(&self, path: &PathBuf) -> Result<(), String> {
        #[derive(Serialize)]
        struct SecretHex {
            name: String,
            secret: String
        }

        let writer = || -> Result<(), std::io::Error> {
            let file = OpenOptions::new().create(true).write(true).open(path)?;
            let mut writer = BufWriter::new(file);
            let secret_hex = SecretHex {
                name: hex::encode(self.name.0),
                secret: hex::encode(self.secret.0)
            };
            let data = serde_json::to_string_pretty(&secret_hex).unwrap();
            writer.write_all(data.as_ref())?;
            writer.write_all(b"\n")?;
            Ok(())
        };
        writer().map_err(|e| e.to_string())
    }
}