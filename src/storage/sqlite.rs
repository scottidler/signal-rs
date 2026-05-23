//! SQLite-backed `Store` and libsignal-protocol storage trait impls.

use std::path::Path;

use async_trait::async_trait;
use libsignal_protocol::{
    Direction, GenericSignedPreKey, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore, KyberPreKeyId,
    KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress, PublicKey,
    SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};
use log::{debug, warn};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

use super::{Identity, LinkStatus, Store, StoreError};

const IDENTITY_KEY_KEYPAIR: &str = "identity_keypair";
const IDENTITY_KEY_REGISTRATION_ID: &str = "registration_id";
const IDENTITY_KEY_ACCOUNT_NUMBER: &str = "account_number";
const IDENTITY_KEY_DEVICE_ID: &str = "device_id";
const IDENTITY_KEY_LINK_STATUS: &str = "link_status";
const IDENTITY_KEY_PASSWORD: &str = "password";
const IDENTITY_KEY_PNI: &str = "pni";
const IDENTITY_KEY_ACI: &str = "aci";
const IDENTITY_KEY_PROFILE_KEY: &str = "profile_key";
const IDENTITY_KEY_PROVISIONING_CODE: &str = "provisioning_code";

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Pool-backed SQLite store. Holds an [`SqlitePool`] for its lifetime; the
/// receive loop and send pipeline both check out connections from the pool.
/// Phase 6 adds a `TxStore<'a, 'tx>` wrapper for transactional libsignal
/// storage-trait calls inside a decrypt critical section.
#[derive(Debug, Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    /// Open or create a SQLite database at `path`. Runs migrations. Enables
    /// WAL journal mode. The file is created with the umask-derived perms
    /// (callers are expected to ensure the surrounding state directory is 0700).
    pub async fn open(path: &Path) -> Result<Self, StoreError> {
        debug!("SqliteStore::open: path={}", path.display());
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal);
        let pool = SqlitePoolOptions::new().max_connections(8).connect_with(opts).await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }

    /// In-memory store for tests. WAL journal is meaningless here.
    #[cfg(test)]
    pub async fn open_in_memory() -> Result<Self, StoreError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    async fn get_identity_value(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let row = sqlx::query("SELECT value FROM identity WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get::<Vec<u8>, _>("value")))
    }

    async fn put_identity_value(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        sqlx::query("INSERT OR REPLACE INTO identity (key, value) VALUES (?, ?)")
            .bind(key)
            .bind(value)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Store the device password minted at link time. Used as the
    /// `password` half of HTTP Basic auth on every authenticated call to
    /// `chat.signal.org`.
    pub async fn set_password(&self, password: &str) -> Result<(), StoreError> {
        self.put_identity_value(IDENTITY_KEY_PASSWORD, password.as_bytes())
            .await
    }

    /// Load the device password. `None` if linking has not reached the
    /// device-completion step.
    pub async fn get_password(&self) -> Result<Option<String>, StoreError> {
        match self.get_identity_value(IDENTITY_KEY_PASSWORD).await? {
            Some(bytes) => Ok(Some(
                String::from_utf8(bytes).map_err(|e| StoreError::Corrupt(format!("password utf8: {e}")))?,
            )),
            None => Ok(None),
        }
    }

    /// Overwrite device_id - used by the device-completion step in `link()`
    /// once Signal's server has assigned us a real device id.
    pub async fn set_device_id(&self, device_id: u32) -> Result<(), StoreError> {
        self.put_identity_value(IDENTITY_KEY_DEVICE_ID, &device_id.to_be_bytes())
            .await
    }

    /// Persist the ACI (account identifier UUID string). Stored as a sibling
    /// of `account_number` (E.164); the Signal protocol uses ACI for routing.
    pub async fn set_aci(&self, aci: &str) -> Result<(), StoreError> {
        self.put_identity_value(IDENTITY_KEY_ACI, aci.as_bytes()).await
    }

    /// Load the persisted ACI string, if any.
    pub async fn get_aci(&self) -> Result<Option<String>, StoreError> {
        match self.get_identity_value(IDENTITY_KEY_ACI).await? {
            Some(bytes) => Ok(Some(
                String::from_utf8(bytes).map_err(|e| StoreError::Corrupt(format!("aci utf8: {e}")))?,
            )),
            None => Ok(None),
        }
    }

    /// Persist the PNI (phone-number identifier UUID string), if the
    /// ProvisionMessage carried one.
    pub async fn set_pni(&self, pni: &str) -> Result<(), StoreError> {
        self.put_identity_value(IDENTITY_KEY_PNI, pni.as_bytes()).await
    }

    /// Load the persisted PNI string, if any.
    pub async fn get_pni(&self) -> Result<Option<String>, StoreError> {
        match self.get_identity_value(IDENTITY_KEY_PNI).await? {
            Some(bytes) => Ok(Some(
                String::from_utf8(bytes).map_err(|e| StoreError::Corrupt(format!("pni utf8: {e}")))?,
            )),
            None => Ok(None),
        }
    }

    /// Persist the profile key from the ProvisionMessage. Required for
    /// upload-the-profile-name and Note-to-Self decoding paths.
    pub async fn set_profile_key(&self, profile_key: &[u8]) -> Result<(), StoreError> {
        self.put_identity_value(IDENTITY_KEY_PROFILE_KEY, profile_key).await
    }

    /// Load the persisted profile key.
    pub async fn get_profile_key(&self) -> Result<Option<Vec<u8>>, StoreError> {
        self.get_identity_value(IDENTITY_KEY_PROFILE_KEY).await
    }

    /// Persist the one-shot provisioning code from the ProvisionMessage.
    /// Needed by the device-completion HTTP call; persisting it lets
    /// `link()` resume after a crash between identity persistence and
    /// device registration. Cleared after a successful PUT to
    /// `/v1/devices/{code}`.
    pub async fn set_provisioning_code(&self, code: &str) -> Result<(), StoreError> {
        self.put_identity_value(IDENTITY_KEY_PROVISIONING_CODE, code.as_bytes())
            .await
    }

    /// Load the persisted provisioning code, if any.
    pub async fn get_provisioning_code(&self) -> Result<Option<String>, StoreError> {
        match self.get_identity_value(IDENTITY_KEY_PROVISIONING_CODE).await? {
            Some(bytes) => {
                Ok(Some(String::from_utf8(bytes).map_err(|e| {
                    StoreError::Corrupt(format!("provisioning_code utf8: {e}"))
                })?))
            }
            None => Ok(None),
        }
    }

    /// Clear the provisioning code after device-completion succeeds.
    /// Signal's server only accepts each provisioning code once; keeping
    /// it around invites a retry that the server would 409.
    pub async fn clear_provisioning_code(&self) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM identity WHERE key = ?")
            .bind(IDENTITY_KEY_PROVISIONING_CODE)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Return the device IDs for which we already hold a session under
    /// the given ACI/PNI string (i.e. all addresses formatted as
    /// `{service_id}.{device_id}` whose service_id matches). Used by
    /// the send path to skip prekey-bundle fetch (and the consumption
    /// of the recipient's one-time prekeys) when we already have
    /// established sessions for the target.
    pub async fn session_device_ids_for_service_id(&self, service_id_string: &str) -> Result<Vec<u32>, StoreError> {
        let prefix = format!("{service_id_string}.");
        let rows = sqlx::query("SELECT address FROM sessions WHERE address LIKE ?")
            .bind(format!("{prefix}%"))
            .fetch_all(&self.pool)
            .await?;
        let mut ids = Vec::with_capacity(rows.len());
        for row in rows {
            let addr: String = row.get("address");
            if let Some(suffix) = addr.strip_prefix(&prefix)
                && let Ok(id) = suffix.parse::<u32>()
            {
                ids.push(id);
            }
        }
        Ok(ids)
    }
}

#[async_trait(?Send)]
impl Store for SqliteStore {
    async fn save_identity_bundle(
        &self,
        identity_keypair: &IdentityKeyPair,
        registration_id: u32,
        account_number: &str,
        device_id: u32,
        link_status: LinkStatus,
    ) -> Result<(), StoreError> {
        debug!(
            "save_identity_bundle: account_number={} device_id={} link_status={:?}",
            account_number, device_id, link_status
        );
        let mut tx = self.pool.begin().await?;
        let keypair_bytes = identity_keypair.serialize();
        for (key, value) in [
            (IDENTITY_KEY_KEYPAIR, keypair_bytes.to_vec()),
            (IDENTITY_KEY_REGISTRATION_ID, registration_id.to_be_bytes().to_vec()),
            (IDENTITY_KEY_ACCOUNT_NUMBER, account_number.as_bytes().to_vec()),
            (IDENTITY_KEY_DEVICE_ID, device_id.to_be_bytes().to_vec()),
            (IDENTITY_KEY_LINK_STATUS, link_status.as_str().as_bytes().to_vec()),
        ] {
            sqlx::query("INSERT OR REPLACE INTO identity (key, value) VALUES (?, ?)")
                .bind(key)
                .bind(value)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn load_identity(&self) -> Result<Identity, StoreError> {
        debug!("load_identity:");
        let keypair_bytes = self
            .get_identity_value(IDENTITY_KEY_KEYPAIR)
            .await?
            .ok_or(StoreError::NotLinked)?;
        let identity_keypair = IdentityKeyPair::try_from(&keypair_bytes[..])?;

        let reg_bytes = self
            .get_identity_value(IDENTITY_KEY_REGISTRATION_ID)
            .await?
            .ok_or_else(|| StoreError::Corrupt("registration_id missing".into()))?;
        let registration_id = u32::from_be_bytes(
            reg_bytes
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupt("registration_id length".into()))?,
        );

        let account_bytes = self
            .get_identity_value(IDENTITY_KEY_ACCOUNT_NUMBER)
            .await?
            .ok_or_else(|| StoreError::Corrupt("account_number missing".into()))?;
        let account_number =
            String::from_utf8(account_bytes).map_err(|e| StoreError::Corrupt(format!("account_number utf8: {e}")))?;

        let device_bytes = self
            .get_identity_value(IDENTITY_KEY_DEVICE_ID)
            .await?
            .ok_or_else(|| StoreError::Corrupt("device_id missing".into()))?;
        let device_id = u32::from_be_bytes(
            device_bytes
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupt("device_id length".into()))?,
        );

        let status_bytes = self
            .get_identity_value(IDENTITY_KEY_LINK_STATUS)
            .await?
            .ok_or_else(|| StoreError::Corrupt("link_status missing".into()))?;
        let status_str =
            std::str::from_utf8(&status_bytes).map_err(|e| StoreError::Corrupt(format!("link_status utf8: {e}")))?;
        let link_status = LinkStatus::from_str(status_str)
            .ok_or_else(|| StoreError::Corrupt(format!("link_status value {status_str}")))?;

        if link_status != LinkStatus::Linked {
            warn!("load_identity: partially linked status={:?}", link_status);
            return Err(StoreError::PartiallyLinked { status: link_status });
        }

        Ok(Identity {
            identity_keypair,
            registration_id,
            account_number,
            device_id,
            link_status,
        })
    }

    async fn set_link_status(&self, status: LinkStatus) -> Result<(), StoreError> {
        debug!("set_link_status: status={:?}", status);
        self.put_identity_value(IDENTITY_KEY_LINK_STATUS, status.as_str().as_bytes())
            .await
    }
}

// libsignal-protocol storage traits below. All error returns are
// `SignalProtocolError` per the trait's `Result<T>` alias.

fn map_err(e: StoreError) -> SignalProtocolError {
    SignalProtocolError::InvalidArgument(format!("storage: {e}"))
}

fn map_sqlx(e: sqlx::Error) -> SignalProtocolError {
    map_err(StoreError::Sqlx(e))
}

#[async_trait(?Send)]
impl IdentityKeyStore for SqliteStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        let bytes = self
            .get_identity_value(IDENTITY_KEY_KEYPAIR)
            .await
            .map_err(map_err)?
            .ok_or_else(|| SignalProtocolError::InvalidArgument("identity_keypair not persisted".into()))?;
        IdentityKeyPair::try_from(&bytes[..])
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        let bytes = self
            .get_identity_value(IDENTITY_KEY_REGISTRATION_ID)
            .await
            .map_err(map_err)?
            .ok_or_else(|| SignalProtocolError::InvalidArgument("registration_id not persisted".into()))?;
        let arr: [u8; 4] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| SignalProtocolError::InvalidArgument("registration_id length".into()))?;
        Ok(u32::from_be_bytes(arr))
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        debug!("save_identity: address={}", address);
        let key = address.to_string();
        let new_key_bytes = identity.serialize();
        let existing = sqlx::query("SELECT key FROM identities WHERE address = ?")
            .bind(&key)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?
            .map(|r| r.get::<Vec<u8>, _>("key"));
        sqlx::query("INSERT OR REPLACE INTO identities (address, key) VALUES (?, ?)")
            .bind(&key)
            .bind(new_key_bytes.as_ref())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(match existing {
            Some(prev) if prev.as_slice() == new_key_bytes.as_ref() => IdentityChange::NewOrUnchanged,
            Some(_) => IdentityChange::ReplacedExisting,
            None => IdentityChange::NewOrUnchanged,
        })
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        let row = sqlx::query("SELECT key FROM identities WHERE address = ?")
            .bind(address.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?;
        match row {
            None => Ok(true),
            Some(r) => {
                let stored = r.get::<Vec<u8>, _>("key");
                Ok(stored.as_slice() == identity.serialize().as_ref())
            }
        }
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let row = sqlx::query("SELECT key FROM identities WHERE address = ?")
            .bind(address.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?;
        match row {
            None => Ok(None),
            Some(r) => {
                let bytes = r.get::<Vec<u8>, _>("key");
                IdentityKey::decode(&bytes).map(Some)
            }
        }
    }
}

#[async_trait(?Send)]
impl SessionStore for SqliteStore {
    async fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let row = sqlx::query("SELECT record FROM sessions WHERE address = ?")
            .bind(address.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?;
        match row {
            None => Ok(None),
            Some(r) => {
                let bytes = r.get::<Vec<u8>, _>("record");
                SessionRecord::deserialize(&bytes).map(Some)
            }
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        debug!("store_session: address={}", address);
        let bytes = record.serialize()?;
        sqlx::query("INSERT OR REPLACE INTO sessions (address, record) VALUES (?, ?)")
            .bind(address.to_string())
            .bind(bytes)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl PreKeyStore for SqliteStore {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        let id: u32 = prekey_id.into();
        let row = sqlx::query("SELECT record FROM prekeys WHERE id = ?")
            .bind(id as i64)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?
            .ok_or(SignalProtocolError::InvalidPreKeyId)?;
        let bytes = row.get::<Vec<u8>, _>("record");
        PreKeyRecord::deserialize(&bytes)
    }

    async fn save_pre_key(&mut self, prekey_id: PreKeyId, record: &PreKeyRecord) -> Result<(), SignalProtocolError> {
        let id: u32 = prekey_id.into();
        debug!("save_pre_key: id={}", id);
        let bytes = record.serialize()?;
        sqlx::query("INSERT OR REPLACE INTO prekeys (id, record) VALUES (?, ?)")
            .bind(id as i64)
            .bind(bytes)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        let id: u32 = prekey_id.into();
        debug!("remove_pre_key: id={}", id);
        sqlx::query("DELETE FROM prekeys WHERE id = ?")
            .bind(id as i64)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SqliteStore {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let id: u32 = signed_prekey_id.into();
        let row = sqlx::query("SELECT record FROM signed_prekeys WHERE id = ?")
            .bind(id as i64)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?;
        let bytes = row.get::<Vec<u8>, _>("record");
        SignedPreKeyRecord::deserialize(&bytes)
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = signed_prekey_id.into();
        debug!("save_signed_pre_key: id={}", id);
        let bytes = record.serialize()?;
        sqlx::query("INSERT OR REPLACE INTO signed_prekeys (id, record) VALUES (?, ?)")
            .bind(id as i64)
            .bind(bytes)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for SqliteStore {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();
        let row = sqlx::query("SELECT record FROM kyber_prekeys WHERE id = ?")
            .bind(id as i64)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)?;
        let bytes = row.get::<Vec<u8>, _>("record");
        KyberPreKeyRecord::deserialize(&bytes)
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();
        debug!("save_kyber_pre_key: id={}", id);
        let bytes = record.serialize()?;
        sqlx::query("INSERT OR REPLACE INTO kyber_prekeys (id, record, used) VALUES (?, ?, 0)")
            .bind(id as i64)
            .bind(bytes)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        _ec_prekey_id: SignedPreKeyId,
        _base_key: &PublicKey,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();
        debug!("mark_kyber_pre_key_used: id={}", id);
        // v0.1 treats all kyber prekeys as one-time (no last-resort distinction).
        // Mark used and delete; Phase 7+ can revisit if last-resort handling lands.
        sqlx::query("DELETE FROM kyber_prekeys WHERE id = ?")
            .bind(id as i64)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
