//! `Client::status` and its public `ClientStatus` return type.
//!
//! Pulls account / device_id / ACI / PNI / link_status from the local
//! store and fans out a `GET /v1/devices` for the server-authoritative
//! linked-devices list. Hard-errors on network failure - callers see
//! the typed `StatusError` and can decide whether to retry.
//!
//! Decomposed out of `client.rs` to keep that file under the 1500-line
//! limit; status is a self-contained read path with no coupling to the
//! send/receive flows.

use log::debug;
use serde::Serialize;
use thiserror::Error;

use crate::api::{self, ApiError, DeviceEntry};
use crate::crypto::prekeys::IdentityKind;
use crate::storage::{LinkStatus, StoreError};

use super::Client;

/// Snapshot of the client's identity-level state plus the
/// server-authoritative linked-devices list. Returned by
/// [`Client::status`].
#[derive(Debug, Clone, Serialize)]
pub struct ClientStatus {
    pub account_number: String,
    pub device_id: u32,
    pub aci: Option<String>,
    pub pni: Option<String>,
    pub link_status: LinkStatus,
    pub linked_devices: Vec<DeviceEntry>,
}

#[derive(Error, Debug)]
pub enum StatusError {
    #[error("storage error: {0}")]
    Storage(#[from] StoreError),

    #[error("api error: {0}")]
    Api(#[from] ApiError),
}

impl Client {
    /// Pull a snapshot of the device's identity state from the local
    /// store and the server's linked-devices list via `GET /v1/devices`.
    /// Hard-errors on either store or network failure - callers that
    /// want a partial view should catch the error and degrade.
    pub async fn status(&self) -> Result<ClientStatus, StatusError> {
        debug!(
            "Client::status: account={} device_id={}",
            self.inner.identity.account_number, self.inner.identity.device_id
        );

        let aci = self.inner.store.get_aci().await?;
        let pni = self.inner.store.get_pni().await?;

        let creds = api::load_upload_credentials(&self.inner.store, IdentityKind::Aci).await?;
        let linked_devices = api::list_devices(&creds).await?;

        Ok(ClientStatus {
            account_number: self.inner.identity.account_number.clone(),
            device_id: self.inner.identity.device_id,
            aci,
            pni,
            link_status: self.inner.identity.link_status,
            linked_devices,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
