//! Native FIDO SSH signing. Desktop owns the shared service; each operation owns
//! its device, cancellation and prompts until the backend has actually stopped.
mod interaction;
mod signature;
#[cfg(test)]
pub(crate) mod tests;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod usb;
#[cfg(windows)]
mod windows;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use self::interaction::Interaction;
use crate::SshSessionConfig;
use russh::keys::ssh_encoding::Encode;
use russh::keys::{PrivateKey, PublicKey, ssh_key::Signature, ssh_key::private::KeypairData};

const OPERATION_TIMEOUT: Duration = Duration::from_secs(120);
const POLL: Duration = Duration::from_millis(25);

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SecurityKeyError {
    #[error("Security key operation cancelled")]
    Cancelled,
    #[error("Security key operation timed out; reconnect to retry")]
    TimedOut,
    #[error("Native security key authentication is unavailable on this system")]
    Unavailable,
    #[error("Security key access failed; check the device and USB access permissions")]
    Device,
    #[error("The security key is locked; use its management software to unlock it")]
    Locked,
    #[error("The security key requires a PIN to be configured with its management software")]
    PinNotSet,
    #[error("The security key returned an invalid signature or an unexpected credential")]
    InvalidSignature,
    #[error("Invalid or unsupported OpenSSH security key")]
    InvalidKey,
    #[error("Security key interaction is unavailable")]
    Prompt,
    #[error("Security key worker stopped unexpectedly")]
    Worker,
}

pub(crate) fn is_security_key(key: &PrivateKey) -> bool {
    matches!(
        key.key_data(),
        KeypairData::SkEd25519(_) | KeypairData::SkEcdsaSha2NistP256(_)
    )
}

struct SigningRequest {
    public_key: PublicKey,
    application: String,
    credential: Vec<u8>,
    verification_required: bool,
    message: Vec<u8>,
}

impl SigningRequest {
    fn new(key: &PrivateKey, message: Vec<u8>) -> Result<Self, SecurityKeyError> {
        let (application, credential, flags) = match key.key_data() {
            KeypairData::SkEd25519(key) => {
                (key.public().application(), key.key_handle(), key.flags())
            }
            KeypairData::SkEcdsaSha2NistP256(key) => {
                (key.public().application(), key.key_handle(), key.flags())
            }
            _ => return Err(SecurityKeyError::InvalidKey),
        };
        if application.is_empty() || application.contains('\0') || credential.is_empty() {
            return Err(SecurityKeyError::InvalidKey);
        }
        Ok(Self {
            public_key: key.public_key().clone(),
            application: application.to_owned(),
            credential: credential.to_vec(),
            verification_required: flags & 0x04 != 0,
            message,
        })
    }
}

struct DeviceSignature {
    credential: Option<Vec<u8>>,
    rp_hash: [u8; 32],
    flags: u8,
    counter: u32,
    signature: Vec<u8>,
}

trait Backend: Send + Sync {
    fn sign(
        &self,
        request: &SigningRequest,
        interaction: &mut Interaction,
    ) -> Result<DeviceSignature, SecurityKeyError>;
}

struct NativeBackend;
impl Backend for NativeBackend {
    fn sign(
        &self,
        request: &SigningRequest,
        interaction: &mut Interaction,
    ) -> Result<DeviceSignature, SecurityKeyError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            usb::sign(request, interaction)
        }
        #[cfg(windows)]
        {
            windows::sign(request, interaction)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            let _ = (request, interaction);
            Err(SecurityKeyError::Unavailable)
        }
    }
}

/// One instance shared by all desktop windows. The lock remains held by the
/// worker even if the SSH future is dropped, until device cleanup is complete.
pub struct SecurityKeyService {
    gate: Arc<tokio::sync::Semaphore>,
    backend: Arc<dyn Backend>,
}

impl Default for SecurityKeyService {
    fn default() -> Self {
        Self {
            gate: Arc::new(tokio::sync::Semaphore::new(1)),
            backend: Arc::new(NativeBackend),
        }
    }
}

struct CancelOnDrop(Arc<AtomicBool>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl SecurityKeyService {
    async fn sign(
        self: &Arc<Self>,
        config: &SshSessionConfig,
        request: SigningRequest,
    ) -> Result<Signature, SecurityKeyError> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel = CancelOnDrop(cancelled.clone());
        let mut interaction = Interaction::new(config, cancelled);
        interaction.show(crate::SshAgentPromptPhase::SecurityKeyQueued)?;
        let acquire = self.gate.clone().acquire_owned();
        tokio::pin!(acquire);
        let permit = loop {
            interaction.check()?;
            tokio::select! {
                permit = &mut acquire => break permit.map_err(|_| SecurityKeyError::Worker)?,
                _ = tokio::time::sleep(POLL) => {},
            }
        };
        let service = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            interaction.start_deadline();
            interaction.show(if cfg!(windows) {
                crate::SshAgentPromptPhase::SecurityKeySystem
            } else {
                crate::SshAgentPromptPhase::SecurityKeyTouch
            })?;
            let response = service.backend.sign(&request, &mut interaction)?;
            interaction.check()?;
            signature::verify_and_encode(&request, response)
        })
        .await
        .map_err(|_| SecurityKeyError::Worker)?
    }
}

pub(crate) struct HardwareSigner<'a> {
    pub config: &'a SshSessionConfig,
    pub key: &'a PrivateKey,
    pub service: Arc<SecurityKeyService>,
}

impl russh::Signer for HardwareSigner<'_> {
    type Error = anyhow::Error;
    async fn auth_sign(
        &mut self,
        identity: &russh::keys::agent::AgentIdentity,
        _hash: Option<russh::keys::HashAlg>,
        mut data: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        if identity.public_key().key_data() != self.key.public_key().key_data() {
            return Err(SecurityKeyError::InvalidKey.into());
        }
        let request = SigningRequest::new(self.key, data.clone())?;
        let signature = self.service.sign(self.config, request).await?;
        // russh expects the original signing buffer with an SSH string containing
        // the signature appended, not just the raw authenticator signature.
        let encoded = signature.encode_vec()?;
        encoded.encode(&mut data)?;
        Ok(data)
    }
}
