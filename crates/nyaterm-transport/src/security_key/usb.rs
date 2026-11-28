use super::{DeviceSignature, POLL, SecurityKeyError, SigningRequest, interaction::Interaction};
use authenticator::StatusPinUv;
use authenticator::StatusUpdate;
use authenticator::authenticatorservice::{AuthenticatorService, SignArgs};
use authenticator::ctap2::commands::client_pin::Pin;
use authenticator::ctap2::server::{PublicKeyCredentialDescriptor, UserVerificationRequirement};
use authenticator::errors::AuthenticatorError;
use authenticator::statecallback::StateCallback;
use sha2::{Digest, Sha256};
use std::sync::mpsc;

struct CancelService(AuthenticatorService);
impl Drop for CancelService {
    fn drop(&mut self) {
        let _ = self.0.cancel();
    }
}

pub(super) fn sign(
    request: &SigningRequest,
    interaction: &mut Interaction,
) -> Result<DeviceSignature, SecurityKeyError> {
    let mut service =
        CancelService(AuthenticatorService::new().map_err(|_| SecurityKeyError::Unavailable)?);
    service.0.add_detected_transports();
    let (status_tx, status_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    service
        .0
        .sign(
            interaction.remaining_ms(),
            SignArgs {
                client_data_hash: Sha256::digest(&request.message).into(),
                origin: request.application.clone(),
                relying_party_id: request.application.clone(),
                allow_list: vec![PublicKeyCredentialDescriptor {
                    id: request.credential.clone(),
                    transports: vec![],
                }],
                user_verification_req: if request.verification_required {
                    UserVerificationRequirement::Required
                } else {
                    UserVerificationRequirement::Discouraged
                },
                user_presence_req: true,
                extensions: Default::default(),
                pin: None,
                use_ctap1_fallback: !request.verification_required
                    && matches!(
                        request.public_key.algorithm(),
                        russh::keys::Algorithm::SkEcdsaSha2NistP256
                    ),
            },
            status_tx,
            StateCallback::new(Box::new(move |result| {
                let _ = result_tx.send(result);
            })),
        )
        .map_err(map_error)?;
    loop {
        interaction.check()?;
        match result_rx.try_recv() {
            Ok(result) => {
                let assertion = result.map_err(map_error)?.assertion;
                return Ok(DeviceSignature {
                    credential: assertion.credentials.map(|credential| credential.id),
                    rp_hash: assertion.auth_data.rp_id_hash.0,
                    flags: assertion.auth_data.flags.bits(),
                    counter: assertion.auth_data.counter,
                    signature: assertion.signature,
                });
            }
            Err(mpsc::TryRecvError::Disconnected) => return Err(SecurityKeyError::Worker),
            Err(mpsc::TryRecvError::Empty) => {}
        }
        match status_rx.recv_timeout(POLL) {
            Ok(StatusUpdate::PinUvError(status)) => match status {
                StatusPinUv::PinRequired(sender) => {
                    let pin = interaction.pin(false)?;
                    sender
                        .send(Pin::new(pin.as_ref()))
                        .map_err(|_| SecurityKeyError::Device)?;
                }
                StatusPinUv::InvalidPin(sender, _) => {
                    let pin = interaction.pin(true)?;
                    sender
                        .send(Pin::new(pin.as_ref()))
                        .map_err(|_| SecurityKeyError::Device)?;
                }
                StatusPinUv::PinAuthBlocked | StatusPinUv::PinBlocked | StatusPinUv::UvBlocked => {
                    return Err(SecurityKeyError::Locked);
                }
                StatusPinUv::PinNotSet => return Err(SecurityKeyError::PinNotSet),
                _ => return Err(SecurityKeyError::Device),
            },
            Ok(StatusUpdate::PresenceRequired | StatusUpdate::SelectDeviceNotice) => {
                interaction.show(crate::SshAgentPromptPhase::SecurityKeyTouch)?;
            }
            Ok(StatusUpdate::SelectResultNotice(sender, _)) => {
                // A single imported credential must never turn into discovery.
                let _ = sender.send(None);
                return Err(SecurityKeyError::InvalidSignature);
            }
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => std::thread::sleep(POLL),
        }
    }
}
fn map_error(error: AuthenticatorError) -> SecurityKeyError {
    match error {
        AuthenticatorError::CancelledByUser => SecurityKeyError::Cancelled,
        AuthenticatorError::NoConfiguredTransports => SecurityKeyError::Unavailable,
        AuthenticatorError::PinError(
            authenticator::errors::PinError::PinBlocked
            | authenticator::errors::PinError::PinAuthBlocked
            | authenticator::errors::PinError::UvBlocked,
        ) => SecurityKeyError::Locked,
        AuthenticatorError::PinError(authenticator::errors::PinError::PinNotSet) => {
            SecurityKeyError::PinNotSet
        }
        _ => SecurityKeyError::Device,
    }
}
