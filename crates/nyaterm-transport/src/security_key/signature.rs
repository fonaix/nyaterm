use super::{DeviceSignature, SecurityKeyError, SigningRequest};
use russh::keys::{Algorithm, signature::Verifier, ssh_encoding::Encode, ssh_key::Signature};
use sha2::{Digest, Sha256};

pub(super) fn verify_and_encode(
    request: &SigningRequest,
    response: DeviceSignature,
) -> Result<Signature, SecurityKeyError> {
    let invalid = || SecurityKeyError::InvalidSignature;
    if response.credential.as_ref().is_some_and(|id| id != &request.credential)
        || response.rp_hash != <[u8; 32]>::from(Sha256::digest(request.application.as_bytes()))
        || response.flags & 0x01 == 0
        || (request.verification_required && response.flags & 0x04 == 0)
        // SSH SK signatures cannot carry attested credential data or extensions.
        || response.flags & 0xc0 != 0
    {
        return Err(invalid());
    }
    let mut bytes = match request.public_key.algorithm() {
        Algorithm::SkEd25519 if response.signature.len() == 64 => response.signature,
        Algorithm::SkEcdsaSha2NistP256 => {
            let signature =
                p256::ecdsa::Signature::from_der(&response.signature).map_err(|_| invalid())?;
            let mut encoded = Vec::new();
            for scalar in [signature.r().to_bytes(), signature.s().to_bytes()] {
                let start = scalar
                    .iter()
                    .position(|byte| *byte != 0)
                    .unwrap_or(scalar.len());
                let mut value = scalar[start..].to_vec();
                if value.first().is_some_and(|byte| byte & 0x80 != 0) {
                    value.insert(0, 0);
                }
                value.encode(&mut encoded).map_err(|_| invalid())?;
            }
            encoded
        }
        _ => return Err(invalid()),
    };
    bytes.push(response.flags);
    bytes.extend_from_slice(&response.counter.to_be_bytes());
    let signature = Signature::new(request.public_key.algorithm(), bytes).map_err(|_| invalid())?;
    Verifier::verify(request.public_key.key_data(), &request.message, &signature)
        .map_err(|_| invalid())?;
    Ok(signature)
}
