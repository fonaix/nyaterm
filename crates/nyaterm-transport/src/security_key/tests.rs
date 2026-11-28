use super::{
    Backend, DeviceSignature, SecurityKeyError, SecurityKeyService, SigningRequest,
    interaction::Interaction, signature::verify_and_encode,
};
use crate::SshSessionConfig;
use russh::keys::ssh_key::{
    LineEnding,
    private::{Ed25519Keypair, KeypairData, SkEcdsaSha2NistP256, SkEd25519},
    public::KeyData,
};
use russh::keys::{PrivateKey, PublicKey, signature::Signer, ssh_encoding::Encode};
use sha2::{Digest, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

enum TestSigningKey {
    Ed(Box<PrivateKey>),
    Ec(p256::ecdsa::SigningKey),
}
struct TestDevice {
    key: TestSigningKey,
    signatures: Arc<AtomicUsize>,
}
impl TestDevice {
    fn response(&self, request: &SigningRequest) -> DeviceSignature {
        let rp_hash: [u8; 32] = Sha256::digest(request.application.as_bytes()).into();
        let flags = 0x05;
        let counter = 42u32;
        let mut message = rp_hash.to_vec();
        message.push(flags);
        message.extend_from_slice(&counter.to_be_bytes());
        message.extend_from_slice(&Sha256::digest(&request.message));
        let signature = match &self.key {
            TestSigningKey::Ed(key) => key.try_sign(&message).unwrap().as_bytes().to_vec(),
            TestSigningKey::Ec(key) => {
                let sig: p256::ecdsa::Signature =
                    p256::ecdsa::signature::Signer::sign(key, &message);
                sig.to_der().as_bytes().to_vec()
            }
        };
        DeviceSignature {
            credential: Some(request.credential.clone()),
            rp_hash,
            flags,
            counter,
            signature,
        }
    }
}
impl Backend for TestDevice {
    fn sign(
        &self,
        request: &SigningRequest,
        interaction: &mut Interaction,
    ) -> Result<DeviceSignature, SecurityKeyError> {
        interaction.check()?;
        self.signatures.fetch_add(1, Ordering::SeqCst);
        Ok(self.response(request))
    }
}

fn fixture(ecdsa: bool) -> (PrivateKey, TestDevice) {
    let (key, ordinary_public) = if ecdsa {
        let key = p256::ecdsa::SigningKey::from_bytes((&[23u8; 32]).into()).unwrap();
        let mut bytes = Vec::new();
        "sk-ecdsa-sha2-nistp256@openssh.com"
            .encode(&mut bytes)
            .unwrap();
        "nistp256".encode(&mut bytes).unwrap();
        key.verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .encode(&mut bytes)
            .unwrap();
        "ssh:test".encode(&mut bytes).unwrap();
        (
            TestSigningKey::Ec(key),
            PublicKey::from_bytes(&bytes).unwrap(),
        )
    } else {
        let pair = Ed25519Keypair::from_seed(&[19; 32]);
        let public = russh::keys::ssh_key::public::SkEd25519::new(pair.public, "ssh:test");
        (
            TestSigningKey::Ed(Box::new(
                PrivateKey::new(KeypairData::Ed25519(pair), "fixture").unwrap(),
            )),
            PublicKey::new(KeyData::SkEd25519(public), "fixture"),
        )
    };
    let reference = match ordinary_public.key_data() {
        KeyData::SkEd25519(public) => {
            PrivateKey::from(SkEd25519::new(public.clone(), 0x05, vec![11; 32]).unwrap())
        }
        KeyData::SkEcdsaSha2NistP256(public) => {
            PrivateKey::from(SkEcdsaSha2NistP256::new(public.clone(), 0x05, vec![11; 32]).unwrap())
        }
        _ => unreachable!(),
    };
    (
        reference,
        TestDevice {
            key,
            signatures: Arc::new(AtomicUsize::new(0)),
        },
    )
}

pub(crate) fn hardware_fixture(
    ecdsa: bool,
) -> (PrivateKey, Arc<SecurityKeyService>, Arc<AtomicUsize>) {
    let (key, device) = fixture(ecdsa);
    let count = device.signatures.clone();
    (
        key,
        Arc::new(SecurityKeyService {
            gate: Arc::new(tokio::sync::Semaphore::new(1)),
            backend: Arc::new(device),
        }),
        count,
    )
}

#[test]
fn both_algorithms_verify_device_signatures_and_preserve_openssh_references() {
    for ecdsa in [false, true] {
        let (key, device) = fixture(ecdsa);
        let pem = key.to_openssh(LineEnding::LF).unwrap();
        let restored = russh::keys::decode_secret_key(&pem, None).unwrap();
        assert!(super::is_security_key(&restored));
        let request =
            SigningRequest::new(&restored, b"ssh authentication request".to_vec()).unwrap();
        let signature = verify_and_encode(&request, device.response(&request)).unwrap();
        let encoded = signature.encode_vec().unwrap();
        let decoded =
            <russh::keys::ssh_key::Signature as russh::keys::ssh_encoding::Decode>::decode(
                &mut encoded.as_slice(),
            )
            .unwrap();
        assert_eq!(decoded, signature);
        let encrypted = key
            .encrypt(&mut rand::rng(), "fixture-passphrase")
            .unwrap()
            .to_openssh(LineEnding::LF)
            .unwrap();
        assert!(russh::keys::decode_secret_key(&encrypted, Some("wrong")).is_err());
        let decrypted =
            russh::keys::decode_secret_key(&encrypted, Some("fixture-passphrase")).unwrap();
        assert_eq!(decrypted.key_data(), key.key_data());
    }
}

#[test]
fn invalid_device_responses_never_become_ssh_signatures() {
    for ecdsa in [false, true] {
        let (key, device) = fixture(ecdsa);
        let request = SigningRequest::new(&key, b"challenge".to_vec()).unwrap();
        for corruption in 0..7 {
            let mut response = device.response(&request);
            match corruption {
                0 => response.credential = Some(vec![99]),
                1 => response.rp_hash[0] ^= 1,
                2 => response.flags &= !1,
                3 => response.flags &= !4,
                4 => response.flags |= 0x80,
                5 => response.signature[0] ^= 1,
                _ => response.counter += 1,
            }
            assert_eq!(
                verify_and_encode(&request, response).unwrap_err(),
                SecurityKeyError::InvalidSignature
            );
        }
    }
}

struct BlockingDevice {
    entered: Arc<AtomicUsize>,
    cleaned: Arc<AtomicBool>,
}
impl Backend for BlockingDevice {
    fn sign(
        &self,
        _: &SigningRequest,
        interaction: &mut Interaction,
    ) -> Result<DeviceSignature, SecurityKeyError> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        loop {
            if let Err(error) = interaction.check() {
                std::thread::sleep(Duration::from_millis(50));
                self.cleaned.store(true, Ordering::SeqCst);
                return Err(error);
            }
            std::thread::sleep(super::POLL);
        }
    }
}

#[tokio::test]
async fn dropping_authentication_stops_device_and_keeps_lease_until_cleanup() {
    let entered = Arc::new(AtomicUsize::new(0));
    let cleaned = Arc::new(AtomicBool::new(false));
    let service = Arc::new(SecurityKeyService {
        gate: Arc::new(tokio::sync::Semaphore::new(1)),
        backend: Arc::new(BlockingDevice {
            entered: entered.clone(),
            cleaned: cleaned.clone(),
        }),
    });
    let worker_service = service.clone();
    let (key, _) = fixture(false);
    let worker = tokio::spawn(async move {
        worker_service
            .sign(
                &SshSessionConfig::default(),
                SigningRequest::new(&key, vec![1]).unwrap(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while entered.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(service.gate.try_acquire().is_err());
    worker.abort();
    let _ = worker.await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(_guard) = service.gate.try_acquire() {
                assert!(cleaned.load(Ordering::SeqCst));
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn queued_cancelled_attempt_never_reaches_device() {
    let (key, service, signatures) = hardware_fixture(false);
    let permit = service.gate.try_acquire().unwrap();
    let config = SshSessionConfig::default();
    config.attempt.cancel();
    assert_eq!(
        service
            .sign(&config, SigningRequest::new(&key, vec![1]).unwrap())
            .await
            .unwrap_err(),
        SecurityKeyError::Cancelled
    );
    assert_eq!(signatures.load(Ordering::SeqCst), 0);
    drop(permit);
}
