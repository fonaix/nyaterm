use super::{OPERATION_TIMEOUT, POLL, SecurityKeyError};
use crate::connection_attempt::ConnectionAttempt;
use crate::{
    SshAgentPrompt, SshAgentPromptPhase, SshAgentPromptProvider, SshAgentPromptRequest,
    SshSessionConfig,
};
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use crate::{
    SshCredentialPrompt, SshCredentialPromptKind, SshCredentialPromptReason, SshCredentialProvider,
};
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use nyaterm_core::SecretString;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use std::sync::mpsc;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;

pub(super) struct Interaction {
    cancelled: Arc<AtomicBool>,
    attempt: ConnectionAttempt,
    deadline: Option<Instant>,
    agent_provider: Option<Arc<dyn SshAgentPromptProvider>>,
    #[cfg(any(target_os = "linux", target_os = "macos", test))]
    credential_provider: Option<Arc<dyn SshCredentialProvider>>,
    prompt: SshAgentPrompt,
    active: Option<Arc<dyn SshAgentPromptRequest>>,
}

impl Interaction {
    pub(super) fn new(config: &SshSessionConfig, cancelled: Arc<AtomicBool>) -> Self {
        Self {
            cancelled,
            attempt: config.attempt.clone(),
            deadline: None,
            agent_provider: config.agent_prompt_provider.clone(),
            #[cfg(any(target_os = "linux", target_os = "macos", test))]
            credential_provider: config.credential_provider.clone(),
            prompt: SshAgentPrompt {
                host: config.host.clone(),
                port: config.port,
                username: config.username.clone(),
                connection_name: config.name.clone(),
                phase: SshAgentPromptPhase::SecurityKeyQueued,
                attempt: 1,
                message: String::new(),
            },
            active: None,
        }
    }
    pub(super) fn start_deadline(&mut self) {
        self.deadline = Some(Instant::now() + OPERATION_TIMEOUT);
    }
    pub(super) fn check(&self) -> Result<(), SecurityKeyError> {
        if self.cancelled.load(Ordering::Acquire) || self.attempt.is_cancelled() {
            return Err(SecurityKeyError::Cancelled);
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(SecurityKeyError::TimedOut);
        }
        if let Some(active) = &self.active
            && active
                .try_action()
                .map_err(|_| SecurityKeyError::Prompt)?
                .is_some()
        {
            return Err(SecurityKeyError::Cancelled);
        }
        Ok(())
    }
    pub(super) fn remaining_ms(&self) -> u64 {
        self.deadline
            .map(|deadline| {
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis() as u64
            })
            .unwrap_or(OPERATION_TIMEOUT.as_millis() as u64)
            .max(1)
    }
    pub(super) fn show(&mut self, phase: SshAgentPromptPhase) -> Result<(), SecurityKeyError> {
        self.check()?;
        self.prompt.phase = phase;
        if let Some(active) = &self.active {
            active
                .update_pending(&self.prompt)
                .map_err(|_| SecurityKeyError::Prompt)?;
        } else if let Some(provider) = &self.agent_provider {
            self.active = provider
                .begin_request(&self.prompt)
                .map_err(|_| SecurityKeyError::Prompt)?;
        }
        Ok(())
    }
    #[cfg(windows)]
    pub(super) fn parent_window(&self) -> Result<usize, SecurityKeyError> {
        loop {
            self.check()?;
            let prompt = self.active.as_ref().ok_or(SecurityKeyError::Prompt)?;
            if let Some(window) = prompt.native_parent_window() {
                return Ok(window);
            }
            std::thread::sleep(POLL);
        }
    }
    #[cfg(any(target_os = "linux", target_os = "macos", test))]
    pub(super) fn pin(&mut self, invalid: bool) -> Result<SecretString, SecurityKeyError> {
        if let Some(active) = self.active.take() {
            active.finish();
        }
        let attempt = ConnectionAttempt::default();
        let provider = self
            .credential_provider
            .as_ref()
            .and_then(|provider| provider.for_attempt(attempt.clone()))
            .ok_or(SecurityKeyError::Prompt)?;
        let prompt = SshCredentialPrompt {
            host: self.prompt.host.clone(),
            port: self.prompt.port,
            username: self.prompt.username.clone(),
            connection_name: self.prompt.connection_name.clone(),
            kind: SshCredentialPromptKind::SecurityKeyPin,
            reason: if invalid {
                SshCredentialPromptReason::SecurityKeyPinInvalid
            } else {
                SshCredentialPromptReason::SecurityKeyPinRequired
            },
            attempt: 1,
            prompt_text: None,
            echo: false,
        };
        let (tx, rx) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("security-key-pin".into())
            .spawn(move || {
                let result = provider
                    .request_secret(&prompt)
                    .map(|value| value.map(SecretString::from));
                let _ = tx.send(result);
            })
            .map_err(|_| SecurityKeyError::Worker)?;
        let result = loop {
            if let Err(error) = self.check() {
                break Err(error);
            }
            match rx.recv_timeout(POLL) {
                Ok(Ok(Some(pin))) => break Ok(pin),
                Ok(Ok(None)) => break Err(SecurityKeyError::Cancelled),
                Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break Err(SecurityKeyError::Prompt);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        };
        attempt.cancel();
        let _ = worker.join();
        if result.is_ok() {
            self.show(SshAgentPromptPhase::SecurityKeyTouch)?;
        }
        result
    }
}
impl Drop for Interaction {
    fn drop(&mut self) {
        if let Some(active) = self.active.take() {
            active.finish();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Interaction;
    use crate::connection_attempt::ConnectionAttempt;
    use crate::security_key::SecurityKeyError;
    use crate::{
        SshCredentialPrompt, SshCredentialPromptKind, SshCredentialProvider, SshSessionConfig,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::time::{Duration, Instant};

    struct WaitingPinProvider {
        attempt: ConnectionAttempt,
        returned: Arc<AtomicBool>,
    }
    impl SshCredentialProvider for WaitingPinProvider {
        fn for_attempt(
            &self,
            attempt: ConnectionAttempt,
        ) -> Option<Arc<dyn SshCredentialProvider>> {
            Some(Arc::new(Self {
                attempt,
                returned: self.returned.clone(),
            }))
        }
        fn request_secret(&self, prompt: &SshCredentialPrompt) -> Result<Option<String>, String> {
            assert_eq!(prompt.kind, SshCredentialPromptKind::SecurityKeyPin);
            assert!(!prompt.echo);
            let (_sender, receiver) = mpsc::channel::<Option<String>>();
            let result = self.attempt.receive(&receiver, Duration::from_secs(5));
            self.returned.store(true, Ordering::Release);
            result
        }
    }
    #[test]
    fn deadline_cancels_and_joins_the_independent_pin_prompt() {
        let returned = Arc::new(AtomicBool::new(false));
        let config = SshSessionConfig {
            credential_provider: Some(Arc::new(WaitingPinProvider {
                attempt: Default::default(),
                returned: returned.clone(),
            })),
            ..Default::default()
        };
        let mut interaction = Interaction::new(&config, Arc::new(AtomicBool::new(false)));
        interaction.deadline = Some(Instant::now() + Duration::from_millis(50));
        assert_eq!(
            interaction.pin(false).unwrap_err(),
            SecurityKeyError::TimedOut
        );
        assert!(returned.load(Ordering::Acquire));
        // The operation-local PIN cancellation must not mutate the connection.
        assert!(!config.attempt.is_cancelled());
    }
}
