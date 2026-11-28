# Native FIDO2 SSH authentication

Import an existing OpenSSH `ED25519-SK` or `ECDSA-SK` private-key reference in
Security → Keys, then select it using the connection's private-key authentication
method. The matching security key must be connected. The public key can be copied
from the key manager and installed in the server's `authorized_keys`.

An encrypted reference file may have a file passphrase. This is separate from the
security key's device PIN. Device PINs are requested only during authentication
and are never saved in the credential store, backups or sync data.

Windows uses the Windows Security dialog through system WebAuthn, without
OpenSSH, an agent service or administrator privileges. On macOS and Linux the
application talks to USB keys directly and displays its own PIN/touch prompts.
Linux requires ordinary-user access to the device's hidraw interface; use the
security-key vendor's or distribution's udev rules. Running NyaTerm as root is
not required. Hardware requests are serialized across workspace windows.

Both algorithms require compatible hardware and an SSH server accepting their
OpenSSH key types. A key allowing authentication without touch may still require
a touch in NyaTerm. The application does not weaken a key's PIN/user-verification
requirement. Cancel or reconnect to retry an interrupted authentication.

This version supports imported references (including a reference to a resident
credential) and matching SSH certificates. It does not create keys, discover
resident credentials, reset devices or manage PINs. Saved hardware keys are not
advertised through the built-in saved-key agent forwarding source. Existing
external-agent authentication and forwarding remain available.

## Implementation and validation

Transport owns the platform adapters and OpenSSH signing; desktop owns the shared
service and prompt lifecycle. A cancelled SSH future signals the hardware worker;
the worker retains the shared lease through device cleanup. The USB dependency's
raw logs are excluded from every application log sink, even with `RUST_LOG=trace`.

Automated tests use deterministic software devices to generate actual FIDO-format
signatures, exercise both algorithms against a verifying SSH server, test
multi-factor continuation and cancellation, and check storage/backup compatibility.
They do not access real security keys.

Use the same thread-stack setting as workspace CI for debug GPUI tests:

```sh
cargo check --workspace
RUST_MIN_STACK=16777216 cargo test --workspace --locked --no-fail-fast
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
```

Release acceptance must additionally run on Windows, macOS and Linux with a USB
key supporting each algorithm. Test ordinary-user access, encrypted reference
import, successful login, PIN failure, required user verification, touch, device
removal, cancellation during PIN/touch, multiple queued connections, window close,
jump-host authentication and authentication followed by password/OTP. Verify
packaged applications on the supported architectures. Record these as pending
until actual platform and hardware runs have completed; cross-compilation and
mock tests alone do not establish device compatibility.
