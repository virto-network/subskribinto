// Copyright (c) Virto Network
// SPDX-License-Identifier: MIT

//! Asking the person at the computer to approve an operation, in a way a model driving this tool
//! can't answer for them.
//!
//! - macOS: LocalAuthentication (Touch ID, or the account password). The dialog is drawn by the
//!   system, and neither a fingerprint nor the password is something the model has.
//! - Elsewhere: a confirmation typed in an interactive terminal. This is weaker (an agent can fake
//!   a terminal), so restricted proxies and narrow policies matter more on those platforms.

/// Whether [`confirm`] is backed by the operating system rather than by a terminal prompt.
pub const STRONG: bool = cfg!(target_os = "macos");

/// Ask the user to approve `reason` (a short phrase, e.g. "sign Balances.transfer as ops").
/// Fails unless they explicitly do.
pub async fn confirm(reason: &str) -> anyhow::Result<()> {
    let reason = reason.to_owned();
    tokio::task::spawn_blocking(move || imp::confirm(&reason))
        .await
        .map_err(|e| anyhow::anyhow!("Confirmation failed: {e}"))?
}

#[cfg(target_os = "macos")]
mod imp {
    use std::sync::mpsc;

    use anyhow::anyhow;
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    pub fn confirm(reason: &str) -> anyhow::Result<()> {
        // Touch ID when available, the account password otherwise.
        let policy = LAPolicy::DeviceOwnerAuthentication;
        let context = unsafe { LAContext::new() };
        unsafe { context.canEvaluatePolicy_error(policy) }
            .map_err(|e| anyhow!("Cannot ask for your approval: {}", e.localizedDescription()))?;

        let (tx, rx) = mpsc::channel();
        let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
            let result = if success.as_bool() {
                Ok(())
            } else {
                // SAFETY: LocalAuthentication passes either null or a valid NSError.
                let reason = unsafe { error.as_ref() }
                    .map(|e| e.localizedDescription().to_string())
                    .unwrap_or_else(|| "not approved".into());
                Err(anyhow!("Not approved: {reason}"))
            };
            let _ = tx.send(result);
        });
        unsafe {
            context.evaluatePolicy_localizedReason_reply(
                policy,
                &NSString::from_str(reason),
                &reply,
            )
        };
        // Keep `context` alive until the reply: releasing it cancels the evaluation.
        let result = rx.recv().map_err(|_| anyhow!("Not approved"))?;
        drop(context);
        result
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use std::io::IsTerminal;

    use anyhow::{bail, ensure};

    pub fn confirm(reason: &str) -> anyhow::Result<()> {
        ensure!(
            std::io::stdin().is_terminal() && std::io::stderr().is_terminal(),
            "Approving this needs an interactive terminal"
        );
        let approved = inquire::Confirm::new(&format!("Approve: {reason}?"))
            .with_default(false)
            .prompt()?;
        if !approved {
            bail!("Not approved");
        }
        Ok(())
    }
}
