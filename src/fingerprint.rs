//! Fingerprint-gated vault unlock.
//!
//! Every fingerprint unlock must carry an explicit *intent*, a short,
//! human-readable reason for accessing the vault. The intent is displayed in
//! the desktop notification together with the caller process, the query being
//! looked up, and the outcome, so the user can audit exactly why their vault
//! was opened.

use anyhow::{anyhow, Result};
use std::process::Command;

use crate::crypto::SymmetricKey;
use crate::protected_key;

/// Context describing who is unlocking the vault and why.
#[derive(Debug, Clone)]
pub struct UnlockContext {
    /// Required, human-readable reason for the unlock (e.g. "autofill github.com").
    pub intent: String,
    /// The vault operation being performed (e.g. "get github.com", "list").
    pub operation: String,
}

/// Information about the process chain that requested the unlock.
#[derive(Debug, Clone)]
pub struct CallerInfo {
    pub pid: u32,
    pub name: String,
    pub parent_name: Option<String>,
}

impl CallerInfo {
    pub fn detect() -> Self {
        let pid = std::process::id();
        let parent_pid = read_ppid(pid);
        let parent_name = parent_pid.and_then(read_comm);
        let grandparent_name = parent_pid
            .and_then(read_ppid_of)
            .and_then(read_comm)
            .filter(|n| n != "systemd" && !n.is_empty());

        // The immediate parent is usually the shell; the grandparent is often
        // the more interesting caller (terminal, script, agent).
        let name = parent_name.clone().unwrap_or_else(|| "unknown".into());
        CallerInfo {
            pid: parent_pid.unwrap_or(pid),
            name,
            parent_name: grandparent_name,
        }
    }

    fn describe(&self) -> String {
        match &self.parent_name {
            Some(p) => format!("{} (pid {}, via {})", self.name, self.pid, p),
            None => format!("{} (pid {})", self.name, self.pid),
        }
    }
}

fn read_ppid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // Field 4 (after the parenthesised comm, which may contain spaces).
    let after = stat.rsplit_once(')').map(|(_, rest)| rest)?;
    after.split_whitespace().nth(1)?.parse().ok()
}

fn read_ppid_of(pid: u32) -> Option<u32> {
    read_ppid(pid)
}

fn read_comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
}

fn validate_intent(intent: &str) -> Result<()> {
    let trimmed = intent.trim();
    if trimmed.is_empty() {
        return Err(anyhow!(
            "Fingerprint unlock requires a non-empty --intent describing why the vault is being accessed."
        ));
    }
    if trimmed.len() < 4 {
        return Err(anyhow!(
            "Intent '{}' is too short. Provide a meaningful reason (e.g. --intent \"log in to github.com\").",
            trimmed
        ));
    }
    Ok(())
}

fn notify(urgency: &str, summary: &str, body: &str) {
    // Best-effort: notification failure must never block or break unlocking.
    let _ = Command::new("notify-send")
        .arg("--app-name=bronzewarden")
        .arg(format!("--urgency={}", urgency))
        .arg("--icon=dialog-password")
        .arg(summary)
        .arg(body)
        .status();
}

fn notification_body(ctx: &UnlockContext, caller: &CallerInfo, outcome: Option<&str>) -> String {
    let mut body = format!(
        "Intent: {}\nOperation: {}\nCaller: {}",
        ctx.intent.trim(),
        ctx.operation,
        caller.describe()
    );
    if let Some(outcome) = outcome {
        body.push_str(&format!("\nResult: {}", outcome));
    }
    body
}

fn run_fprintd_verify() -> Result<()> {
    let status = Command::new("fprintd-verify")
        .status()
        .map_err(|e| anyhow!("Failed to run fprintd-verify: {} (is fprintd installed?)", e))?;
    if !status.success() {
        return Err(anyhow!("Fingerprint verification failed or was cancelled"));
    }
    Ok(())
}

/// Verify the user's fingerprint and, on success, load the cached vault key.
///
/// A desktop notification is shown before the scan (so the user knows why
/// their fingerprint is being requested) and after (with the outcome).
pub fn verify_and_unlock(ctx: &UnlockContext) -> Result<SymmetricKey> {
    validate_intent(&ctx.intent)?;

    if !protected_key::has_protected_key() {
        return Err(anyhow!(
            "Fingerprint unlock is not set up. Run `bronzewarden setup-fingerprint` first."
        ));
    }

    let caller = CallerInfo::detect();

    notify(
        "critical",
        "🔐 Fingerprint requested",
        &notification_body(ctx, &caller, None),
    );
    eprintln!("Touch the fingerprint sensor to unlock the vault...");
    eprintln!("  intent:    {}", ctx.intent.trim());
    eprintln!("  operation: {}", ctx.operation);

    match run_fprintd_verify() {
        Ok(()) => {}
        Err(e) => {
            notify(
                "critical",
                "❌ Vault unlock denied",
                &notification_body(ctx, &caller, Some("fingerprint verification failed")),
            );
            return Err(e);
        }
    }

    match protected_key::load_protected_key() {
        Ok(key) => {
            notify(
                "normal",
                "🔓 Vault unlocked",
                &notification_body(ctx, &caller, Some("fingerprint verified, key released")),
            );
            Ok(key)
        }
        Err(e) => {
            notify(
                "critical",
                "❌ Vault unlock failed",
                &notification_body(ctx, &caller, Some("fingerprint OK but key load failed")),
            );
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intent_required() {
        assert!(validate_intent("").is_err());
        assert!(validate_intent("   ").is_err());
        assert!(validate_intent("ab").is_err());
        assert!(validate_intent("log in to github.com").is_ok());
    }

    #[test]
    fn test_caller_detect_does_not_panic() {
        let caller = CallerInfo::detect();
        assert!(!caller.name.is_empty());
    }
}
