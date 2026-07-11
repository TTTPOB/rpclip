use serde::{Deserialize, Serialize};

pub mod auth;

pub const PROTOCOL_VERSION: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClipboardOperation {
    Get,
    Set,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub ver: u8,
    pub operation: ClipboardOperation,
    pub client_ssh_pubkey: String,
}

impl ChallengeRequest {
    pub fn validate_version(&self) -> Result<(), String> {
        validate_version(self.ver)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub ver: u8,
    pub operation: ClipboardOperation,
    pub client_fingerprint: String,
    pub nonce: [u8; 32],
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub signature: String,
}

impl Challenge {
    pub fn validate_version(&self) -> Result<(), String> {
        validate_version(self.ver)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgeEncryptedBlob {
    pub ver: u8,
    pub data: Vec<u8>,
}

impl AgeEncryptedBlob {
    pub fn validate_version(&self) -> Result<(), String> {
        validate_version(self.ver)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub ver: u8,
    pub client_ssh_pubkey: String,
    pub challenge: Challenge,
    pub signature: String,
}

impl AuthRequest {
    pub fn validate_version(&self) -> Result<(), String> {
        validate_version(self.ver)?;
        self.challenge.validate_version()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetRequest {
    pub auth: AuthRequest,
    pub blob: AgeEncryptedBlob,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedClipboard {
    pub ver: u8,
    pub blob: AgeEncryptedBlob,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedSetResponse {
    pub ver: u8,
    pub signature: String,
}

impl SignedSetResponse {
    pub fn validate_version(&self) -> Result<(), String> {
        validate_version(self.ver)
    }
}

impl SignedClipboard {
    pub fn validate_version(&self) -> Result<(), String> {
        validate_version(self.ver)?;
        self.blob.validate_version()
    }
}

fn validate_version(version: u8) -> Result<(), String> {
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(format!(
            "unsupported protocol version {}; expected {}",
            version, PROTOCOL_VERSION
        ))
    }
}

#[tarpc::service]
pub trait RpClip {
    async fn issue_challenge(request: ChallengeRequest) -> Result<Challenge, String>;

    async fn get_clip(auth: AuthRequest) -> Result<SignedClipboard, String>;

    async fn set_clip(request: SetRequest) -> Result<SignedSetResponse, String>;
}

pub mod line_end {
    #[cfg(target_os = "windows")]
    const LINE_ENDING: &str = "\r\n";
    #[cfg(target_os = "macos")]
    const LINE_ENDING: &str = "\r";
    #[cfg(target_os = "linux")]
    const LINE_ENDING: &str = "\n";

    pub fn to_platform_line_ending(text: &str) -> String {
        text.replace("\r\n", "\n")
            .replace('\r', "\n")
            .replace('\n', LINE_ENDING)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn preserves_trailing_line_ending() {
            assert_eq!(
                to_platform_line_ending("first\nsecond\n"),
                format!("first{LINE_ENDING}second{LINE_ENDING}")
            );
        }

        #[test]
        fn preserves_empty_lines() {
            assert_eq!(
                to_platform_line_ending("first\r\n\r\nsecond\r"),
                format!("first{LINE_ENDING}{LINE_ENDING}second{LINE_ENDING}")
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_encrypted_blob_version() {
        let supported = AgeEncryptedBlob {
            ver: PROTOCOL_VERSION,
            data: Vec::new(),
        };
        let unsupported = AgeEncryptedBlob {
            ver: PROTOCOL_VERSION + 1,
            data: Vec::new(),
        };

        assert_eq!(supported.validate_version(), Ok(()));
        assert_eq!(
            unsupported.validate_version(),
            Err(format!(
                "unsupported protocol version {}; expected {}",
                PROTOCOL_VERSION + 1,
                PROTOCOL_VERSION
            ))
        );
    }
}
