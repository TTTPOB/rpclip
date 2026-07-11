use serde::{Deserialize, Serialize};
use tarpc;

pub const PROTOCOL_VERSION: u8 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgeEncryptedBlob {
    pub ver: u8,
    pub data: Vec<u8>,
}

impl AgeEncryptedBlob {
    pub fn validate_version(&self) -> Result<(), String> {
        if self.ver == PROTOCOL_VERSION {
            Ok(())
        } else {
            Err(format!(
                "unsupported protocol version {}; expected {}",
                self.ver, PROTOCOL_VERSION
            ))
        }
    }
}

#[tarpc::service]
pub trait RpClip {
    // Client provides its OpenSSH public key line; server returns age-encrypted bytes
    async fn get_clip(client_ssh_pubkey_line: String) -> Result<AgeEncryptedBlob, String>;

    // Client sends ciphertext encrypted for the server
    async fn set_clip(blob: AgeEncryptedBlob) -> Result<(), String>;
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
