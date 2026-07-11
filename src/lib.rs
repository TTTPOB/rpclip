use serde::{Deserialize, Serialize};
use tarpc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgeEncryptedBlob {
    pub ver: u8,
    pub data: Vec<u8>,
}

#[tarpc::service]
pub trait RpClip {
    // Client provides its OpenSSH public key line; server returns age-encrypted bytes
    async fn get_clip(client_ssh_pubkey_line: String) -> AgeEncryptedBlob;

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
        let lines: Vec<&str> = text.lines().collect();
        let result = lines.join(LINE_ENDING);
        result
    }
}
