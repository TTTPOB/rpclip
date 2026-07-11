use age::ssh;
use age::{Decryptor, Encryptor};
use arboard::Clipboard;
use clap::Parser;
use futures::prelude::*;
use log::{error, info};
use rpclip::auth::{self, AuthorizedClients, ChallengeStore, ServerAuthenticator, CHALLENGE_TTL};
use rpclip::{
    AgeEncryptedBlob, AuthRequest, Challenge, ChallengeRequest, RpClip, SetRequest,
    SignedClipboard, SignedSetResponse, PROTOCOL_VERSION,
};
use std::str::FromStr;
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tarpc::{
    context,
    server::{
        self,
        incoming::{spawn_incoming, Incoming},
    },
    tokio_serde::formats::Bincode,
};

const MAX_OPEN_CHANNELS: u32 = 64;
const MAX_CONCURRENT_REQUESTS_PER_CHANNEL: usize = 8;

#[derive(Parser)]
struct Args {
    #[arg(short, long, value_name = "IP:PORT", required = true)]
    address: Vec<SocketAddr>,
    /// Unencrypted Ed25519 server private key. Defaults to ~/.ssh/id_ed25519
    #[arg(long)]
    ssh_key_path: Option<String>,
    /// OpenSSH authorized_keys file. Defaults to the platform OpenSSH user file
    #[arg(long)]
    authorized_keys_path: Option<String>,
}

#[derive(Clone)]
struct RpClipServer {
    clipboard: Arc<Mutex<Clipboard>>,
    ssh_key_path: String,
    authenticator: Arc<ServerAuthenticator>,
}

impl RpClip for RpClipServer {
    async fn issue_challenge(
        self,
        _: context::Context,
        request: ChallengeRequest,
    ) -> Result<Challenge, String> {
        self.authenticator.issue_challenge(&request)
    }

    async fn get_clip(
        self,
        _: context::Context,
        auth_request: AuthRequest,
    ) -> Result<SignedClipboard, String> {
        self.authenticator.authenticate_get(&auth_request)?;

        let clipboard = self.clipboard.clone();
        let authenticator = self.authenticator.clone();
        tokio::task::spawn_blocking(move || {
            let blob = encrypt_clipboard(clipboard, auth_request.client_ssh_pubkey.clone())?;
            authenticator.sign_get_response(&auth_request, blob)
        })
        .await
        .map_err(|e| format!("clipboard worker failed: {e}"))?
    }

    async fn set_clip(
        self,
        _: context::Context,
        request: SetRequest,
    ) -> Result<SignedSetResponse, String> {
        self.authenticator.authenticate_set(&request)?;
        let response = self.authenticator.sign_set_response(&request)?;

        let clipboard = self.clipboard.clone();
        let ssh_key_path = self.ssh_key_path.clone();
        let blob = request.blob;
        tokio::task::spawn_blocking(move || {
            decrypt_and_set_clipboard(clipboard, ssh_key_path, blob)
        })
        .await
        .map_err(|e| format!("clipboard worker failed: {e}"))??;
        Ok(response)
    }
}

fn encrypt_clipboard(
    clipboard: Arc<Mutex<Clipboard>>,
    client_ssh_pubkey_line: String,
) -> Result<AgeEncryptedBlob, String> {
    let text = match clipboard
        .lock()
        .map_err(|_| "clipboard lock is poisoned".to_string())?
        .get_text()
    {
        Ok(text) => {
            info!("server got clipboard text (len={} bytes)", text.len());
            text
        }
        Err(e) => {
            error!("server failed to open system clipboard: {e}");
            return Err(format!("failed to read system clipboard: {e}"));
        }
    };

    // Encrypt to client's SSH public key
    let recipient = match ssh::Recipient::from_str(&client_ssh_pubkey_line) {
        Ok(r) => r,
        Err(e) => {
            error!("invalid client ssh pubkey: {:?}", e);
            return Err(format!("invalid client SSH public key: {e:?}"));
        }
    };
    let recipients: Vec<&dyn age::Recipient> = vec![&recipient as &dyn age::Recipient];
    let encryptor = match Encryptor::with_recipients(recipients.into_iter()) {
        Ok(e) => e,
        Err(e) => {
            error!("encryptor error: {}", e);
            return Err(format!("failed to initialize clipboard encryption: {e}"));
        }
    };
    let mut out = Vec::new();
    let mut writer = match encryptor.wrap_output(&mut out) {
        Ok(writer) => writer,
        Err(e) => {
            error!("wrap_output error: {}", e);
            return Err(format!("failed to initialize encrypted response: {e}"));
        }
    };
    use std::io::Write;
    if let Err(e) = writer.write_all(text.as_bytes()) {
        error!("encrypt write error: {}", e);
        return Err(format!("failed to encrypt clipboard data: {e}"));
    }
    if let Err(e) = writer.finish() {
        error!("encrypt finish error: {}", e);
        return Err(format!("failed to finish clipboard encryption: {e}"));
    }

    Ok(AgeEncryptedBlob {
        ver: PROTOCOL_VERSION,
        data: out,
    })
}

fn decrypt_and_set_clipboard(
    clipboard: Arc<Mutex<Clipboard>>,
    ssh_key_path: String,
    blob: AgeEncryptedBlob,
) -> Result<(), String> {
    let key_path = expand_tilde(&ssh_key_path);
    let key_bytes = match std::fs::read(&key_path) {
        Ok(b) => b,
        Err(e) => {
            error!("failed to read ssh key {}: {}", key_path, e);
            return Err(format!("failed to read server SSH key: {e}"));
        }
    };
    let identity =
        match ssh::Identity::from_buffer(std::io::Cursor::new(key_bytes), Some(key_path.clone())) {
            Ok(i) => i,
            Err(e) => {
                error!("failed to parse ssh identity {}: {:?}", key_path, e);
                return Err(format!("failed to parse server SSH identity: {e:?}"));
            }
        };
    let decryptor = match Decryptor::new(&blob.data[..]) {
        Ok(d) => d,
        Err(e) => {
            error!("decryptor error: {}", e);
            return Err(format!("failed to read encrypted clipboard data: {e}"));
        }
    };
    let mut reader = match decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity)) {
        Ok(r) => r,
        Err(e) => {
            error!("decrypt error: {}", e);
            return Err(format!("failed to decrypt clipboard data: {e}"));
        }
    };
    use std::io::Read;
    let mut plaintext = Vec::new();
    if let Err(e) = reader.read_to_end(&mut plaintext) {
        error!("decrypt read error: {}", e);
        return Err(format!("failed to decrypt clipboard data: {e}"));
    }

    let text = match String::from_utf8(plaintext) {
        Ok(s) => s,
        Err(e) => {
            error!("utf8 error: {}", e);
            return Err(format!("clipboard data is not valid UTF-8: {e}"));
        }
    };

    if let Err(e) = clipboard
        .lock()
        .map_err(|_| "clipboard lock is poisoned".to_string())?
        .set_text(rpclip::line_end::to_platform_line_ending(&text))
    {
        error!("server failed to set clipboard text: {e}");
        Err(format!("failed to set system clipboard: {e}"))
    } else {
        info!("server set clipboard text (len={} bytes)", text.len());
        Ok(())
    }
}

fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest).to_string_lossy().into_owned();
        }
    }
    path.to_string()
}

fn authorized_keys_path_for(
    home: &std::path::Path,
    windows_administrator: bool,
    program_data: Option<&std::ffi::OsStr>,
) -> Result<PathBuf, String> {
    if windows_administrator {
        let program_data = program_data.ok_or_else(|| {
            "ProgramData is not set; pass --authorized-keys-path explicitly".to_string()
        })?;
        Ok(PathBuf::from(program_data)
            .join("ssh")
            .join("administrators_authorized_keys"))
    } else {
        Ok(home.join(".ssh").join("authorized_keys"))
    }
}

fn default_authorized_keys_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| {
        "cannot determine home directory; pass --authorized-keys-path".to_string()
    })?;
    #[cfg(windows)]
    {
        return authorized_keys_path_for(
            &home,
            current_user_is_windows_administrator()?,
            std::env::var_os("ProgramData").as_deref(),
        );
    }
    #[cfg(not(windows))]
    authorized_keys_path_for(&home, false, None)
}

#[cfg(windows)]
fn current_user_is_windows_administrator() -> Result<bool, String> {
    use std::ptr::{null_mut, NonNull};
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        AllocateAndInitializeSid, EqualSid, FreeSid, GetTokenInformation, TokenGroups,
        SECURITY_NT_AUTHORITY, TOKEN_GROUPS, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::SystemServices::{
        DOMAIN_ALIAS_RID_ADMINS, SECURITY_BUILTIN_DOMAIN_RID,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut administrator_sid = null_mut();
    let allocated = unsafe {
        AllocateAndInitializeSid(
            &SECURITY_NT_AUTHORITY,
            2,
            SECURITY_BUILTIN_DOMAIN_RID as u32,
            DOMAIN_ALIAS_RID_ADMINS as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut administrator_sid,
        )
    };
    if allocated == 0 {
        return Err(format!(
            "failed to determine Windows administrator membership: {}",
            std::io::Error::last_os_error()
        ));
    }
    let administrator_sid =
        NonNull::new(administrator_sid).expect("AllocateAndInitializeSid returned a null SID");

    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        unsafe {
            FreeSid(administrator_sid.as_ptr());
        }
        return Err(format!(
            "failed to open the Windows process token: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut required_bytes = 0;
    unsafe {
        GetTokenInformation(token, TokenGroups, null_mut(), 0, &mut required_bytes);
    }
    if required_bytes == 0 {
        unsafe {
            CloseHandle(token);
            FreeSid(administrator_sid.as_ptr());
        }
        return Err(format!(
            "failed to size the Windows token group list: {}",
            std::io::Error::last_os_error()
        ));
    }
    let word_size = std::mem::size_of::<usize>();
    let mut buffer = vec![0_usize; (required_bytes as usize).div_ceil(word_size)];
    let loaded = unsafe {
        GetTokenInformation(
            token,
            TokenGroups,
            buffer.as_mut_ptr().cast(),
            required_bytes,
            &mut required_bytes,
        )
    };
    if loaded == 0 {
        unsafe {
            CloseHandle(token);
            FreeSid(administrator_sid.as_ptr());
        }
        return Err(format!(
            "failed to read the Windows token group list: {}",
            std::io::Error::last_os_error()
        ));
    }

    let groups = buffer.as_ptr().cast::<TOKEN_GROUPS>();
    let is_member = unsafe {
        std::slice::from_raw_parts((*groups).Groups.as_ptr(), (*groups).GroupCount as usize)
            .iter()
            .any(|group| EqualSid(group.Sid, administrator_sid.as_ptr()) != 0)
    };
    unsafe {
        CloseHandle(token);
        FreeSid(administrator_sid.as_ptr());
    }
    Ok(is_member)
}

fn load_server_security(
    ssh_key_path: Option<String>,
    authorized_keys_path: Option<String>,
) -> Result<(String, Arc<ServerAuthenticator>), String> {
    let ssh_key_path =
        expand_tilde(&ssh_key_path.unwrap_or_else(|| "~/.ssh/id_ed25519".to_string()));
    let authorized_keys_path = match authorized_keys_path {
        Some(path) => PathBuf::from(expand_tilde(&path)),
        None => default_authorized_keys_path()?,
    };
    let private_key = auth::read_server_private_key(PathBuf::from(&ssh_key_path).as_path())?;
    let authorized_clients = AuthorizedClients::read_file(&authorized_keys_path)?;
    info!(
        "Loaded client authorization keys from {}",
        authorized_keys_path.display()
    );
    let authenticator = ServerAuthenticator::new(
        Arc::new(private_key),
        Arc::new(authorized_clients),
        Arc::new(ChallengeStore::new(CHALLENGE_TTL)),
    );
    Ok((ssh_key_path, Arc::new(authenticator)))
}

#[tokio::main]
async fn main() {
    env_logger::init();
    // Parse command line arguments
    let args = Args::parse();
    let (ssh_key_path, authenticator) =
        load_server_security(args.ssh_key_path, args.authorized_keys_path).unwrap_or_else(|e| {
            error!("Unable to initialize server authentication: {e}");
            std::process::exit(1);
        });
    let mut listeners = Vec::with_capacity(args.address.len());
    for listen_addr in args.address {
        let listener = tarpc::serde_transport::tcp::listen(&listen_addr, Bincode::default)
            .await
            .unwrap_or_else(|e| panic!("Failed to listen on {listen_addr}: {e}"));
        info!("Listening on: {}", listen_addr);
        listeners.push(listener);
    }

    let clipboard = Arc::new(Mutex::new(
        tokio::task::spawn_blocking(Clipboard::new)
            .await
            .expect("clipboard worker failed")
            .expect("failed to initialize system clipboard"),
    ));
    info!("Clipboard server started");
    let rpserver = RpClipServer {
        clipboard,
        ssh_key_path,
        authenticator,
    };
    let incoming = futures::stream::select_all(listeners)
        .filter_map(|result| {
            future::ready(match result {
                Ok(transport) => Some(transport),
                Err(e) => {
                    error!("Failed to accept client connection: {e}");
                    None
                }
            })
        })
        .map(server::BaseChannel::with_defaults)
        .max_channels_per_key(MAX_OPEN_CHANNELS, |_| "global")
        .max_concurrent_requests_per_channel(MAX_CONCURRENT_REQUESTS_PER_CHANNEL)
        .execute(rpserver.serve());
    spawn_incoming(incoming).await;
    error!("All server listeners stopped");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_multiple_listen_addresses() {
        let args = Args::try_parse_from([
            "rpclip-server",
            "--address",
            "127.0.0.1:6667",
            "--address",
            "[::1]:6667",
            "--authorized-keys-path",
            "authorized_keys",
        ])
        .unwrap();

        assert_eq!(
            args.address,
            [
                "127.0.0.1:6667".parse().unwrap(),
                "[::1]:6667".parse().unwrap(),
            ]
        );
        assert_eq!(
            args.authorized_keys_path.as_deref(),
            Some("authorized_keys")
        );
    }

    #[test]
    fn selects_openssh_authorized_keys_paths() {
        let home = std::path::Path::new("users/example");
        assert_eq!(
            authorized_keys_path_for(home, false, None).unwrap(),
            home.join(".ssh").join("authorized_keys")
        );
        assert_eq!(
            authorized_keys_path_for(home, true, Some(std::ffi::OsStr::new("program-data")),)
                .unwrap(),
            PathBuf::from("program-data")
                .join("ssh")
                .join("administrators_authorized_keys")
        );
        assert!(authorized_keys_path_for(home, true, None).is_err());
    }
}
