use tarpc;
#[tarpc::service]
pub trait RpClip {
    async fn get_clip() -> String;
    async fn set_clip(text: String);
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
