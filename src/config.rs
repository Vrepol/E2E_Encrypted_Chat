pub struct PresetServer {
    pub name: &'static str,
    pub addr: &'static str,
}

pub const DEFAULT_SERVER_PORT: u16 = 6655;
pub const DEFAULT_SERVER_PASSWORD: &str = "Vrepol";

pub const CLIENT_SERVER_PRESETS: &[PresetServer] = &[
    PresetServer {
        name: "Public server",
        addr: "8.153.67.166:6655",
    },
    PresetServer {
        name: "Tailscale server",
        addr: "100.123.171.94:6655",
    },
];

pub const CLIENT_DEFAULT_SERVER_INDEX: usize = 0;

pub fn default_client_server() -> &'static PresetServer {
    CLIENT_SERVER_PRESETS
        .get(CLIENT_DEFAULT_SERVER_INDEX)
        .unwrap_or(&CLIENT_SERVER_PRESETS[0])
}
