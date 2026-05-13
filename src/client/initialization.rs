use colored::*;
use fake::faker::name::raw::*;
use fake::locales::FR_FR;
use fake::Fake;
use std::io;
use std::io::IsTerminal;
use supports_color::{self, Stream as ColorStream};

use crate::client::local_server::{detect_advertise_candidates, spawn_local_server};
use crate::config::{
    default_client_server, CLIENT_SERVER_PRESETS, DEFAULT_SERVER_PASSWORD, DEFAULT_SERVER_PORT,
};
use crate::ui::banner;

pub fn init_color() {
    if std::env::var_os("NO_COLOR").is_some() {
        colored::control::set_override(false);
        return;
    }

    let windows_vt_ok = enable_windows_vt_processing();
    let ok = io::stdout().is_terminal()
        && supports_color::on(ColorStream::Stdout).is_some()
        && windows_vt_ok;

    colored::control::set_override(ok);
}

#[cfg(windows)]
fn enable_windows_vt_processing() -> bool {
    use windows::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, CONSOLE_MODE, ENABLE_PROCESSED_OUTPUT,
        ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_OUTPUT_HANDLE,
    };

    unsafe {
        let Ok(handle) = GetStdHandle(STD_OUTPUT_HANDLE) else {
            return false;
        };
        let mut mode = CONSOLE_MODE(0);
        if GetConsoleMode(handle, &mut mode as *mut CONSOLE_MODE).is_err() {
            return false;
        }

        let desired_mode =
            CONSOLE_MODE(mode.0 | ENABLE_PROCESSED_OUTPUT.0 | ENABLE_VIRTUAL_TERMINAL_PROCESSING.0);
        SetConsoleMode(handle, desired_mode).is_ok()
    }
}

#[cfg(not(windows))]
fn enable_windows_vt_processing() -> bool {
    true
}
fn read_trimmed_line() -> io::Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn get_password_or_default() -> io::Result<String> {
    let input = if io::stdin().is_terminal() {
        rpassword::read_password()?
    } else {
        read_trimmed_line()?
    };
    Ok(if input.trim().is_empty() {
        DEFAULT_SERVER_PASSWORD.to_string()
    } else {
        input.trim().to_string()
    })
}

fn parse_port_or_default(trimmed: &str) -> io::Result<u16> {
    if trimmed.is_empty() {
        Ok(DEFAULT_SERVER_PORT)
    } else {
        let port = trimmed.parse::<u16>().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "端口必须是 1-65535 的数字")
        })?;
        if port == 0 {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "端口必须是 1-65535 的数字",
            ))
        } else {
            Ok(port)
        }
    }
}

fn render_startup(username: Option<&str>, notice: Option<&str>) -> io::Result<()> {
    banner::clear_screen()?;
    banner::print_banner();
    if let Some(username) = username {
        banner::summary("Profile", username);
    }
    if let Some(notice) = notice {
        banner::warning(notice);
    }
    Ok(())
}

fn choose_local_advertised_addr(username: &str, port: u16) -> io::Result<Option<String>> {
    let candidates = detect_advertise_candidates()?;
    let mut notice: Option<String> = None;

    loop {
        render_startup(Some(username), notice.as_deref())?;
        banner::summary("Local port", port);
        banner::section(
            "Invite Address",
            "Choose what other devices should connect to. Type back to change the port.",
        );
        for (i, candidate) in candidates.iter().enumerate() {
            banner::option(i + 1, &candidate.addr, &candidate.label);
        }
        banner::option("manual", "Custom IP or hostname", "");
        banner::option("back", "Return to local server", "");
        banner::prompt(
            "Choice / IP / hostname",
            &format!(
                "[{}]",
                candidates
                    .first()
                    .map(|item| item.addr.as_str())
                    .unwrap_or("127.0.0.1")
            ),
        )?;
        let trimmed = read_trimmed_line()?;

        let host = if trimmed.is_empty() {
            candidates
                .first()
                .map(|item| item.addr.clone())
                .unwrap_or_else(|| "127.0.0.1".to_string())
        } else if trimmed.eq_ignore_ascii_case("back") {
            return Ok(None);
        } else if trimmed.eq_ignore_ascii_case("manual") {
            banner::prompt("Public IP or hostname", "")?;
            let value = read_trimmed_line()?;
            if value.is_empty() {
                notice = Some("公网地址不能为空".to_string());
                continue;
            }
            value
        } else if let Ok(idx) = trimmed.parse::<usize>() {
            match candidates.get(idx.saturating_sub(1)) {
                Some(item) => item.addr.clone(),
                None => {
                    notice = Some("无效的地址选项".to_string());
                    continue;
                }
            }
        } else {
            trimmed
        };

        return Ok(Some(format!("{host}:{port}")));
    }
}
pub fn initial_name() -> io::Result<String> {
    render_startup(None, None)?;
    banner::section("Profile", "Press Enter to use a generated nickname.");
    banner::prompt("Nickname", "[random]")?;
    let input = read_trimmed_line()?;
    let username = match input.as_str() {
        "" => FirstName(FR_FR).fake(),
        name => name.to_owned(),
    };
    banner::success(format!("Signed in as {}", username.as_str().bold()));
    Ok(username)
}

fn configure_local_server(username: &str) -> io::Result<Option<String>> {
    let mut notice: Option<String> = None;

    loop {
        render_startup(Some(username), notice.as_deref())?;
        banner::section(
            "Local Server",
            "Start a private server on this machine. Type back to return.",
        );
        banner::prompt("Local port", &format!("[{}]", DEFAULT_SERVER_PORT))?;
        let port_input = read_trimmed_line()?;
        if port_input.eq_ignore_ascii_case("back") {
            return Ok(None);
        }
        let port = match parse_port_or_default(&port_input) {
            Ok(port) => port,
            Err(err) => {
                notice = Some(err.to_string());
                continue;
            }
        };

        let Some(addr) = choose_local_advertised_addr(username, port)? else {
            notice = None;
            continue;
        };

        render_startup(Some(username), None)?;
        banner::summary("Local port", port);
        banner::summary("Advertise", &addr);
        banner::section("Local Server", "Set the server password before starting.");
        banner::prompt("Server password", "[default hidden]")?;
        let key = get_password_or_default()?;
        match spawn_local_server(port, &key) {
            Ok(()) => {
                render_startup(Some(username), None)?;
                banner::success(format!("Local server listening on 127.0.0.1:{port}"));
                banner::note(format!("Advertised as {addr}"));
                return Ok(Some(format!("{addr}&{key}")));
            }
            Err(err) => {
                notice = Some(format!("启动本地服务器失败: {err}"));
            }
        }
    }
}

pub fn initial_serveraddr(username: &str) -> io::Result<String> {
    // 交互循环直到拿到合法输入
    let host_port_re = regex::Regex::new(r"^[A-Za-z0-9.\-]+:\d+$").expect("regex should compile");
    let mut notice: Option<String> = None;
    let chosen = loop {
        render_startup(Some(username), notice.as_deref())?;
        banner::section(
            "Connect",
            "Pick a preset, paste an invite, enter host:port, or start locally.",
        );
        for (i, server) in CLIENT_SERVER_PRESETS.iter().enumerate() {
            banner::option(i + 1, &server.name, &server.addr);
        }
        banner::option("host", "Start local server", "");
        banner::prompt("Choice", "number / host:port / host / /INVITE:...")?;

        let s = read_trimmed_line()?;
        if s.is_empty() {
            let server = default_client_server();
            render_startup(Some(username), None)?;
            banner::success(format!("Using default server: {}", server.name));
            break format!("{}&{}", server.addr, DEFAULT_SERVER_PASSWORD);
        }
        if s.eq_ignore_ascii_case("host") {
            if let Some(server_addr) = configure_local_server(username)? {
                break server_addr;
            }
            notice = None;
            continue;
        }
        // 1️⃣ 数字
        if let Ok(idx) = s.parse::<usize>() {
            if let Some(server) = CLIENT_SERVER_PRESETS.get(idx - 1) {
                banner::prompt("Server password", "[default hidden]")?;
                let key = get_password_or_default()?;
                render_startup(Some(username), None)?;
                banner::success(format!("Connecting to {}", server.name));
                break format!("{}&{}", server.addr, key);
            }
        }
        // 2️⃣ host:port / IP:port
        if host_port_re.is_match(&s) {
            banner::prompt("Server password", "[default hidden]")?;
            let key = get_password_or_default()?;
            render_startup(Some(username), None)?;
            banner::success(format!("Connecting to {s}"));
            break format!("{}&{}", s, key);
        }
        // 3️⃣ 邀请码
        if s.starts_with("/INVITE:") {
            render_startup(Some(username), None)?;
            banner::success("Using invite code");
            break s;
        }
        notice = Some("Enter a choice, host:port, host, or invite code.".to_string());
    };

    Ok(chosen)
}
