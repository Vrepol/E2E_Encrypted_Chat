use std::io::{self, Write};
use fake::Fake;
use fake::locales::{FR_FR};
use fake::faker::name::raw::*;
use colored::*;
use std::io::IsTerminal;
use supports_color::{self,Stream as ColorStream};

use crate::app_config::{
    default_client_server, CLIENT_SERVER_PRESETS, DEFAULT_SERVER_PASSWORD, DEFAULT_SERVER_PORT,
};
use crate::client::local_server::{detect_advertise_candidates, spawn_local_server};

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
        CONSOLE_MODE, GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_PROCESSED_OUTPUT,
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

        let desired_mode = CONSOLE_MODE(
            mode.0 | ENABLE_PROCESSED_OUTPUT.0 | ENABLE_VIRTUAL_TERMINAL_PROCESSING.0
        );
        SetConsoleMode(handle, desired_mode).is_ok()
    }
}

#[cfg(not(windows))]
fn enable_windows_vt_processing() -> bool {
    true
}
fn get_password_or_default()->String {
    let mut inp = String::new();
    let _ = io::stdin().read_line(&mut inp);
    if inp.trim().is_empty() {
        DEFAULT_SERVER_PASSWORD.to_string()
    } else {
        inp.trim().to_string()
    }
}

fn get_port_or_default() -> io::Result<u16> {
    let mut inp = String::new();
    io::stdin().read_line(&mut inp)?;
    let trimmed = inp.trim();
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

fn choose_local_advertised_addr(port: u16) -> io::Result<String> {
    let candidates = detect_advertise_candidates()?;

    println!("Advertised address for invites:");
    for (i, candidate) in candidates.iter().enumerate() {
        println!("  {}. {} ({})", i + 1, candidate.addr, candidate.label);
    }
    println!("  manual. Enter a custom IP or hostname");
    print!("Choice / IP / hostname [{}]: ", candidates
        .first()
        .map(|item| item.addr.as_str())
        .unwrap_or("127.0.0.1"));
    io::stdout().flush()?;

    let mut inp = String::new();
    io::stdin().read_line(&mut inp)?;
    let trimmed = inp.trim();

    let host = if trimmed.is_empty() {
        candidates
            .first()
            .map(|item| item.addr.clone())
            .unwrap_or_else(|| "127.0.0.1".to_string())
    } else if trimmed.eq_ignore_ascii_case("manual") {
        print!("Public IP or hostname: ");
        io::stdout().flush()?;
        let mut manual = String::new();
        io::stdin().read_line(&mut manual)?;
        let value = manual.trim();
        if value.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "公网地址不能为空",
            ));
        }
        value.to_string()
    } else if let Ok(idx) = trimmed.parse::<usize>() {
        candidates
            .get(idx.saturating_sub(1))
            .map(|item| item.addr.clone())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "无效的地址选项"))?
    } else {
        trimmed.to_string()
    };

    Ok(format!("{host}:{port}"))
}
pub fn initial_name() -> io::Result<String> {
    // ---------- 询问昵称 ----------
    let username = loop {
        println!("{}","Continue with fake name".purple());
        print!("{}","      Or customize here: ".purple());
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let name = input.trim();
        if !name.is_empty() {
            break name.to_owned();
        } else {
            let name: String = FirstName(FR_FR).fake();
            break name.to_owned()
        }
    };
    println!("{} {}","Enjoy youself, ".green(),username.clone().to_string().green());
    Ok(username)
}
pub fn initial_serveraddr() -> io::Result<String> {
    // 交互循环直到拿到合法输入
    let chosen = loop {
        println!("\nAvaliable Servers:");
        for (i, server) in CLIENT_SERVER_PRESETS.iter().enumerate() {
            println!("  {}. {}", i + 1, server.name);
        }
        println!("  host. Start local server");
        print!("Choice / IP:Port / host / /INVITE:…  ➜ ");
        io::stdout().flush()?;

        let mut inp = String::new();
        io::stdin().read_line(&mut inp)?;
        let s = inp.trim();
        if s.is_empty() {
            let server = default_client_server();
            println!("Default Choice : {}", server.name);
            break format!("{}&{}", server.addr, DEFAULT_SERVER_PASSWORD);
        }
        if s.eq_ignore_ascii_case("host") {
            print!("Local Port [{}]: ", DEFAULT_SERVER_PORT);
            io::stdout().flush()?;
            let port = match get_port_or_default() {
                Ok(port) => port,
                Err(err) => {
                    println!("{err}");
                    continue;
                }
            };

            print!("Server Password: ");
            io::stdout().flush()?;
            let key = get_password_or_default();
            match spawn_local_server(port, &key) {
                Ok(()) => {
                    let addr = match choose_local_advertised_addr(port) {
                        Ok(addr) => addr,
                        Err(err) => {
                            println!("选择对外地址失败: {err}");
                            continue;
                        }
                    };
                    println!("Local server started on 127.0.0.1:{port}");
                    println!("Advertised as {addr}");
                    break format!("{addr}&{key}");
                }
                Err(err) => {
                    println!("启动本地服务器失败: {err}");
                    continue;
                }
            }
        }
        // 1️⃣ 数字
        if let Ok(idx) = s.parse::<usize>() {
            if let Some(server) = CLIENT_SERVER_PRESETS.get(idx - 1) {
                print!("Server Password: ");
                io::stdout().flush()?;
                let key = get_password_or_default();
                break format!("{}&{}", server.addr, key);
            }
        }
        // 2️⃣ host:port / IP:port
        if regex::Regex::new(r"^[A-Za-z0-9.\-]+:\d+$")
            .unwrap()
            .is_match(s)
        {
            print!("Server Password: ");
            io::stdout().flush()?;
            let key = get_password_or_default();
            break format!("{}&{}", s, key);
        }
        // 3️⃣ 邀请码
        if s.starts_with("/INVITE:") {
            break s.to_string();
        }
        println!("Enter an choice, IP or invite code!");
    };

    Ok(chosen)
}
