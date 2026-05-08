use std::{
    env,
    io,
    net::{IpAddr, Ipv4Addr, TcpStream, ToSocketAddrs, UdpSocket},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertiseAddrCandidate {
    pub label: String,
    pub addr: String,
}

fn server_binary_candidates(current_exe: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(dir) = current_exe.parent() {
        candidates.push(dir.join("server.exe"));
        candidates.push(dir.join("server"));
    }
    candidates
}

fn resolve_server_binary() -> io::Result<PathBuf> {
    let current_exe = env::current_exe()?;
    server_binary_candidates(&current_exe)
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "未找到同目录 server 可执行文件，请先构建或放置 server/server.exe",
            )
        })
}

fn wait_for_local_server(addr: &str, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    let socket_addrs: Vec<_> = addr.to_socket_addrs()?.collect();
    if socket_addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("无法解析本地服务端地址: {addr}"),
        ));
    }

    while Instant::now() < deadline {
        for socket_addr in &socket_addrs {
            if TcpStream::connect_timeout(socket_addr, Duration::from_millis(200)).is_ok() {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(150));
    }

    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("本地服务端启动超时: {addr}"),
    ))
}

fn primary_local_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if is_advertisable_ipv4(&ip) => Some(ip),
        _ => None,
    }
}

fn is_advertisable_ipv4(ip: &Ipv4Addr) -> bool {
    !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_unspecified()
        && *ip != Ipv4Addr::BROADCAST
}

#[derive(Debug, Deserialize)]
struct WindowsIpRow {
    #[serde(rename = "InterfaceAlias")]
    interface_alias: String,
    #[serde(rename = "IPAddress")]
    ip_address: String,
}

#[cfg(windows)]
fn windows_ip_candidates() -> io::Result<Vec<AdvertiseAddrCandidate>> {
    let script = concat!(
        "Get-NetIPAddress -AddressFamily IPv4 | ",
        "Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.AddressState -eq 'Preferred' -and $_.SkipAsSource -eq $false } | ",
        "Select-Object InterfaceAlias,IPAddress | ConvertTo-Json -Compress"
    );

    let output = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    parse_windows_ip_candidates(String::from_utf8_lossy(&output.stdout).trim())
}

#[cfg(not(windows))]
fn windows_ip_candidates() -> io::Result<Vec<AdvertiseAddrCandidate>> {
    Ok(Vec::new())
}

fn parse_windows_ip_candidates(json: &str) -> io::Result<Vec<AdvertiseAddrCandidate>> {
    if json.is_empty() || json == "null" {
        return Ok(Vec::new());
    }

    let rows: Vec<WindowsIpRow> = if json.trim_start().starts_with('[') {
        serde_json::from_str(json).map_err(io::Error::other)?
    } else {
        vec![serde_json::from_str(json).map_err(io::Error::other)?]
    };

    let mut candidates = Vec::new();
    for row in rows {
        let Ok(ip) = row.ip_address.parse::<Ipv4Addr>() else {
            continue;
        };
        if !is_advertisable_ipv4(&ip) {
            continue;
        }
        candidates.push(AdvertiseAddrCandidate {
            label: row.interface_alias,
            addr: ip.to_string(),
        });
    }

    Ok(candidates)
}

pub fn detect_advertise_candidates() -> io::Result<Vec<AdvertiseAddrCandidate>> {
    let mut candidates = windows_ip_candidates()?;

    if let Some(ip) = primary_local_ipv4() {
        let ip_str = ip.to_string();
        if !candidates.iter().any(|entry| entry.addr == ip_str) {
            candidates.insert(
                0,
                AdvertiseAddrCandidate {
                    label: "Primary route".to_string(),
                    addr: ip_str,
                },
            );
        }
    }

    candidates.sort_by(|a, b| a.addr.cmp(&b.addr).then(a.label.cmp(&b.label)));
    candidates.dedup_by(|a, b| a.addr == b.addr);

    candidates.push(AdvertiseAddrCandidate {
        label: "Loopback (local only)".to_string(),
        addr: "127.0.0.1".to_string(),
    });

    Ok(candidates)
}

pub fn spawn_local_server(port: u16, password: &str) -> io::Result<()> {
    let addr = format!("127.0.0.1:{port}");

    if wait_for_local_server(&addr, Duration::from_millis(250)).is_ok() {
        return Ok(());
    }

    let server_bin = resolve_server_binary()?;
    Command::new(server_bin)
        .arg("--port")
        .arg(port.to_string())
        .arg("-k")
        .arg(password)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    wait_for_local_server(&addr, Duration::from_secs(3))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_windows_ip_candidates;

    #[test]
    fn test_parse_windows_ip_candidates_filters_invalid_addrs() {
        let json = r#"[{"InterfaceAlias":"Wi-Fi","IPAddress":"192.168.1.23"},{"InterfaceAlias":"Loopback","IPAddress":"127.0.0.1"},{"InterfaceAlias":"LinkLocal","IPAddress":"169.254.10.20"}]"#;
        let parsed = parse_windows_ip_candidates(json).expect("windows candidate json should parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].addr, "192.168.1.23");
        assert_eq!(parsed[0].label, "Wi-Fi");
    }
}
