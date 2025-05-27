use std::io::{self, Write};
use fake::Fake;
use fake::locales::{FR_FR};
use fake::faker::name::raw::*;
use colored::*;
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
pub fn initial() -> io::Result<String> {

    let servers = vec![
        ("Public server", "8.153.67.166:6655"),
        ("Tailscale server", "100.123.171.94:6655"),
    ];

    // 交互循环直到拿到合法输入
    let chosen = loop {
        println!("\nAvaliable Servers:");
        for (i, (name, _)) in servers.iter().enumerate() {
            println!("  {}. {}", i + 1, name);
        }
        print!("Choice / IP:Port / /INVITE:…  ➜ ");
        io::stdout().flush()?;

        let mut inp = String::new();
        io::stdin().read_line(&mut inp)?;
        let s = inp.trim();
        if s.is_empty() {
            println!("Default Choice : {}", servers[0].0);
            break servers[0].1.to_string();
        }
        // 1️⃣ 数字
        if let Ok(idx) = s.parse::<usize>() {
            if (1..=servers.len()).contains(&idx) {
                break servers[idx - 1].1.to_string();
            }
        }
        // 2️⃣ IP:Port  (简单正则校验 0-255.0-255.0-255.0-255:数字)
        if regex::Regex::new(r"^(?:\d{1,3}\.){3}\d{1,3}:\d+$")
            .unwrap()
            .is_match(s)
        {
            break s.to_string();
        }
        // 3️⃣ 邀请码
        if s.starts_with("/INVITE:") {
            break s.to_string();
        }
        println!("输入无效，请重来！");
    };

    Ok(chosen)
}
