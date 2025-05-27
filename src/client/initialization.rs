use std::io::{self, Write};
use fake::Fake;
use fake::locales::{FR_FR};
use fake::faker::name::raw::*;
use colored::*;
pub fn initial() -> io::Result<(String, &'static str)> {
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
    let servers = vec![
    ("Public server", "8.153.67.166:6655"),
    ("Tailscale server", "100.123.171.94:6655"),
    ];

    // 2. 打印名称列表
    println!("Avaliable Severs:");
    for (i, (name, _addr)) in servers.iter().enumerate() {
        println!("  {}. {}", i + 1, name);
    }
    print!("Choose From (1-{}): ", servers.len());
    io::stdout().flush()?;

    // 3. 读取用户输入并映射到地址
    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;
    let idx = choice.trim()
        .parse::<usize>()
        .ok()
        .filter(|&n| n >= 1 && n <= servers.len())
        .map(|n| n - 1)
        .unwrap_or(0);

    // 4. 直接解构拿到服务器名和地址
    let (server_name, server_addr) = servers[idx];
    println!("Connecting to {} …", server_name);

    //println!("Connecting {} …", server_addr);
    // 把 &str 转成 String，和签名统一
    Ok((username, &server_addr))
}
