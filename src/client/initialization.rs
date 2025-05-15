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
    /* 
    // ---------- 选择服务器 ----------
    let servers = vec![
        "100.97.92.19:6655",
        "100.123.171.94:6655",
        "8.153.67.166:6655",
        "192.168.1.4:6655",
    ];
    println!("Available Server:");
    for (i, s) in servers.iter().enumerate() {
        println!("  {}. {}", i + 1, s);
    }
    print!("Choose from (1-{}): ", servers.len());
    io::stdout().flush()?;

    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;
    let idx = choice.trim().parse::<usize>().unwrap_or(1).saturating_sub(1);
    let server_addr = servers[idx.min(servers.len() - 1)];
    */
    let server_addr = "8.153.67.166:6655";
    //println!("Connecting {} …", server_addr);
    // 把 &str 转成 String，和签名统一
    Ok((username, &server_addr))
}
