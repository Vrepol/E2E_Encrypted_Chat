use std::io::{self, Write};
use fake::Fake;
use fake::locales::{FR_FR};
use fake::faker::name::raw::*;
use colored::*;
use std::collections::HashMap;
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
    let mut servers: HashMap<&str, &str> = HashMap::new();
    servers.insert("Public server", "8.153.67.166:6655");
    servers.insert("Tailscale server", "100.123.171.94:6655");

    // 2. 打印名称列表
    println!("Avaliable Severs:");
    let names: Vec<&str> = servers.keys().copied().collect();
    for (i, name) in names.iter().enumerate() {
        println!("  {}. {}", i + 1, name);
    }
    print!("Choose From (1-{}): ", names.len());
    io::stdout().flush()?;

    // 3. 读取用户输入并映射到地址
    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;
    let idx = choice.trim()
        .parse::<usize>()
        .ok()
        .and_then(|n| if n >= 1 && n <= names.len() { Some(n - 1) } else { None })
        .unwrap_or(0);

    let server_name = names[idx];
    let server_addr = servers.get(server_name).unwrap();

    //let server_addr = "8.153.67.166:6655";
    //println!("Connecting {} …", server_addr);
    // 把 &str 转成 String，和签名统一
    Ok((username, &server_addr))
}
