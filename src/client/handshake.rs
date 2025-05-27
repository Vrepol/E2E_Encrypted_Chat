// client/handshake.rs
use anyhow::{anyhow, Result};
use md5::{Digest, Md5};
use rpassword::read_password;
use std::io::{self, Write};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    net::TcpStream,
};
use super::utils::parse_invitation;
use super::crypto;
use colored::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;
/// 返回已经握手成功、可以直接进入聊天循环的
/// `(Lines<OwnedReadHalf>, OwnedWriteHalf, String /*room_id*/)`
pub async fn connect_and_login(
    server_addr_or_invite: &str,
    nickname: &str,
) -> Result<(Lines<BufReader<tokio::net::tcp::OwnedReadHalf>>,
            tokio::net::tcp::OwnedWriteHalf,
            String,String)> {
            if server_addr_or_invite.starts_with("/INVITE:") {
                // 1) 解码
                let (server_addr, room_id, pwd) = match parse_invitation(server_addr_or_invite) {
                    Some(t) => t,
                    None => {
                        // 直接返回带中文提示的 anyhow 错误
                        return Err(anyhow!("邀请码无效或已过期"));
                    }
                };
        
                // 2) 先连 TCP
                let stream = TcpStream::connect(&server_addr).await?;
                let (reader, mut writer) = stream.into_split();
                let mut lines = BufReader::new(reader).lines();
        
                // 与原流程相同：读取 "ROOMS ..." 横幅
                let first = lines.next_line().await?
                    .ok_or_else(|| anyhow!("server closed during handshake"))?;
                if !first.starts_with("ROOMS") {
                    return Err(anyhow!("unexpected banner: {}", first));
                }
        
                // 3) 直接拼 JOIN 指令，无需交互
                let digest = Md5::digest(format!("{room_id}{pwd}"));
                crypto::set_room_key(&hex::encode(digest));
                let mut mac = Hmac::<Sha256>::new_from_slice(&digest).unwrap();
                mac.update(b"Hello");
                let credential = hex::encode(mac.finalize().into_bytes());
                let cmd = format!("JOIN {room_id} {credential} {nickname}\n");
                writer.write_all(cmd.as_bytes()).await?;
        
                // 4) 等待服务器 OK
                let resp = lines.next_line().await?
                    .ok_or_else(|| anyhow!("server closed during handshake-2"))?;
                if resp.trim() != "OK" {
                    return Err(anyhow!("server refused: {}", resp));
                }
                return Ok((lines, writer, room_id,pwd));
            }
    // 0. TCP 连接
    let stream = TcpStream::connect(server_addr_or_invite).await?;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    // 1. 服务器首条消息：房间列表
    let first = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow!("server closed during handshake"))?;
    if !first.starts_with("ROOMS") {
        return Err(anyhow!("unexpected banner: {}", first));
    }
    let rooms: Vec<String> = first.split_whitespace().skip(1).map(|s| s.to_owned()).collect();
    if rooms.is_empty() {
        println!("{}","— 服务器当前没有房间 —".green().bold());
    } else {
        println!("{} \n {}","— 可加入的房间 —".green().bold(), rooms.join("; "));
    }

    // 2. 本地交互：输入房间号 & 密码
    let (room_id, pwd, action) = loop {
        print!("{}","留空则为大厅,".yellow().bold());
        print!("{}","输入房间号：".blue());
        io::stdout().flush()?;
        let mut id = String::new();
        io::stdin().read_line(&mut id)?;
        let id = if id.trim().is_empty() {"Public"} else {id.trim()} ;
        if id != "Public" {
            print!("{}","输入密码时不会显示,".yellow().bold());
            print!("{}","输入密码：".red());
            io::stdout().flush()?;
            let pwd = read_password()?;
            let act = if rooms.contains(&id.to_string()) { "JOIN" } else { "CREATE" };
            break (id.to_owned(), pwd, act);
        } else {
            let pwd = String::from("");
            let act = if rooms.contains(&id.to_string()) { "JOIN" } else { "CREATE" };
            break (id.to_owned(), pwd, act);
        }
        
    };

    // 3. 计算 md5，作为房间密钥 & 凭据
    let digest = Md5::digest(format!("{room_id}{pwd}").as_bytes()); // 16 B
    let md5_hex = hex::encode(digest);
    // ① 把 md5 设置为本房间的会话密钥
    crypto::set_room_key(&md5_hex);
    // ② 用它把 “Hello” 包装成密文，作为凭据
    let mut mac = Hmac::<Sha256>::new_from_slice(&digest).unwrap();
    mac.update(b"Hello");
    let tag = mac.finalize().into_bytes();
    let credential = hex::encode(tag);

    // 4. 发送指令：<ACTION> <ROOM> <CRED> <NICK>
    let cmd = format!("{action} {room_id} {credential} {nickname}\n");
    writer.write_all(cmd.as_bytes()).await?;

    // 5. 等待握手结果
    let resp = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow!("server closed during handshake‑2"))?;
    if resp.trim() != "OK" {
        return Err(anyhow!("server refused: {}", resp));
    }
    Ok((lines, writer, room_id,pwd))
}
