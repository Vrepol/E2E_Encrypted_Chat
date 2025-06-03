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
use rand::{distr::Alphanumeric, Rng};
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
                let (server_addr,enc_pwd, room_id, pwd) = match parse_invitation(server_addr_or_invite) {
                    Some(t) => t,
                    None => {
                        // 直接返回带中文提示的 anyhow 错误
                        return Err(anyhow!("Invalid or expired invitation"));
                    }
                };
                //return Err(anyhow!("s:{},sk:{:?},r:{},rk:{}",server_addr,enc_pwd, room_id, pwd));
                // 2) 先连 TCP
                let stream = TcpStream::connect(&server_addr).await?;
                let (reader, mut writer) = stream.into_split();
                let mut lines = BufReader::new(reader).lines();
                let auth = {
                    // enc_pwd1 是 Base64(layer-1)
                    use super::crypto::{period_key};
                    use chrono::Utc;
                    use base64::Engine;
                    // 再包第二层
                    let outer = {
                        let now = Utc::now().timestamp();
                        super::crypto::chacha_once(&enc_pwd, &period_key(now))
                    };
                    base64::engine::general_purpose::STANDARD.encode(outer)
                };
                writer.write_all(format!("AUTH {auth}\n").as_bytes()).await?;
                // 等待 OK
                let resp = lines.next_line().await?
                    .ok_or_else(|| anyhow!("server closed during auth"))?;
                if resp.trim() != "OK" {
                    return Err(anyhow!("Server declined: {}", resp));
                }


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
    use super::crypto::enc_auth;

    let mut iter = server_addr_or_invite.splitn(2, '&');
    let server = iter.next().unwrap_or("");
    let password = iter.next().unwrap_or("");

    let stream = TcpStream::connect(server).await?;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    let auth = enc_auth(password);        // server_pwd = 用户输入的服务器口令


    writer.write_all(format!("AUTH {auth}\n").as_bytes()).await?;
    // 等待 OK
    let resp = lines.next_line().await?
        .ok_or_else(|| anyhow!("server closed during auth"))?;
    if resp.trim() != "OK" {
        return Err(anyhow!("Server declined: {}", resp));
    }

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
        println!("\n{}","— No Rooms Available —".green().bold());
    } else {
        println!("\n{} \n {}","— Available Rooms —".green().bold(), rooms.join("; "));
    }

    // 2. 本地交互：输入房间号 & 密码
    let (room_id, pwd, action) = loop {
        print!("{}","type \"/q\" to disconnect, leave blank to join the Public Room,".yellow().bold());
        print!("{}","Room ID: ".blue());
        io::stdout().flush()?;
        let mut id = String::new();
        io::stdin().read_line(&mut id)?;

        if id.trim()=="/q"{
            return Err(anyhow!("Disconnected"));
        } else if id.trim() =="'" {
            let room_id: String = rand::rng()
                .sample_iter(&Alphanumeric)
                .take(9)                                // 8‒10 都行，这里用 9
                .map(char::from)
                .collect();

            // 2. 随机密码（16 字符，含部分符号提升复杂度）
            const CHARSET: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                abcdefghijklmnopqrstuvwxyz\
                0123456789-_@#";
            let pwd: String = (0..16)
                .map(|_| {
                    let idx = rand::rng().random_range(0..CHARSET.len());
                    CHARSET[idx] as char
                })
                .collect();
            break (room_id, pwd, "CREATE");
        }

        let id = if id.trim().is_empty() {"Public"} else {id.trim()} ;
        if id != "Public" {
            print!("{}","It wouldn't display while typing,".yellow().bold());
            print!("{}","Password:".red());
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
