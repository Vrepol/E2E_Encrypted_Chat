# E2E Encrypted Chat

> **终端 × Rust × 端到端加密** — 一款跨平台、零依赖、可在本地或 VPS 一键部署的即时通讯应用。

---

## ✨ 项目概述

`E2E_Encrypted_Chat` 由 **客户端** 和 **服务器** 两部分组成，均使用 Rust **Tokio 异步运行时** 实现。项目聚焦在「轻量级 + 强安全 + 高可玩性」：内置房间系统、邀请码、TUI 聊天界面、附件分片传输、图片预览与可插拔的加密层。

默认服务器、默认端口、默认服务器密码现在集中在 `src/app_config.rs`。

<div align="center">
  <img src="./demo.gif" width="600" alt="Demo GIF"/>
</div>

---

## 📂 目录结构

```text
E2E_Encrypted_Chat/
├── Cargo.toml
├── README.md
├── src/
│   ├── client/            # 客户端逻辑
│   │   ├── crypto.rs      # 加解密部分
│   │   ├── handshake.rs   # 认证 + 密钥生成
│   │   ├── keyboard.rs    # 按键交互部分
│   │   ├── network.rs     # 读写 + 心跳
│   │   ├── receiver.rs    # 消息通道 → UI
│   │   ├── utils.rs       # 工具函数部分
│   │   ├── crypto.rs      # 加密算法部分
│   │   ├── network.rs     # 客户端通信收发部分
│   │   ├── clipboard.rs   # 剪切板部分
│   │   └── initialization.rs  # 初始化部分
│   └── bin/         
│       ├── client.rs      # 客户端部分
│       └── server.rs      # 服务端部分
│
└── LICENSE
```

---

## 🚀 快速开始

### 1. 编译

```bash
# 克隆代码
$ git clone https://github.com/Vrepol/E2E_Encrypted_Chat.git
$ cd E2E_Encrypted_Chat

# Release 构建
$ cargo build --release
```

### 2. 运行服务器

```bash
./server --port 6655 -k 'Password'
```

| 参数           | 作用              | 默认       |
| ------------ | --------------- | -------- |
| `--port`     | 监听端口            | `6655`   |
| `-k` | 服务器主密码（同时作为根密钥） | `Vrepol` |

如果你想改项目默认值，而不是每次手动传参：
- 服务端默认端口
- 服务端默认密码
- 客户端预设服务器列表

直接修改 `src/app_config.rs` 即可。


### 3. 运行客户端

```bash
./client
或
client.exe
```

启动流程：
1. **昵称**（留空则为随机法语昵称）
2. **服务器地址 / 邀请码 / `host`**（可直接粘贴以 `/INVITE:` 开头的一次性链接；输入 `host` 可在本机拉起同目录 `server` 二进制，并选择一个写入邀请码的对外 IP）
3. **服务器密码**（仅本地使用，不会明文上传）
4. **房间号码**（留空则为大厅，输入/q退回到第2步，输入单引号 ' 为加强的随机房间，32位密码，配合邀请码使用）
5. **房间密码**

---

## 🔑 信息安全

当前实现的安全模型可以概括为三层：

| 层级 | 当前实现 | 服务器可见内容 |
| --- | --- | --- |
| 服务器握手层 | 基于服务器密码哈希的对称认证与外层加密 | 连接时序、认证是否成功 |
| 房间消息层 | 房间消息使用 AEAD 加密，消息正文和附件控制帧不会以明文出现在服务器 | 房间号、成员变化、包大小、发送时序 |
| 邀请码层 | 一次性 token + 10 分钟有效期 + owner capability；邀请码本体只包含 `server_addr + token + blob_key` | token、过期状态、房间成员关系；看不到房间秘密与 blob 明文 |

当前邀请码流程：

1. 只有当前房主连接可以申请邀请码。
2. 服务器只发放一次性 token，并记录 10 分钟有效期。
3. 客户端本地把 `server_pwd_hash + room_id + room_key` 加密成 opaque blob。
4. 服务器只暂存 `token -> blob`，本身无法解 blob。
5. 被邀请者使用邀请码时，先用 token 拉取 blob，再在本地用 `blob_key` 解开。

这意味着：

- 邀请码已经不会暴露服务器明文密码。
- 服务器也无法直接还原房间秘密。
- 但邀请码本身仍然是 bearer capability。
  也就是谁拿到邀请码，谁就能在有效期内使用一次。

当前仍然存在的重要边界：

- 还没有前向安全和后向安全；房间消息仍基于长期房间秘密，后续需要改为 `epoch rekey + sender chain + pairwise X25519`。
- TLS 未来可以补上链路保护，但不能替代应用层群聊端到端密钥轮换。
- 本地 `host` 模式目前会从客户端同目录拉起 `server.exe` / `server`，如果该目录可被攻击者写入，存在二进制劫持风险。

> 加密/解密逻辑主要位于 `src/client/crypto.rs`、`src/client/handshake.rs`、`src/client/network.rs`，后续可继续演进到 Noise、TLS、Sender Chain 或 MLS / TreeKEM。

---

## 🖥️ TUI 操作快捷键（聊天界面）

| 快捷键            | 功能      | 快捷键            | 功能      |
| -------------- | ------- | -------------- | ------- |
| **Ctrl+H/J**   | 中文/英文提示 | **Crtl+↑ / ↓** | 加速滚动    |
| **Ctrl+I**     | 生成邀请码   | **Ctrl+X**     | 粘贴图片或文字 |
| ← / →          | 移动光标    | **Ctrl+Z**     | 撤销  |
| **Crtl+← / →** | 加速移动    | **Ctrl+C**     | 复制消息文本  |
| ↑ / ↓          | 滚动消息    | **Ctrl+A**     | 清空输入框   |
| Tab            | 打开附件    | ESC            | 退出房间    |

补充说明：
1. 粘贴图片会自动转为 PNG，并以分片方式发送。
2. 输入完整文件路径，或使用 `/send <path>`，可以发送任意文件。
3. 图片附件会保留预览体验，普通文件会落到临时目录并可直接打开。
4. 附件发送现在带有分片 ACK / 超时重试，聊天界面会显示传输进度和失败提示。
5. 邀请码现在由当前房主连接向服务器申请，一次性有效，10 分钟过期；房主断线后不再保留邀请权限。
6. 邀请码本体只携带服务器地址、token 和本地解 blob 的 key；完整房间秘密以客户端加密 blob 形式暂存服务器，服务器本身无法解开。
7. 附件分片当前默认 `64 KiB`，窗口发送；较弱网络下仍需要进一步做自适应窗口/分片。

---

## 💻 常见问题 FAQ

<details>
<summary>编译时报错 <code>alsa-sys</code> 找不到库？</summary>
安装 `libasound2-dev`，或在 <code>Cargo.toml</code> 中为 <code>rodio</code> 关闭默认特性：

```toml
rodio = { version = "0.18", default-features = false }
```

</details>

<details>
<summary>PowerShell 显示 Emoji/彩色字符为乱码？</summary>
请使用 **Windows Terminal** 并选择支持 Emoji 的字体（如 *Cascadia Code PL*）。
</details>

<details>
<summary>如何跨编译到 Windows 可执行文件？</summary>
```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```
</details>

---

## 🛣️ Roadmap / TODO

### 已完成

* [x] 邀请码缩短：改为 `token + opaque blob`
* [x] 一次性邀请码：仅房主可申请，10 分钟有效
* [x] 附件分片传输：统一支持图片和任意文件
* [x] 传输提速：`64 KiB` chunk + 滑动窗口 ACK

### 近期优先级

* [ ] 适配低带宽服务器：窗口/分片大小改为可配置，或做自适应带宽控制
* [ ] 发送者本地附件回显优化：避免服务端再回环一份完整附件数据给发送者
* [ ] 输入框改进：处理中英文混输导致的光标错位
* [ ] IPv6 支持
  当前协议层基本兼容，但实现层还不算支持：
  - 服务端监听仍偏向 IPv4
  - 客户端输入规则还不能稳定接受 `[IPv6]:port`
  - `host` 模式的本地地址探测与对外地址选择仍以 IPv4 为主
* [ ] 本地 `host` 模式安全加固：降低同目录 `server.exe` 被替换后的二进制劫持风险

### 中期重构

* [ ] client / server 单二进制整合
  建议路线：
  - 抽出共享服务端模块
  - 保留 `client` / `server` / `host` 三种模式
  - 优先做单二进制双模式，而不是把服务端逻辑直接硬塞进客户端主循环
* [ ] 断点续传 / 大文件续发
* [ ] 移动端或 GUI 客户端

### 安全协议升级

* [ ] 移除长期静态 `ROOM_KEY`
* [ ] 房间密码仅用于加入认证，不再直接加密聊天消息
* [ ] 引入 `epoch rekey`，成员加入/退出时推进 group epoch
* [ ] 引入 `sender chain`，每条消息使用独立 `message_key`
* [ ] 引入 `pairwise X25519` 分发新的 `group_secret`
* [ ] 附件升级为 `manifest + encrypted chunk` 的 hybrid encryption
* [ ] 在轻量方案稳定后，评估迁移到 MLS / TreeKEM


## 📄 许可证

本项目基于 **MIT License** - 详见 [LICENSE](LICENSE)。
