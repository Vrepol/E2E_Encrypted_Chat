# E2E Encrypted Chat

> 终端 + Rust + 端到端加密的轻量聊天应用，包含客户端、服务端、邀请码、房间密钥与附件传输。

![Demo](./assets/demo.gif)

## 项目概述

`rust_chat` 由客户端和服务端两部分组成，均基于 Rust + Tokio 异步运行时实现。当前仓库已经包含：

- 终端聊天界面
- 房间系统与邀请码机制
- 端到端消息加密
- 附件分片传输
- 本地 `host` 模式
- 群组密钥演进相关实验实现

默认配置集中在 [src/config.rs](src/config.rs)：

- 默认服务端端口 `DEFAULT_SERVER_PORT`
- 默认服务端密码 `DEFAULT_SERVER_PASSWORD`
- 客户端预设服务器列表 `CLIENT_SERVER_PRESETS`

## 目录结构

当前 `src/` 的一级模块如下：

```text
src/
├── attachments/   # 附件发送、接收、落盘
├── bin/           # client/server 二进制入口
├── client/        # 客户端初始化、握手、收发、会话逻辑
├── crypto/        # 房间加密、邀请码、传输安全、群组密钥演进
├── protocol/      # 协议行格式与解析
├── server/        # 服务端连接、广播、房间、邀请码逻辑
├── transport/     # 包封装、ACK、心跳
├── ui/            # TUI、通知、快捷键、剪贴板
├── util/          # 路径等辅助函数
├── config.rs      # 默认配置
└── lib.rs         # 模块导出与测试
```

二进制入口：

- [src/bin/client.rs](src/bin/client.rs)
- [src/bin/server.rs](src/bin/server.rs)

## 快速开始

### 编译

```bash
git clone https://github.com/Vrepol/E2E_Encrypted_Chat.git
cd E2E_Encrypted_Chat
cargo build --release
```

### 运行服务器

```bash
./server --port 6655 -k "Password"
```

参数：

| 参数 | 作用 | 默认值 |
| --- | --- | --- |
| `--port` | 监听端口 | `6655` |
| `-k` | 服务端主密码 | `Vrepol` |

如果你想修改默认值而不是每次传参，直接编辑 [src/config.rs](src/config.rs)。

### 运行客户端

```bash
./client
```

启动流程：

1. 输入昵称
2. 输入服务器地址、邀请码，或输入 `host` 在本机拉起服务端
3. 输入服务器密码
4. 输入房间号
5. 输入房间密码

## 安全现状

当前实现可以拆成 4 层来看：服务端口令握手、房间凭证、群组消息层、邀请码层。下面按实际代码路径说明。

### 1. 服务端握手与传输层

普通登录路径：

1. 客户端对服务端密码做 `SHA-256`，得到 `server_pwd_hash`
2. 客户端发明文 `/AUTH_HELLO <client_nonce>`
3. 服务端回明文 `/AUTH_CHALLENGE <server_nonce>`
4. 客户端回明文 `/AUTH_PROOF <HMAC(server_pwd_hash, label, client_nonce, server_nonce)>`
5. 双方用 `HKDF(server_pwd_hash, salt = client_nonce || server_nonce)` 派生会话共享密钥
6. 再按方向分离出 `client->server` 和 `server->client` 两把传输密钥

邀请码登录路径类似：

1. 邀请码中带有 `token_secret` 和本地解 blob 的 `blob_key`
2. 客户端发明文 `/INVITE_HELLO <token_id> <client_nonce>`
3. 服务端回明文 `/INVITE_CHALLENGE <server_nonce>`
4. 客户端回明文 `/INVITE_PROOF <HMAC(token_secret, ...)>`
5. 双方用 `HKDF(token_secret, salt = token_id || client_nonce || server_nonce)` 派生传输层共享密钥

握手完成后，后续链路使用：

- `ChaCha20-Poly1305`
- 单调递增 `seq`
- `seq` 映射到 nonce
- 方向分离密钥
- 基于窗口的重复包检测

这层的作用是保护客户端到服务端之间的传输内容不被链路旁路直接读明文，但它不是 TLS，也不是带前向安全的标准握手协议。

### 2. 房间凭证与房间认证

房间侧当前使用 `room_id + room_credential` 本地导出房间秘密：

- `room_key = MD5(room_id || room_credential)` 后重复扩展成 32 字节
- `join_credential = HMAC(room_key[..16], ROOM_JOIN_LABEL)`
- `room_auth_key = HKDF(room_key, salt = ROOM_AUTH_LABEL, info = "room-auth")`

其中：

- `join_credential` 发给服务端，用于创建 / 加入房间校验
- `room_auth_key` 不直接发给服务端，用于群组控制消息认证与 epoch secret 包装

这意味着：

- 服务端默认拿不到原始 `room_credential`
- 但服务端拿得到 `room_id` 和 `join_credential`
- 如果房间口令较弱，服务端可以离线猜测 `room_credential`
- 由于当前不是 memory-hard KDF，这部分抗暴力破解能力并不强

所以当前“房间密码不直接上传”是成立的，但“服务端无法对弱口令做离线猜解”并不成立。

### 3. 群组消息层如何加密

房主创建房间后，本地生成一个随机 `group_secret(epoch 0)`。消息层随后按 epoch 运作：

1. 用 `group_secret + group_id + epoch` 通过 HKDF 派生 `sender_chain_root`
2. 再按 `sender_id` 派生每个发送者自己的 `chain_key`
3. 每发一条消息，从当前 `chain_key` 派生：
   - 下一跳 `next_chain_key`
   - 本条消息 `aead_key`
   - 本条消息 `nonce`
4. 使用 `ChaCha20-Poly1305` 加密正文

消息头包含：

- `group_id`
- `epoch`
- `sender_id`
- `msg_no`
- `msg_type`

这些头字段会作为 AEAD 的 AAD 做完整性绑定，但不会被加密；因此服务端如果愿意解析 `/RMSG` 载荷，可以看到这些元数据。

当前效果是：

- 每条消息使用独立的 AEAD key / nonce
- 同一发送者的消息链是单向推进的
- 单独泄露某一条消息的 `aead_key` 不会直接反推出其他消息 key

但要注意，当前还不是完整意义上的现代群聊前向安全方案：

- 如果当前 epoch 的 `group_secret` 泄露，该 epoch 下所有发送者的链都可被重建
- 一旦可重建链起点，就可以回放推出该 epoch 的历史消息 key 和后续消息 key
- 也就是说，当前设计具备“逐消息独立 key”，但还不具备“epoch 内强前向安全”

### 4. 成员加入 / 退出时如何换密钥

当成员列表变化时，当前实现会走一轮 epoch rekey：

1. 每个成员持有一对临时 `X25519` 密钥
2. 成员通过 `/KEY_ANNOUNCE` 广播自己的 `X25519 public key`
3. `KEY_ANNOUNCE` 不是签名，而是由 `room_auth_key` 做 MAC 认证
4. 提议者生成新的随机 `group_secret`
5. 对每个接收者，提议者执行一次 `X25519 DH`
6. 用 `HKDF(DH, salt = room_auth_key)` 派生包裹密钥
7. 把新的 epoch secret 分别加密封装进 `/EPOCH_COMMIT`
8. 各成员解开属于自己的 wrapped secret，激活新 epoch
9. 激活新 epoch 后，本地会重新生成新的临时 `X25519` 密钥对

这部分带来的安全性质比较细：

- 新加入成员默认拿不到旧 epoch secret，因此不能解密加入前的历史 epoch
- 被移除成员在新 epoch 生效后，按设计不能再解密后续 epoch
- 所以“加入前历史保密”和“退出后未来保密”在 epoch 边界上是有的

但仍有明显限制：

- 不是连续前向安全；epoch 内如果 `group_secret` 泄露，该 epoch 仍整体失守
- `KEY_ANNOUNCE` 依赖 `room_auth_key` 做 MAC，不是基于长期身份公钥的签名认证
- 当前安全码机制还没有真正把“长期身份公钥”绑定进用户可验证流程

### 5. 邀请码到底保护了什么

当前邀请码是：

```text
/INVITE:<server_addr_b64>.<token_secret>.<blob_key>
```

其中：

- `token_secret` 用于和服务端完成一次性邀请码握手
- `blob_key` 只在客户端本地使用
- 服务端只存储 `token -> blob_b64`
- `blob_b64` 内部是加密后的 `{room_id, room_credential}`

所以：

- 邀请码不再把房间密码直接暴露给服务端
- 服务端不能直接解开 blob
- 邀请码本质上仍然是 bearer capability
- 谁拿到完整邀请码，谁就在有效期内拥有一次使用能力

当前 TTL 为 10 分钟，且一次性消费。

### 6. 附件是怎么加密的

附件分成两层：

1. `manifest`
   - 含 `file_key`、`nonce_base`、文件名、总大小、分片数、哈希
   - 先构造成 `/FILEMANIFEST2 ...`
   - 再作为普通群消息正文走 `/RMSG` 加密

2. `chunk`
   - 每个附件随机生成一个 `file_key`
   - 每片用 `ChaCha20-Poly1305(file_key)` 加密
   - AAD 绑定 `group_id / epoch / sender_id / transfer_id / chunk_index / total_chunks`
   - 以 `/FILECHUNK2 ...` 形式发送

因此：

- 服务端拿不到文件明文
- 服务端通常也拿不到 `file_key`，因为它藏在加密后的 manifest 里
- 但服务端仍能看到 `transfer_id`、`chunk index`、chunk 数量推进与密文大小

### 7. 当前能否保证前向 / 后向安全

结论需要分层看：

| 维度 | 当前状态 | 说明 |
| --- | --- | --- |
| 传输层前向安全 | 否 | 会话密钥直接由服务端密码或邀请码 token 派生，没有 ECDHE/Noise/TLS 级别 FS |
| 传输层后向安全 / PCS | 否 | 一旦底层共享秘密泄露，录制流量可被回溯解密 |
| 新成员看旧消息 | 部分可保证 | 只会拿到新 epoch secret，默认不应解密加入前 epoch |
| 退出成员看新消息 | 部分可保证 | 依赖 rekey 成功推进到新 epoch |
| epoch 内前向安全 | 否 | 泄露当前 epoch group secret 可重建整条 epoch 消息链 |
| 单条消息 key 独立性 | 是 | 每条消息都有独立派生出的 AEAD key / nonce |

如果希望更接近成熟 E2EE 群聊协议，后续应继续推进：

- 长期身份密钥
- 身份签名绑定 `KEY_ANNOUNCE`
- 真正的安全码 / 指纹校验
- 更频繁和更严格的 epoch rekey
- 更接近 Double Ratchet / MLS / TreeKEM 的群组状态演进

### 8. 服务端能知道什么

如果把服务端视为“诚实但好奇”甚至“主动分析”，当前它能知道的内容比“只知道时序”多得多：

- 谁连上了服务器，连接多久，什么时候断线
- 使用的是密码登录还是邀请码登录
- 房间的 `room_id`
- 成员列表、昵称、加入/退出事件
- 谁是房主，谁持有 owner capability
- 每个传输包的方向、大小、到达时间、重传与 ACK 节奏
- 对 `/RMSG` 来说，可解析到 `group_id / epoch / sender_id / msg_no / msg_type`
- 对附件来说，可看到 `transfer_id`、chunk 序号、分片推进速度、总消息规模
- 邀请码申请行为、邀请码是否被消费、何时过期

服务端默认看不到的内容：

- 服务端主密码明文
- 房间密码明文
- 文本消息正文
- 附件明文
- 邀请 blob 内的房间秘密

但需要强调：

- 弱服务端密码可被旁路观察者离线猜解
- 弱房间密码可被服务端基于 `join_credential` 离线猜解
- 当前安全码还不足以抵抗“恶意服务端替换成员身份 / 做中间人转发”的高强度威胁模型

### 9. 外部被动流量分析能看到什么

如果观察者在链路外部抓包，而不是控制服务端：

- 能看到 TCP 连接建立、断开、连接时长
- 能看到是否使用密码握手还是邀请码握手
- 因为握手前几帧是明文协议头，所以能看到：
  - `/AUTH_HELLO`
  - `/AUTH_CHALLENGE`
  - `/AUTH_PROOF`
  - `/INVITE_HELLO`
  - `/INVITE_CHALLENGE`
  - `/INVITE_PROOF`
- 握手完成后，看不到应用层明文，但能看到每一行密文长度和时间间隔
- 当前每 30 秒有 `/ping` 心跳，容易形成稳定指纹
- 文本消息没有 padding，密文长度仍与原文长度强相关
- 附件发送会表现出明显的分片流模式：
  - 默认 `32 KiB` chunk
  - 默认窗口 `3`
  - ACK 超时 `4.5s`
  - 最多重试 `2` 次

所以从外部流量分析角度看，当前项目仍然比较容易被做：

- 协议指纹识别
- 在线行为画像
- 文本消息长度估计
- 附件发送行为识别
- 活跃时间与交互节奏推断

这也是为什么 roadmap 里把“流量混淆”列为 `P0`。

## TUI 快捷键

| 快捷键 | 功能 |
| --- | --- |
| `Ctrl+H` / `Ctrl+J` | 中英文提示切换 |
| `Ctrl+Up` / `Ctrl+Down` | 加速滚动 |
| `Ctrl+I` | 生成邀请码 |
| `Ctrl+X` | 粘贴图片或文字 |
| `Ctrl+Z` | 撤销 |
| `Ctrl+C` | 复制消息文本 |
| `Ctrl+A` | 清空输入框 |
| `Tab` | 打开附件 |
| `Esc` | 退出房间 |

补充：

- 图片会自动转为 PNG 再分片发送
- 可输入完整文件路径，或使用 `/send <path>` 发送文件
- 附件传输已带 ACK / 超时重试

## FAQ

### `alsa-sys` 找不到库

Linux 下安装 `libasound2-dev`，或者在 `Cargo.toml` 中调整相关音频依赖配置。

### PowerShell 显示乱码

建议使用 Windows Terminal，并选择支持较完整字符集的字体。

### 如何跨编译到 Windows

```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

## Roadmap / TODO

### 高优先级

- [ ] `P0` 增加流量混淆，降低消息长度、时序和行为模式被服务端侧信道观察的风险
- [ ] `P1` 软件可信性增强：面向不可信服务器场景，改进当前校验码机制，考虑基于公钥材料生成可核验校验码
- [ ] `P3` 防止服务端端口泄露，降低默认暴露端口和部署痕迹带来的识别风险

### 近期改进

- [ ] 适配低带宽服务器：窗口大小 / 分片大小可配置，或做自适应带宽控制
- [ ] 发送者本地附件回显优化：避免服务端回环完整附件
- [ ] 输入框改进：处理中英文混输导致的光标错位
- [ ] IPv6 支持
- [ ] 本地 `host` 模式安全加固：降低同目录服务端二进制被替换后的风险

### 中期重构

- [ ] client / server 单二进制整合
- [ ] 断点续传 / 大文件续发
- [ ] 移动端或 GUI 客户端

### 协议升级

- [ ] 移除长期静态 `ROOM_KEY`
- [ ] 房间密码仅用于加入认证，不再直接加密聊天消息
- [ ] 引入 `epoch rekey`
- [ ] 引入 `sender chain`
- [ ] 引入 `pairwise X25519` 分发新的 `group_secret`
- [ ] 附件升级为 `manifest + encrypted chunk` 的 hybrid encryption
- [ ] 在轻量方案稳定后评估 MLS / TreeKEM

## 许可证

本项目基于 [MIT License](LICENSE)。
