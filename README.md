# x_key_scanner

> [!tip]
>
> 这是一个**注意力惊人**的项目

从**正在运行、已登录**的 QQ NT 客户端进程内存中，提取 **NTQQ 主数据库密钥**
并可选地解密 QQ 的本地数据库。

## 非侵入式

本工具对 QQ 是**只读**的：只读取进程内存、只以只读方式打开登录锁、只复制数据库文件出来，绝不修改、注入或调试 QQ 进程。

> 比起常规的hook手段更方便 和 安全。  几乎不可能有被QQ检测到的风险

## 使用前提

- **支持多开**：工具自动枚举 login.db 中的全部账号，通过文件占用反查出已登录的 QQ 进程并逐个并发扫描；每个已登录账号都会输出自己的 raw_key。
- **QQ 保持登录、保持运行**。密钥只存在于运行中的进程内存里，扫描时 QQ 必须活着。
- 若运行失败，**尝试提权运行**：
  - **Windows**：在**管理员终端**中运行。
  - **Linux**：用 **`sudo`** 运行（或授予 `CAP_SYS_PTRACE`）。若仍失败，检查 `/proc/sys/kernel/yama/ptrace_scope`。
  - **macOS**：用 **`sudo`** 运行。若 `sudo` 仍失败，通常是目标启用了强化运行时（hardened runtime），该系统版本无法授予任务端口，此时无法扫描内存。

## 快速开始

下载自己平台的release文件

```sh
# 默认：检测所有已登录账号、逐个扫描内存、打印每个账号验证过的 raw_key。
sudo ./x_key_scanner            # macOS / Linux
x_key_scanner.exe               # Windows cmd/powershell
```

输出中的 `raw_key (hex)` 就是你要的主密钥。

## 解密数据库

加上 `--output` 会在打印密钥后，把 `login.db` 解密到指定目录，每个已登录账号的数据库解密到 `<输出目录>/<uin>/` 子目录：

```sh
sudo ./x_key_scanner --output ./plain
```

每个数据库都会**连同它的 `-wal` 一起解密并合并**。QQ 的数据库常驻 WAL 模式，最近一次检查点之后的所有改动（刚登录的账号、刚收发的消息）都只存在于 `-wal` 里：

- 枚举账号时会先回放 `-wal`，所以**本次刚登录的账号也能被扫到**；
- 输出的 `login.db` / `*.db` 是合并后的普通 SQLite 文件，自包含、可直接打开，不会附带 `-wal` / `-shm`；
- 若 `-wal` 有半截写入（QQ 仍在运行时可能出现），只回放校验通过的部分，并给出提示。

解密数据库**建议先关闭 QQ**：运行中的 QQ 可能在读取过程中改写数据页，导致解密结果损坏。因此加了 `--output` 后：

- 若仍有 QQ 在运行，工具会**暂停等待**——你关闭所有 QQ 后它会**自动继续**；
- 或直接**按回车**忽略警告，立即解密（QQ 仍运行，结果可能不完整）。

若不想要这个等待环节，加 `--force` 直接跳过、立即解密：

```sh
sudo ./x_key_scanner --output ./plain --force
```

## 自动检测失败时

工具会自动定位 QQ 数据目录。若失败，用 `--data-root` 手动指定（指向包含各账号目录的文件夹，Windows 上通常是 `.../Tencent Files`）：

```sh
./x_key_scanner --data-root "/path/to/QQ"
```

也可以在工具提示时直接输入路径。

## 参数一览

| 参数 | 说明 |
| ---- | ---- |
| `--output <目录>` | 将 `login.db` 及各个已登录账号的数据库解密到该目录（每个账号一个子目录；不加则只打印密钥后停止）。 |
| `--data-root <目录>` | 手动指定数据目录，跳过自动检测。 |
| `--force` | 配合 `--output`：跳过“等待 QQ 退出”的暂停，立即解密。 |

## 支持平台

每次发布都会提供以下 6 个目标的预编译二进制：

| 系统    | x86_64                     | arm64                       |
| ------- | -------------------------- | --------------------------- |
| Windows | `x86_64-pc-windows-msvc`   | `aarch64-pc-windows-msvc`   |
| Linux   | `x86_64-unknown-linux-gnu` | `aarch64-unknown-linux-gnu` |
| macOS   | `x86_64-apple-darwin`      | `aarch64-apple-darwin`      |

## 自行编译

```sh
cargo build --release
```
