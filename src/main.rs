mod crypto;
mod locate;
mod login_db;
mod platform;
mod scan;
mod ui;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;

use crypto::{Algo, decrypt_database, detect_algo};
use login_db::Account;
use platform::ProcessAccess;

#[derive(Parser, Debug)]
#[command(
    name = "x_key_scanner",
    version,
    about = "非侵入式提取已登录 QQ 的 NTQQ 主密钥。",
    long_about = "通过扫描正在运行、已登录的 QQ 进程内存来提取 NTQQ 主密钥（raw key）。\
本工具是非侵入式的：只读取内存、只以只读方式打开锁，绝不写入或注入 QQ。\n\n\
运行前请确保只登录了一个 QQ 账号。默认情况下工具在找到 raw key 后即停止；\
如需同时解密数据库，请加上 --output 参数。"
)]
struct Cli {
    /// 手动指定数据目录（跳过自动检测）。指向包含各账号目录的文件夹
    /// （Windows 上是 "Tencent Files"）。
    #[arg(long)]
    data_root: Option<PathBuf>,

    /// 将 login.db 及该账号的数据库解密输出到此目录。不指定时，工具在
    /// 打印出 raw key 后即停止。
    #[arg(long)]
    output: Option<PathBuf>,

    /// 配合 --output 使用：跳过“等待 QQ 退出”的暂停，即使 QQ 仍在运行也
    /// 立即解密（对运行中的数据库解密可能得到损坏的数据页）。
    #[arg(long)]
    force: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    run(&cli).unwrap_or_else(|e| {
        ui::error(&e.to_string());
        ExitCode::FAILURE
    })
}

fn run(cli: &Cli) -> io::Result<ExitCode> {
    ui::app_banner("非侵入式 NTQQ 主密钥提取工具");
    ui::info("请确保当前只登录了一个 QQ 账号，工具将提取该账号的密钥。");

    if !platform::is_elevated() {
        ui::warn(&format!(
            "当前未以管理员/root 权限运行，内存扫描很可能失败。请{}。",
            platform::elevation_hint()
        ));
    }

    // --- Step 1: data root ---------------------------------------------------
    let root = match &cli.data_root {
        Some(p) => p.clone(),
        None => match locate::detect_data_root() {
            Some(p) if p.exists() => p,
            other => {
                if let Some(p) = other {
                    ui::warn(&format!("检测到的数据目录不存在：{}", p.display()));
                }
                prompt_for_root()?
            }
        },
    };
    ui::section("检测");
    ui::field("数据目录", &root.display().to_string());

    // --- Step 2: main process (wrapper.node) ---------------------------------
    let pids = platform::find_wrapper_node_pids()?;
    let pid = match pids.as_slice() {
        [] => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "未找到 QQ 主进程（没有进程加载了 wrapper.node）。请确认 QQ 已启动并已登录。",
            ));
        }
        [pid] => *pid,
        many => {
            return Err(io::Error::other(
                format!(
                    "发现 {} 个 QQ 主进程（{many:?}）；只允许登录一个账号。请关闭多余的 QQ 后重试。",
                    many.len()
                ),
            ));
        }
    };
    ui::field("主进程 PID", &pid.to_string());

    // --- Step 3: login.db -> accounts ---------------------------------------
    let login_candidates = locate::login_db_candidates(&root);
    // For decryption later we need a concrete file; prefer the first candidate
    // that exists, falling back to the primary path for the error message.
    let login_db = login_candidates
        .iter()
        .find(|p| p.exists())
        .cloned()
        .unwrap_or_else(|| login_candidates[0].clone());
    let (accounts, login_algo) = login_db::read_accounts_merged(&login_candidates).map_err(|e| {
        io::Error::new(e.kind(), format!("reading {}: {e}", login_db.display()))
    })?;
    if accounts.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "login.db 解密成功，但未列出任何账号",
        ));
    }
    ui::field("login.db 账号数", &accounts.len().to_string());
    for a in &accounts {
        ui::field("  candidate", &format!("{} (uin {}, uid {})", a.nick, a.uin, a.uid));
    }

    // --- Step 4: which account is logged in ----------------------------------
    let (account, holder_pid) = pick_logged_in(&root, &accounts)?;
    ui::field("已登录账号", &format!("{} (uin {})", account.nick, account.uin));
    if let Some(hp) = holder_pid {
        if hp != pid {
            ui::warn(&format!(
                "锁持有进程 pid {hp} 与主进程 pid {pid} 不一致；将继续使用 {pid}。"
            ));
        }
    }

    // --- Step 5: account DB dir ---------------------------------------------
    let db_dir = locate::account_db_dir(&root, &account.uin, &account.uid);
    ui::field("账号数据库目录", &db_dir.display().to_string());
    if !db_dir.exists() {
        ui::warn(&format!("账号数据库目录不存在：{}", db_dir.display()));
    }

    // --- Step 6: memory scan -------------------------------------------------
    // Scanning REQUIRES QQ to be live (the key only exists in the running
    // process's memory), so there is nothing to warn about here — the
    // "close QQ" guidance belongs to the decryption step, not this one.
    ui::section("内存扫描");
    let access = platform::PlatformAccess::open(pid)?;
    let candidates = scan::scan(&access)?;
    if candidates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "内存扫描未在 HMAC_SHA1 锚点附近找到任何 raw_key 候选",
        ));
    }
    ui::field("raw_key 候选数", &candidates.len().to_string());

    // --- Step 7: verify candidates against settings.db -----------------------
    let settings_db = db_dir.join("settings.db");
    let verified = verify_against_settings(&settings_db, &candidates);

    ui::section("结果");
    let (raw_key, algo) = match verified {
        Some((cand, algo)) => {
            ui::ok("raw_key 已通过 settings.db 验证");
            ui::key_line("raw_key (ascii)", &String::from_utf8_lossy(&cand.key));
            ui::key_line("raw_key (hex)", &hex::encode(cand.key));
            ui::field("algorithm", &format!("page={} kdf={}", algo.page.label(), algo.kdf.label()));
            (cand.key, algo)
        }
        None => {
            // Could not verify (settings.db missing, or QQ mangled the key in
            // memory). Still show the top candidates so the user isn't stuck.
            ui::warn(
                "无法用 settings.db 验证任何候选（文件缺失，或 QQ 在内存中改动了密钥）。\
                 以下为未验证的候选：",
            );
            for c in candidates.iter().take(5) {
                ui::key_line(
                    &format!("x{}", c.count),
                    &format!("{}  hex={}", String::from_utf8_lossy(&c.key), hex::encode(c.key)),
                );
            }
            return Ok(ExitCode::FAILURE);
        }
    };

    // --- Step 8/9: optional decryption --------------------------------------
    if let Some(out_dir) = &cli.output {
        ui::section("解密");
        // Decryption (unlike the scan) wants QQ CLOSED: a live QQ can rewrite
        // database pages mid-read and hand us a torn/corrupt page. If QQ is
        // still up, pause and let the user close it — unless --force skips it.
        if !cli.force && qq_still_running(pid) {
            wait_for_qq_to_exit(pid)?;
        }
        decrypt_all(out_dir, &login_db, login_algo, &db_dir, &raw_key, algo)?;
        ui::ok(&format!("数据库已解密到 {}", out_dir.display()));
    }

    Ok(ExitCode::SUCCESS)
}

/// Whether the QQ main process (`pid`) is still alive — re-enumerates the
/// `wrapper.node` holders and checks membership (cross-platform, no new syscall).
fn qq_still_running(pid: u32) -> bool {
    platform::find_wrapper_node_pids()
        .map(|pids| pids.contains(&pid))
        .unwrap_or(false)
}

/// Pause before decrypting while QQ is still running. The user can either close
/// QQ (we poll until it exits) or press Enter to ignore the warning and decrypt
/// the live database anyway.
fn wait_for_qq_to_exit(pid: u32) -> io::Result<()> {
    use std::sync::mpsc;
    use std::time::Duration;

    ui::warn(
        "QQ 仍在运行。对运行中的数据库解密可能得到损坏的数据页。\
         建议关闭 QQ 以获得干净的解密结果。",
    );
    ui::info("请关闭 QQ（将自动继续），或直接按回车忽略并立即解密……");

    // Read a line on a background thread so we can poll QQ's status meanwhile.
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = io::stdin().read_line(&mut line);
        let _ = tx.send(());
    });

    loop {
        if !qq_still_running(pid) {
            ui::ok("QQ 已退出，开始解密。");
            return Ok(());
        }
        if rx.recv_timeout(Duration::from_millis(500)).is_ok() {
            ui::info("已忽略警告，继续解密（QQ 仍在运行）。");
            return Ok(());
        }
    }
}

/// Determine which cached account is currently logged in (exactly one expected).
fn pick_logged_in<'a>(
    root: &Path,
    accounts: &'a [Account],
) -> io::Result<(&'a Account, Option<u32>)> {
    let mut hits = Vec::new();
    for a in accounts {
        let db_dir = locate::account_db_dir(root, &a.uin, &a.uid);
        let (logged_in, holder) = platform::is_account_logged_in(&a.uin, &db_dir);
        if logged_in {
            hits.push((a, holder));
        }
    }
    match hits.as_slice() {
        [] => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "当前没有账号处于登录状态（未检测到锁/互斥体）。请先登录 QQ 再重试。",
        )),
        [one] => Ok(*one),
        many => Err(io::Error::other(
            format!(
                "检测到 {} 个账号处于登录状态；只允许登录一个账号。",
                many.len()
            ),
        )),
    }
}

/// Try each raw_key candidate against settings.db, brute-forcing the algorithm
/// pair. Returns the first that decrypts, with its algorithm.
fn verify_against_settings(
    settings_db: &Path,
    candidates: &[scan::Candidate],
) -> Option<(scan::Candidate, Algo)> {
    let bytes = std::fs::read(settings_db).ok()?;
    for cand in candidates {
        let pass = hex_passphrase(&cand.key);
        if let Some(v) = detect_algo(&bytes, &pass) {
            return Some((cand.clone(), v.algo));
        }
    }
    None
}

/// QQ's raw_key is 16 printable bytes used as the SQLCipher passphrase. Match
/// the reference: pass the bytes through verbatim (the KDF salts + stretches).
fn hex_passphrase(key: &[u8; 16]) -> Vec<u8> {
    key.to_vec()
}

fn decrypt_all(
    out_dir: &Path,
    login_db: &Path,
    login_algo: Algo,
    db_dir: &Path,
    raw_key: &[u8; 16],
    algo: Algo,
) -> io::Result<()> {
    std::fs::create_dir_all(out_dir)?;

    // login.db uses the built-in pre-login key + its own detected algo.
    if let Ok(bytes) = std::fs::read(login_db) {
        if let Some(plain) = decrypt_database(&bytes, b"BD156D6710D54D8782F4", &login_algo) {
            std::fs::write(out_dir.join("login.db"), plain)?;
            ui::ok("已解密 login.db");
        }
    }

    // Account databases use the scanned raw_key.
    let pass = raw_key.to_vec();
    let entries: Vec<PathBuf> = std::fs::read_dir(db_dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "db"))
        .collect();

    use indicatif::{ProgressBar, ProgressStyle};
    use rayon::prelude::*;

    let bar = ProgressBar::new(entries.len() as u64);
    bar.set_style(
        ProgressStyle::with_template(
            "  {spinner:.cyan} [{bar:32.cyan/blue}] {pos}/{len}  {msg}",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("██░"),
    );

    let results: Vec<(PathBuf, bool)> = entries
        .par_iter()
        .map(|src| {
            let name = src.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            bar.set_message(name);
            let ok = (|| {
                let bytes = std::fs::read(src).ok()?;
                let plain = decrypt_database(&bytes, &pass, &algo)?;
                let name = src.file_name()?;
                std::fs::write(out_dir.join(name), plain).ok()?;
                Some(())
            })()
            .is_some();
            bar.inc(1);
            (src.clone(), ok)
        })
        .collect();

    bar.finish_and_clear();

    for (src, ok) in results {
        let name = src.file_name().unwrap_or_default().to_string_lossy();
        if ok {
            ui::ok(&format!("已解密 {name}"));
        } else {
            ui::warn(&format!("跳过 {name}（算法不匹配，或来自运行中 QQ 的损坏数据页）"));
        }
    }
    Ok(())
}

fn prompt_for_root() -> io::Result<PathBuf> {
    ui::info("无法自动检测到 QQ 数据目录，请手动输入：");
    print!("  数据目录路径> ");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let p = PathBuf::from(line.trim());
    if p.as_os_str().is_empty() || !p.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "未提供有效的数据目录",
        ));
    }
    Ok(p)
}
