mod crypto;
mod locate;
mod login_db;
mod platform;
mod scan;
mod ui;

use std::collections::HashSet;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use rayon::prelude::*;

use crypto::{Algo, decrypt_database, detect_algo};
use login_db::Account;
use platform::{DbHolder, ProcessAccess};

#[derive(Parser, Debug)]
#[command(
    name = "x_key_scanner",
    version,
    about = "非侵入式提取已登录 QQ 的 NTQQ 主密钥。",
    long_about = "通过扫描正在运行、已登录的 QQ 进程内存来提取 NTQQ 主密钥（raw key）。\
本工具是非侵入式的：只读取内存、只以只读方式打开锁，绝不写入或注入 QQ。\n\n\
支持多账号同时登录：自动枚举 login.db 中的全部账号，通过文件占用反查出已登录的 \
QQ 进程，逐个并发扫描并汇总结果。默认情况下工具在找到 raw key 后即停止；\
如需同时解密数据库，请加上 --output 参数。"
)]
struct Cli {
    /// 手动指定数据目录（跳过自动检测）。指向包含各账号目录的文件夹
    /// （Windows 上是 "Tencent Files"）。
    #[arg(long)]
    data_root: Option<PathBuf>,

    /// 将 login.db 及各个已登录账号的数据库解密输出到此目录（每个账号一个
    /// 子目录）。不指定时，工具在打印出 raw key 后即停止。
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

/// One account confirmed logged in, with the QQ process holding its database.
struct LoggedInAccount {
    account: Account,
    pid: u32,
    process_name: String,
}

/// Per-account memory-scan outcome (always produced, even on failure).
struct ScanResult {
    account: Account,
    pid: u32,
    process_name: String,
    candidates: usize,
    top_candidates: Vec<scan::Candidate>,
    verified: Option<(scan::Candidate, Algo)>,
    error: Option<String>,
}

fn run(cli: &Cli) -> io::Result<ExitCode> {
    ui::app_banner("非侵入式 NTQQ 主密钥提取工具");
    ui::info("支持多个 QQ 账号同时登录：自动枚举已登录账号并逐个扫描。");

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

    // --- Step 2: login.db -> accounts ----------------------------------------
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

    // --- Step 3: QQ main processes (wrapper.node) ----------------------------
    // Used to prefer the true main process when an account's database is held
    // by several QQ-named processes, and to wait for QQ to exit before
    // decrypting. Login detection itself does not depend on it.
    let wrapper_pids = platform::find_wrapper_node_pids().unwrap_or_default();
    ui::field("QQ 主进程数 (wrapper.node)", &wrapper_pids.len().to_string());

    // --- Step 4: which accounts are logged in (file occupancy -> pid) --------
    ui::section("登录检测");
    let logged_in = detect_logged_in(&root, &accounts, &wrapper_pids);
    if logged_in.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "没有账号处于登录状态：文件占用探查未发现任何 QQ 进程持有账号数据库。\
             请先登录 QQ 再重试。",
        ));
    }
    ui::field("已登录账号数", &logged_in.len().to_string());
    for li in &logged_in {
        ui::field(
            &format!("{} (uin {})", li.account.nick, li.account.uin),
            &format!("pid {} [{}]", li.pid, li.process_name),
        );
    }

    // --- Step 5: scan every pid concurrently ---------------------------------
    ui::section("内存扫描");
    let results: Vec<ScanResult> = logged_in
        .par_iter()
        .map(|li| scan_one(&root, li))
        .collect();

    // --- Step 6: aggregated results ------------------------------------------
    ui::section("结果");
    let mut verified_count = 0usize;
    for r in &results {
        match &r.verified {
            Some((cand, algo)) => {
                verified_count += 1;
                ui::ok(&format!(
                    "{} (uin {}) pid {} [{}]: raw_key 已通过 settings.db 验证",
                    r.account.nick, r.account.uin, r.pid, r.process_name
                ));
                ui::key_line("raw_key (ascii)", &String::from_utf8_lossy(&cand.key));
                ui::key_line("raw_key (hex)", &hex::encode(cand.key));
                ui::field(
                    "algorithm",
                    &format!("page={} kdf={}", algo.page.label(), algo.kdf.label()),
                );
            }
            None => {
                ui::warn(&format!(
                    "{} (uin {}) pid {} [{}]: {}",
                    r.account.nick,
                    r.account.uin,
                    r.pid,
                    r.process_name,
                    r.error.as_deref().unwrap_or("未知错误")
                ));
                for c in r.top_candidates.iter().take(5) {
                    ui::key_line(
                        &format!("x{}", c.count),
                        &format!("{}  hex={}", String::from_utf8_lossy(&c.key), hex::encode(c.key)),
                    );
                }
            }
        }
    }
    if verified_count == 0 {
        ui::warn("没有任何账号取得验证通过的 raw_key。");
        return Ok(ExitCode::FAILURE);
    }
    ui::ok(&format!("共 {} 个账号取得 raw_key", verified_count));

    // --- Step 7: optional decryption ----------------------------------------
    if let Some(out_dir) = &cli.output {
        ui::section("解密");
        // Decryption (unlike the scan) wants QQ CLOSED: a live QQ can rewrite
        // database pages mid-read and hand us a torn/corrupt page. If any QQ is
        // still up, pause and let the user close them — unless --force skips it.
        if !cli.force && qq_still_running(&logged_in_pids(&logged_in)) {
            wait_for_qq_to_exit(&logged_in)?;
        }
        decrypt_login_db(out_dir, &login_db, login_algo)?;
        for r in results.iter().filter(|r| r.verified.is_some()) {
            let (cand, algo) = r.verified.as_ref().expect("filtered above");
            let db_dir = locate::account_db_dir(&root, &r.account.uin, &r.account.uid);
            let out = out_dir.join(&r.account.uin);
            decrypt_account_dbs(&out, &db_dir, &cand.key, *algo)?;
        }
        ui::ok(&format!("数据库已解密到 {}", out_dir.display()));
    }

    Ok(ExitCode::SUCCESS)
}

/// Detect every logged-in account by reverse-mapping its database files to the
/// QQ process(es) holding them. Runs the per-account probes concurrently.
fn detect_logged_in(
    root: &Path,
    accounts: &[Account],
    wrapper_pids: &[u32],
) -> Vec<LoggedInAccount> {
    let wrapper: HashSet<u32> = wrapper_pids.iter().copied().collect();
    accounts
        .par_iter()
        .filter_map(|a| {
            let db_dir = locate::account_db_dir(root, &a.uin, &a.uid);
            let holders = platform::probe_account_db_holders(&db_dir);
            // Keep holders whose name looks like QQ (the user-facing criterion),
            // plus any known wrapper.node main process (covers name-lookup
            // failures on Unix).
            let mut matched: Vec<DbHolder> = holders
                .into_iter()
                .filter(|h| platform::is_qq_process_name(&h.name) || wrapper.contains(&h.pid))
                .collect();
            // Deduplicate by pid (one account, one process).
            let mut seen = HashSet::new();
            matched.retain(|h| seen.insert(h.pid));
            // Prefer holders that also loaded wrapper.node (the true main
            // process) over QQ-named helper processes.
            let mains: Vec<DbHolder> = matched
                .iter()
                .filter(|h| wrapper.contains(&h.pid))
                .cloned()
                .collect();
            let chosen = if mains.is_empty() { matched } else { mains };
            let holder = chosen.into_iter().next()?;
            Some(LoggedInAccount {
                account: a.clone(),
                pid: holder.pid,
                process_name: holder.name,
            })
        })
        .collect()
}

/// Scan one logged-in account's process for the raw_key and verify the
/// candidates against that account's settings.db.
fn scan_one(root: &Path, li: &LoggedInAccount) -> ScanResult {
    let db_dir = locate::account_db_dir(root, &li.account.uin, &li.account.uid);
    let mut out = ScanResult {
        account: li.account.clone(),
        pid: li.pid,
        process_name: li.process_name.clone(),
        candidates: 0,
        top_candidates: Vec::new(),
        verified: None,
        error: None,
    };
    let access = match platform::PlatformAccess::open(li.pid) {
        Ok(a) => a,
        Err(e) => {
            out.error = Some(format!("无法打开进程: {e}"));
            return out;
        }
    };
    let candidates = match scan::scan(&access) {
        Ok(c) => c,
        Err(e) => {
            out.error = Some(format!("内存扫描失败: {e}"));
            return out;
        }
    };
    out.candidates = candidates.len();
    if candidates.is_empty() {
        out.error = Some("内存扫描未在 HMAC_SHA1 锚点附近找到任何 raw_key 候选".to_string());
        return out;
    }
    out.top_candidates = candidates.iter().take(5).cloned().collect();
    let settings_db = db_dir.join("settings.db");
    out.verified = verify_against_settings(&settings_db, &candidates);
    if out.verified.is_none() {
        out.error = Some(
            "无法用 settings.db 验证任何候选（文件缺失，或 QQ 在内存中改动了密钥）".to_string(),
        );
    }
    out
}

/// Try each raw_key candidate against settings.db, brute-forcing the algorithm
/// pair. Candidate checks run in parallel, while `find_map_first` preserves the
/// scanner's character-class and frequency priority.
fn verify_against_settings(
    settings_db: &Path,
    candidates: &[scan::Candidate],
) -> Option<(scan::Candidate, Algo)> {
    let bytes = std::fs::read(settings_db).ok()?;
    candidates.par_iter().find_map_first(|cand| {
        let pass = hex_passphrase(&cand.key);
        detect_algo(&bytes, &pass).map(|verified| (cand.clone(), verified.algo))
    })
}

/// QQ's raw_key is 16 printable bytes used as the SQLCipher passphrase. Match
/// the reference: pass the bytes through verbatim (the KDF salts + stretches).
fn hex_passphrase(key: &[u8; 16]) -> Vec<u8> {
    key.to_vec()
}

/// Whether any of the given QQ pids is still alive — re-enumerates the
/// `wrapper.node` holders and checks membership (cross-platform, no new syscall).
fn qq_still_running(pids: &[u32]) -> bool {
    platform::find_wrapper_node_pids()
        .map(|alive| pids.iter().any(|p| alive.contains(p)))
        .unwrap_or(false)
}

fn logged_in_pids(logged_in: &[LoggedInAccount]) -> Vec<u32> {
    logged_in.iter().map(|li| li.pid).collect()
}

/// Pause before decrypting while QQ is still running. The user can either close
/// all QQ instances (we poll until they exit) or press Enter to ignore the
/// warning and decrypt the live databases anyway.
fn wait_for_qq_to_exit(logged_in: &[LoggedInAccount]) -> io::Result<()> {
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

    let pids = logged_in_pids(logged_in);
    loop {
        if !qq_still_running(&pids) {
            ui::ok("QQ 已退出，开始解密。");
            return Ok(());
        }
        if rx.recv_timeout(Duration::from_millis(500)).is_ok() {
            ui::info("已忽略警告，继续解密（QQ 仍在运行）。");
            return Ok(());
        }
    }
}

/// Decrypt the global login.db into `out_dir/login.db`.
fn decrypt_login_db(out_dir: &Path, login_db: &Path, login_algo: Algo) -> io::Result<()> {
    std::fs::create_dir_all(out_dir)?;
    // login.db uses the built-in pre-login key + its own detected algo.
    if let Ok(bytes) = std::fs::read(login_db) {
        if let Some(plain) = decrypt_database(&bytes, b"BD156D6710D54D8782F4", &login_algo) {
            std::fs::write(out_dir.join("login.db"), plain)?;
            ui::ok("已解密 login.db");
        }
    }
    Ok(())
}

/// Decrypt every `*.db` of one account's `nt_db` directory into `out_dir`,
/// using the scanned raw_key.
fn decrypt_account_dbs(
    out_dir: &Path,
    db_dir: &Path,
    raw_key: &[u8; 16],
    algo: Algo,
) -> io::Result<()> {
    std::fs::create_dir_all(out_dir)?;

    let pass = raw_key.to_vec();
    let entries: Vec<PathBuf> = match std::fs::read_dir(db_dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "db"))
            .collect(),
        Err(e) => {
            ui::warn(&format!("无法读取账号数据库目录 {}：{e}", db_dir.display()));
            return Ok(());
        }
    };

    use indicatif::{ProgressBar, ProgressStyle};
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
