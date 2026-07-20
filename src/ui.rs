//! Colored TUI helpers. Section headers + status lines use plain ANSI styling
//! via anstyle/anstream; the startup banner is a hardcoded ansi_shadow figlet of
//! "x-key-scanner" painted with a per-column cyan→magenta truecolor gradient.

use anstyle::{AnsiColor, Color, RgbColor, Style};
use std::io::Write;

/// ansi_shadow figlet of "x-key-scanner" (generated once with pyfiglet, then
/// hardcoded so the binary needs no font files or figlet crate).
const BANNER_ART: &[&str] = &[
    "██╗  ██╗     ██╗  ██╗███████╗██╗   ██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗",
    "╚██╗██╔╝     ██║ ██╔╝██╔════╝╚██╗ ██╔╝     ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗",
    " ╚███╔╝█████╗█████╔╝ █████╗   ╚████╔╝█████╗███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝",
    " ██╔██╗╚════╝██╔═██╗ ██╔══╝    ╚██╔╝ ╚════╝╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗",
    "██╔╝ ██╗     ██║  ██╗███████╗   ██║        ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║",
    "╚═╝  ╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝        ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝",
];

fn styled(style: Style, text: &str) -> String {
    format!("{style}{text}{style:#}")
}

fn fg(c: AnsiColor) -> Style {
    Style::new().fg_color(Some(Color::Ansi(c)))
}

/// Linear cyan(0,255,255)→magenta(255,0,255) at position `t` in [0,1].
fn gradient(t: f32) -> Style {
    let t = t.clamp(0.0, 1.0);
    let r = (t * 255.0).round() as u8;
    let g = ((1.0 - t) * 255.0).round() as u8;
    Style::new().fg_color(Some(Color::Rgb(RgbColor(r, g, 255)))).bold()
}

/// Print the big startup banner: gradient figlet art + a subtitle line.
pub fn app_banner(subtitle: &str) {
    let mut out = anstream::stdout();
    let _ = writeln!(out);
    let width = BANNER_ART.iter().map(|l| l.chars().count()).max().unwrap_or(1).max(1) as f32;
    for line in BANNER_ART {
        let mut painted = String::new();
        for (col, ch) in line.chars().enumerate() {
            if ch == ' ' {
                painted.push(' ');
            } else {
                let g = gradient(col as f32 / width);
                painted.push_str(&format!("{g}{ch}{g:#}"));
            }
        }
        let _ = writeln!(out, "{painted}");
    }
    let _ = writeln!(out, "  {}\n", styled(fg(AnsiColor::BrightBlack), subtitle));
}

/// A section header (dim rule under a bold cyan title).
pub fn section(title: &str) {
    let s = fg(AnsiColor::Cyan).bold();
    let mut out = anstream::stdout();
    let _ = writeln!(out, "\n{}", styled(s, title));
    let width = title.chars().count().max(1);
    let _ = writeln!(out, "{}", styled(fg(AnsiColor::BrightBlack), &"─".repeat(width)));
}

/// A "label: value" line with a dim label and a bright value.
pub fn field(label: &str, value: &str) {
    let l = fg(AnsiColor::BrightBlack);
    let v = fg(AnsiColor::White).bold();
    let mut out = anstream::stdout();
    let _ = writeln!(out, "  {:<20} {}", styled(l, label), styled(v, value));
}

pub fn ok(msg: &str) {
    let s = fg(AnsiColor::Green).bold();
    let mut out = anstream::stdout();
    let _ = writeln!(out, "{}  {msg}", styled(s, "[ ok ]"));
}

pub fn info(msg: &str) {
    let s = fg(AnsiColor::Blue).bold();
    let mut out = anstream::stdout();
    let _ = writeln!(out, "{} {msg}", styled(s, "[info]"));
}

pub fn warn(msg: &str) {
    let s = fg(AnsiColor::Yellow).bold();
    let mut out = anstream::stderr();
    let _ = writeln!(out, "{} {msg}", styled(s, "[warn]"));
}

pub fn error(msg: &str) {
    let s = fg(AnsiColor::Red).bold();
    let mut out = anstream::stderr();
    let _ = writeln!(out, "{} {msg}", styled(s, "[fail]"));
}

/// Highlight the recovered key prominently.
pub fn key_line(label: &str, value: &str) {
    let l = fg(AnsiColor::BrightBlack);
    let v = fg(AnsiColor::BrightGreen).bold();
    let mut out = anstream::stdout();
    let _ = writeln!(out, "  {:<20} {}", styled(l, label), styled(v, value));
}
