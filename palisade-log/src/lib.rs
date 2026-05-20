use std::{
    io::{self, IsTerminal, Write},
    sync::{
        Arc,
        Mutex,
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const GREEN: &str = "\x1b[32m";
pub const YELLOW: &str = "\x1b[33m";
pub const BLUE: &str = "\x1b[34m";
pub const MAGENTA: &str = "\x1b[35m";
pub const CYAN: &str = "\x1b[36m";
pub const RED: &str = "\x1b[31m";

static TRANSIENT_ACTIVE: OnceLock<Mutex<bool>> = OnceLock::new();

pub fn style(code: &'static str) -> &'static str {
    if io::stdout().is_terminal() { code } else { "" }
}

fn transient_state() -> &'static Mutex<bool> {
    TRANSIENT_ACTIVE.get_or_init(|| Mutex::new(false))
}

pub fn clear_transient() {
    let Ok(mut active) = transient_state().lock() else {
        return;
    };
    if *active && io::stdout().is_terminal() {
        print!("\r\x1b[2K");
        let _ = io::stdout().flush();
    }
    *active = false;
}

pub fn transient(msg: impl AsRef<str>) {
    if !io::stdout().is_terminal() {
        return;
    }
    let Ok(mut active) = transient_state().lock() else {
        return;
    };
    print!(
        "\r\x1b[2K{}·{} {}{}{}",
        style(DIM),
        style(RESET),
        style(DIM),
        msg.as_ref(),
        style(RESET)
    );
    let _ = io::stdout().flush();
    *active = true;
}

pub fn persist(msg: impl AsRef<str>) {
    clear_transient();
    println!("  {}•{} {}", style(CYAN), style(RESET), msg.as_ref());
}

pub fn banner(title: impl AsRef<str>, detail: impl AsRef<str>) {
    println!(
        "\n{}{}{}{} {}{}{}",
        style(BOLD),
        style(MAGENTA),
        title.as_ref(),
        style(RESET),
        style(DIM),
        detail.as_ref(),
        style(RESET)
    );
}

pub fn section(title: impl AsRef<str>) {
    clear_transient();
    println!(
        "\n{}{}{}{}",
        style(BOLD),
        style(CYAN),
        title.as_ref(),
        style(RESET)
    );
}

pub fn label_value(label: impl AsRef<str>, value: impl std::fmt::Display) {
    println!(
        "  {}{}{}: {}",
        style(DIM),
        label.as_ref(),
        style(RESET),
        value
    );
}

pub fn phase(msg: impl AsRef<str>) {
    clear_transient();
    println!("{}→{} {}", style(BLUE), style(RESET), msg.as_ref());
}

pub fn success(msg: impl AsRef<str>) {
    clear_transient();
    println!("{}✓{} {}", style(GREEN), style(RESET), msg.as_ref());
}

pub fn warn(msg: impl AsRef<str>) {
    clear_transient();
    println!("{}!{} {}", style(YELLOW), style(RESET), msg.as_ref());
}

pub fn fail(msg: impl AsRef<str>) {
    clear_transient();
    eprintln!("{}✗{} {}", style(RED), style(RESET), msg.as_ref());
}

pub fn print_validation(checks: &[String]) {
    clear_transient();
    section("Validation");
    for line in checks {
        println!("  {}{}{}", style(GREEN), line, style(RESET));
    }
}

pub fn left_cell(value: &str, width: usize, color: &'static str) -> String {
    left_cell_styled(value, width, style(color), style(RESET))
}

pub fn right_cell(value: &str, width: usize, color: &'static str) -> String {
    right_cell_styled(value, width, style(color), style(RESET))
}

pub fn left_cell_styled(value: &str, width: usize, start: &str, end: &str) -> String {
    let padding = width.saturating_sub(value.len());
    format!("{}{}{}{}", start, value, end, " ".repeat(padding))
}

pub fn right_cell_styled(value: &str, width: usize, start: &str, end: &str) -> String {
    let padding = width.saturating_sub(value.len());
    format!("{}{}{}{}", " ".repeat(padding), start, value, end)
}

pub struct Spinner {
    done: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    label: String,
    animated: bool,
}

impl Spinner {
    pub fn start(label: impl Into<String>) -> Self {
        let label = label.into();
        let animated = io::stderr().is_terminal();
        if !io::stdout().is_terminal() || !animated {
            phase(&label);
        }
        let done = Arc::new(AtomicBool::new(false));
        let handle = if animated {
            let done_for_thread = done.clone();
            let label_for_thread = label.clone();
            Some(thread::spawn(move || {
                let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
                let mut i = 0usize;
                while !done_for_thread.load(Ordering::Relaxed) {
                    eprint!(
                        "\r{}{}{} {}{}{}",
                        style(CYAN),
                        frames[i % frames.len()],
                        style(RESET),
                        style(DIM),
                        label_for_thread,
                        style(RESET)
                    );
                    let _ = io::stderr().flush();
                    i += 1;
                    thread::sleep(Duration::from_millis(90));
                }
            }))
        } else {
            None
        };
        Self {
            done,
            handle,
            label,
            animated,
        }
    }

    pub fn finish(mut self, msg: impl AsRef<str>) {
        self.stop();
        success(msg);
    }

    fn stop(&mut self) {
        self.done.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        if self.animated {
            eprint!("\r\x1b[2K");
            let _ = io::stderr().flush();
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        if self.handle.is_some() {
            self.stop();
            warn(format!("{} interrupted", self.label));
        }
    }
}

pub struct TestLogger {
    pub passed: u32,
    pub failed: u32,
    section: String,
}

impl TestLogger {
    pub fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
            section: String::new(),
        }
    }

    pub fn section(&mut self, name: &str) {
        self.section = name.to_string();
        section(name);
    }

    pub fn ok(&mut self, msg: &str) {
        self.passed += 1;
        println!("  {}✓{} {msg}", style(GREEN), style(RESET));
    }

    pub fn fail(&mut self, msg: &str, err: &dyn std::fmt::Display) {
        self.failed += 1;
        eprintln!("  {}✗{} {msg}: {err}", style(RED), style(RESET));
    }

    pub fn assert_eq<T: PartialEq + std::fmt::Debug>(
        &mut self,
        label: &str,
        got: &T,
        expected: &T,
    ) {
        if got == expected {
            self.ok(label);
        } else {
            self.failed += 1;
            eprintln!(
                "  {}✗{} {label}: expected {expected:?}, got {got:?}",
                style(RED),
                style(RESET)
            );
        }
    }

    pub fn summary(&self) {
        section("Summary");
        println!("  {}passed{}: {}", style(DIM), style(RESET), self.passed);
        println!("  {}failed{}: {}", style(DIM), style(RESET), self.failed);
        println!(
            "  {}total{}: {}",
            style(DIM),
            style(RESET),
            self.passed + self.failed
        );
        if self.failed > 0 {
            warn("some tests failed");
        } else {
            success("all tests passed");
        }
    }
}

impl Default for TestLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{left_cell_styled, right_cell_styled};

    fn strip_ansi(input: &str) -> String {
        let mut out = String::new();
        let mut chars = input.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\x1b' && chars.peek() == Some(&'[') {
                chars.next();
                for next in chars.by_ref() {
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(ch);
            }
        }
        out
    }

    #[test]
    fn left_cells_keep_rhs_padding_outside_color() {
        for workload in ["balanced", "scan-heavy", "transfer-heavy"] {
            let cell = left_cell_styled(workload, 16, "\x1b[36m", "\x1b[0m");
            assert!(cell.ends_with(' ') || workload.len() >= 16);
            assert_eq!(strip_ansi(&cell), format!("{workload:<16}"));
        }
    }

    #[test]
    fn right_cells_keep_lhs_padding_outside_color() {
        let cell = right_cell_styled("135.19", 10, "\x1b[32m", "\x1b[0m");
        assert!(cell.starts_with("    \x1b[32m"));
        assert_eq!(strip_ansi(&cell), format!("{:>10}", "135.19"));
    }
}
