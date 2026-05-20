#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::{
    env,
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

#[derive(Clone, Copy)]
enum TransientStream {
    Stdout,
    Stderr,
}

#[derive(Default)]
struct TransientState {
    stdout: bool,
    stderr: bool,
}

static TRANSIENT_ACTIVE: OnceLock<Mutex<TransientState>> = OnceLock::new();

pub fn style(code: &'static str) -> &'static str {
    if io::stdout().is_terminal() { code } else { "" }
}

fn transient_state() -> &'static Mutex<TransientState> {
    TRANSIENT_ACTIVE.get_or_init(|| Mutex::new(TransientState::default()))
}

fn stream_is_terminal(stream: TransientStream) -> bool {
    match stream {
        TransientStream::Stdout => io::stdout().is_terminal(),
        TransientStream::Stderr => io::stderr().is_terminal(),
    }
}

fn stream_style(stream: TransientStream, code: &'static str) -> &'static str {
    if stream_is_terminal(stream) { code } else { "" }
}

fn write_stream(stream: TransientStream, text: &str) {
    match stream {
        TransientStream::Stdout => {
            print!("{text}");
            let _ = io::stdout().flush();
        }
        TransientStream::Stderr => {
            eprint!("{text}");
            let _ = io::stderr().flush();
        }
    }
}

fn preferred_transient_stream() -> Option<TransientStream> {
    if io::stdout().is_terminal() {
        Some(TransientStream::Stdout)
    } else if io::stderr().is_terminal() {
        Some(TransientStream::Stderr)
    } else {
        None
    }
}

fn terminal_columns(stream: TransientStream) -> usize {
    if let Ok(columns) = env::var("COLUMNS")
        && let Ok(columns) = columns.parse::<usize>()
        && columns > 0
    {
        return columns;
    }

    #[cfg(unix)]
    {
        let fd = match stream {
            TransientStream::Stdout => io::stdout().as_raw_fd(),
            TransientStream::Stderr => io::stderr().as_raw_fd(),
        };
        let mut winsize = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: ioctl only writes to the provided winsize struct for the selected terminal fd.
        let rc = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut winsize) };
        if rc == 0 && winsize.ws_col > 0 {
            return winsize.ws_col as usize;
        }
    }

    80
}

fn transient_width(stream: TransientStream) -> usize {
    terminal_columns(stream).saturating_sub(1).max(1)
}

fn char_len(value: &str) -> usize {
    value.chars().count()
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if char_len(value) <= max_chars {
        return value.to_string();
    }
    if max_chars <= 3 {
        return value.chars().take(max_chars).collect();
    }

    let mut out: String = value.chars().take(max_chars - 3).collect();
    out.push_str("...");
    out
}

fn stream_active(active: &mut TransientState, stream: TransientStream) -> &mut bool {
    match stream {
        TransientStream::Stdout => &mut active.stdout,
        TransientStream::Stderr => &mut active.stderr,
    }
}

fn clear_stream(active: &mut TransientState, stream: TransientStream) {
    let active_for_stream = stream_active(active, stream);
    if *active_for_stream && stream_is_terminal(stream) {
        write_stream(stream, "\r\x1b[2K\r");
    }
    *active_for_stream = false;
}

pub fn clear_transient() {
    let Ok(mut active) = transient_state().lock() else {
        return;
    };
    clear_stream(&mut active, TransientStream::Stdout);
    clear_stream(&mut active, TransientStream::Stderr);
}

pub fn transient(msg: impl AsRef<str>) {
    let Some(stream) = preferred_transient_stream() else {
        return;
    };
    let Ok(mut active) = transient_state().lock() else {
        return;
    };
    let prefix = "· ";
    let msg = truncate_chars(
        msg.as_ref(),
        transient_width(stream).saturating_sub(char_len(prefix)),
    );
    write_stream(
        stream,
        &format!(
            "\r\x1b[2K\r{}·{} {}{}{}",
            stream_style(stream, DIM),
            stream_style(stream, RESET),
            stream_style(stream, DIM),
            msg,
            stream_style(stream, RESET)
        ),
    );
    *stream_active(&mut active, stream) = true;
}

fn render_spinner_frame(stream: TransientStream, frame: &str, label: &str) {
    write_stream(
        stream,
        &format!(
            "\r\x1b[2K\r{}{}{} {}{}{}",
            stream_style(stream, CYAN),
            frame,
            stream_style(stream, RESET),
            stream_style(stream, DIM),
            label,
            stream_style(stream, RESET)
        ),
    );
}

fn truncate_spinner_label(stream: TransientStream, frame: &str, label: &str) -> String {
    truncate_chars(
        label,
        transient_width(stream)
            .saturating_sub(char_len(frame))
            .saturating_sub(1),
    )
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
}

impl Spinner {
    pub fn start(label: impl Into<String>) -> Self {
        let label = label.into();
        let stream = preferred_transient_stream();
        if !io::stdout().is_terminal() {
            phase(&label);
        }
        let done = Arc::new(AtomicBool::new(false));
        let handle = if let Some(stream) = stream {
            let done_for_thread = done.clone();
            let label_for_thread = label.clone();
            Some(thread::spawn(move || {
                let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
                let mut i = 0usize;
                while !done_for_thread.load(Ordering::Relaxed) {
                    let Ok(mut active) = transient_state().lock() else {
                        break;
                    };
                    let frame = frames[i % frames.len()];
                    let label = truncate_spinner_label(stream, frame, &label_for_thread);
                    render_spinner_frame(stream, frame, &label);
                    *stream_active(&mut active, stream) = true;
                    drop(active);
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
            clear_transient();
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
    use super::{left_cell_styled, right_cell_styled, truncate_chars};

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

    #[test]
    fn truncation_keeps_transient_output_within_width() {
        assert_eq!(truncate_chars("running workload", 32), "running workload");
        assert_eq!(truncate_chars("running workload", 10), "running...");
        assert_eq!(truncate_chars("running workload", 3), "run");
        assert_eq!(truncate_chars("running workload", 0), "");
    }
}
