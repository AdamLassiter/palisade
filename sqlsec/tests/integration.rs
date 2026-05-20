use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use palisade_log::{GREEN, RED, RESET, style};

/// Helper: Get absolute path to extension
fn extension_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("debug");
    path.push(if cfg!(target_os = "windows") {
        "sqlsec.dll"
    } else if cfg!(target_os = "macos") {
        "libsqlsec.dylib"
    } else {
        "libsqlsec.so"
    });
    path
}

/// Run a single .sql test and compare output.
fn run_test_case(name: &str) -> bool {
    let base_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let case_dir = base_dir.join("tests/cases");
    let expected_dir = base_dir.join("tests/expected");

    let sql_path = case_dir.join(format!("{name}.sql"));
    assert!(
        sql_path.exists(),
        "missing testcase file: {}",
        sql_path.display()
    );

    let expected_out_path = expected_dir.join(format!("{name}.out"));
    let expected_err_path = expected_dir.join(format!("{name}.err"));

    // Decide mode: normal success test (.out) or failure test (.err)
    let expect_output = expected_out_path.exists();
    let expect_error = expected_err_path.exists();

    let lib_path = extension_path();
    assert!(
        lib_path.exists(),
        "extension not built: {}",
        lib_path.display()
    );

    let sql_content = fs::read_to_string(&sql_path).expect("could not read SQL test case file");

    // Feed script via stdin
    let script = format!(
        ".load {}\n.headers on\n.mode column\n{}\n",
        lib_path.display(),
        sql_content
    );

    let mut child = match Command::new("sqlite3")
        .current_dir(base_dir)
        .arg(":memory:")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            palisade_log::fail(format!("Failed to run sqlite3: {}", err));
            return false;
        }
    };

    // Send to stdin
    if let Some(stdin) = &mut child.stdin {
        if let Err(err) = stdin.write_all(script.as_bytes()) {
            palisade_log::fail(format!("Failed to write to sqlite3 stdin: {}", err));
            return false;
        }
    }

    // Capture result
    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(err) => {
            palisade_log::fail(format!("Failed to get sqlite3 output: {}", err));
            return false;
        }
    };

    // Decide whether this test passed:
    let mut success = true;

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);

    let expected_output = if expect_output {
        fs::read_to_string(expected_out_path)
            .expect("could not read expected output file")
            .trim()
            .replace("\r\n", "\n")
    } else {
        "".into()
    };

    // normal success test
    let actual_trimmed = stdout_str.trim().replace("\r\n", "\n");
    if expected_output != actual_trimmed {
        palisade_log::fail(format!("error in test case {name}"));
        eprintln!(
            "=== EXPECTED STDOUT ===\n{}\n=== GOT STDOUT ===\n{}",
            expected_output, actual_trimmed
        );
        eprintln!("=== END ERROR ===\n");
        success = false;
    }

    let expected_error = if expect_error {
        fs::read_to_string(expected_err_path)
            .expect("could not read expected error file")
            .trim()
            .replace("\r\n", "\n")
    } else {
        "".into()
    };

    let actual_trimmed = stderr_str.trim().replace("\r\n", "\n");
    if expected_error != actual_trimmed {
        palisade_log::fail(format!("error in test case {name}"));
        eprintln!(
            "=== EXPECTED STDERR ===\n{}\n=== GOT STDERR ===\n{}",
            expected_error, actual_trimmed
        );
        eprintln!("=== END ERROR ===\n");
        success = false
    }

    success
}

/// Discover all test cases (.sql)
fn test_cases() -> Vec<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cases");
    let mut names = vec![];
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.path().extension().and_then(|s| s.to_str()) == Some("sql") {
                if let Some(stem) = entry.path().file_stem() {
                    names.push(stem.to_string_lossy().to_string());
                }
            }
        }
    }
    names.sort();
    names
}

#[test]
fn run_all_sql_tests() {
    let cases = test_cases();
    let mut results = HashMap::new();
    palisade_log::section("sqlsec integration");
    palisade_log::label_value("test cases", cases.len());

    let start_time = std::time::Instant::now();
    for case in cases {
        let result = run_test_case(&case);
        let msg = if result {
            format!("{}ok{}", style(GREEN), style(RESET))
        } else {
            format!("{}fail{}", style(RED), style(RESET))
        };
        println!("\tcase {case} ... {msg}");
        results.insert(case, result);
    }
    let duration_millis = start_time.elapsed().as_millis();
    let duration_secs = duration_millis as f64 / 1000.0;

    let pass_count = results.values().filter(|&&r| r).count();
    let fail_count = results.values().filter(|&&r| !r).count();
    let status = if fail_count == 0 {
        format!("{}PASSED{}", style(GREEN), style(RESET))
    } else {
        format!("{}FAILED{}", style(RED), style(RESET))
    };
    println!(
        "\ntest result: {status}. {pass_count} passed; {fail_count} failed; finished in {duration_secs}s"
    );
    assert!(fail_count == 0, "some test cases failed");
}
