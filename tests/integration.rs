use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

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
    let expect_error = expected_err_path.exists();
    let expected_path = if expect_error {
        &expected_err_path
    } else {
        &expected_out_path
    };

    assert!(
        expected_path.exists(),
        "missing expected output or error file: {}.out/.err",
        name
    );

    let lib_path = extension_path();
    assert!(
        lib_path.exists(),
        "extension not built: {}",
        lib_path.display()
    );

    let expected_output = fs::read_to_string(expected_path).expect("could not read expected file");
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
            eprintln!("Failed to run sqlite3: {}", err);
            return false;
        }
    };

    // Send to stdin
    if let Some(stdin) = &mut child.stdin {
        if let Err(err) = stdin.write_all(script.as_bytes()) {
            eprintln!("Failed to write to sqlite3 stdin: {}", err);
            return false;
        }
    }

    // Capture result
    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(err) => {
            eprintln!("Failed to get sqlite3 output: {}", err);
            return false;
        }
    };

    // Decide whether this test passed:
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);

    let expected_trimmed = expected_output.trim().replace("\r\n", "\n");

    if expect_error {
        // expected failure test
        if output.status.success() {
            eprintln!("\n=== ERROR IN TEST CASE ===\n{}", name);
            eprintln!("Expected sqlite3 to fail, but it succeeded.");
            eprintln!("=== END ERROR ===\n");
            return false;
        }

        let actual_trimmed = stderr_str.trim().replace("\r\n", "\n");
        if expected_trimmed != actual_trimmed {
            eprintln!("\n=== ERROR IN TEST CASE ===\n{}", name);
            eprintln!(
                "=== EXPECTED STDERR ===\n{}\n=== GOT STDERR ===\n{}",
                expected_trimmed, actual_trimmed
            );
            eprintln!("=== END ERROR ===\n");
            return false;
        }
    } else {
        // normal success test
        if !output.status.success() {
            eprintln!("\n=== ERROR IN TEST CASE ===\n{}", name);
            eprintln!("sqlite3 exited with {:?}", output.status.code());
            eprintln!("stdout:\n{}", stdout_str);
            eprintln!("stderr:\n{}", stderr_str);
            eprintln!("=== END ERROR ===\n");
            return false;
        }

        let actual_trimmed = stdout_str.trim().replace("\r\n", "\n");
        if expected_trimmed != actual_trimmed {
            eprintln!("\n=== ERROR IN TEST CASE ===\n{}", name);
            eprintln!(
                "=== EXPECTED STDOUT ===\n{}\n=== GOT STDOUT ===\n{}",
                expected_trimmed, actual_trimmed
            );
            eprintln!("=== END ERROR ===\n");
            return false;
        }
    }

    true
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
    let mut all_passed = true;
    let cases = test_cases();
    println!("\trunning {} test cases", cases.len());
    for case in cases {
        let result = run_test_case(&case);
        let msg = if result { "ok" } else { "fail" };
        println!("\tcase {case} ... {msg}");
        all_passed &= result;
    }
    assert!(all_passed, "Some test cases failed");
}
