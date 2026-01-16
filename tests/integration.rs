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
fn run_test_case(name: String) -> bool {
    let case_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cases");
    let expected_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/expected");

    let sql_path = case_dir.join(format!("{name}.sql"));
    assert!(
        sql_path.exists(),
        "missing testcase file: {}",
        sql_path.display()
    );

    let expected_path = expected_dir.join(format!("{name}.out"));
    assert!(
        expected_path.exists(),
        "missing expected output: {}",
        expected_path.display()
    );

    let lib_path = extension_path();
    assert!(
        lib_path.exists(),
        "extension not built: {}",
        lib_path.display()
    );

    let expected_output =
        fs::read_to_string(&expected_path).expect("could not read expected output file");
    let sql_content = fs::read_to_string(&sql_path).expect("could not read SQL test case file");

    // Prepare the script we'll feed to sqlite3 via stdin
    let script = format!(
        ".load {}\n.headers on\n.mode column\n{}\n",
        lib_path.display(),
        sql_content
    );

    // Spawn sqlite3 and feed commands via stdin
    let mut child = match Command::new("sqlite3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
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

    // Write the commands into sqlite3's stdin
    if let Some(stdin) = &mut child.stdin {
        if let Err(err) = stdin.write_all(script.as_bytes()) {
            eprintln!("Failed to write to sqlite3 stdin: {}", err);
            return false;
        }
    }

    // Capture output
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(err) => {
            eprintln!("Failed to get sqlite3 output: {}", err);
            return false;
        }
    };

    if !output.status.success() {
        eprintln!("stdout:\n{}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr:\n{}", String::from_utf8_lossy(&output.stderr));
        eprintln!("sqlite3 exited with {}", output.status);
        return false;
    }

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let expected_trimmed = expected_output.trim().replace("\r\n", "\n");
    let actual_trimmed = stdout_str.trim().replace("\r\n", "\n");

    if actual_trimmed != expected_trimmed {
        eprintln!("\n=== ERROR IN TEST CASE ===\n{}", name);
        eprintln!(
            "=== EXPECTED ===\n{}\n=== GOT ===\n{}",
            expected_trimmed, actual_trimmed
        );
        eprintln!("=== END ERROR ===\n");
        return false;
    }

    true
}

fn test_cases() -> Vec<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cases");

    let mut names = vec![];
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Some(ext) = entry.path().extension() {
                if ext == "sql" {
                    if let Some(stem) = entry.path().file_stem() {
                        names.push(stem.to_string_lossy().to_string());
                    }
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
    for case in test_cases() {
        all_passed &= run_test_case(case);
    }
    assert!(all_passed, "Some test cases failed");
}
