use std::path::PathBuf;

pub(crate) struct TestDir {
    dir: tempfile::TempDir,
}

impl TestDir {
    pub(crate) fn new(prefix: &str) -> Self {
        Self {
            dir: tempfile::Builder::new()
                .prefix(prefix)
                .tempdir()
                .expect("failed to create temp dir"),
        }
    }

    pub(crate) fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Write a 32-byte keyfile and return its path.
    pub(crate) fn write_keyfile(&self, name: &str, key: [u8; 32]) -> PathBuf {
        let p = self.path(name);
        std::fs::write(&p, key).expect("failed to write keyfile");
        p
    }
}

/// Counts passed / failed and prints a summary.
pub(crate) struct TestRunner {
    pub(crate) passed: u32,
    pub(crate) failed: u32,
    section: String,
}

impl TestRunner {
    pub(crate) fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
            section: String::new(),
        }
    }

    pub(crate) fn section(&mut self, name: &str) {
        self.section = name.to_string();
        println!("\n--- {name} ---");
    }

    pub(crate) fn ok(&mut self, msg: &str) {
        self.passed += 1;
        println!("  ✓ {msg}");
    }

    pub(crate) fn fail(&mut self, msg: &str, err: &dyn std::fmt::Display) {
        self.failed += 1;
        eprintln!("  ✗ {msg}: {err}");
    }

    pub(crate) fn assert_eq<T: PartialEq + std::fmt::Debug>(
        &mut self,
        label: &str,
        got: &T,
        expected: &T,
    ) {
        if got == expected {
            self.ok(label);
        } else {
            self.failed += 1;
            eprintln!("  ✗ {label}: expected {expected:?}, got {got:?}");
        }
    }

    pub(crate) fn summary(&self) {
        println!("\n========================================");
        println!(
            "  {} passed, {} failed, {} total",
            self.passed,
            self.failed,
            self.passed + self.failed,
        );
        if self.failed > 0 {
            println!("  SOME TESTS FAILED");
        } else {
            println!("  ALL TESTS PASSED");
        }
        println!("========================================");
    }
}

// pub(crate) fn make_provider(keyfile: &Path) -> Arc<dyn KmsProvider> {
//     Arc::new(DeviceKeyProvider::from_keyfile(keyfile.to_path_buf()))
// }
