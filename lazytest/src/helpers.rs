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

pub(crate) type TestRunner = palisade_log::TestLogger;

// pub(crate) fn make_provider(keyfile: &Path) -> Arc<dyn KmsProvider> {
//     Arc::new(DeviceKeyProvider::from_keyfile(keyfile.to_path_buf()))
// }
