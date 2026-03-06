use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use sqlevfs::kms::{KmsProvider, local::DeviceKeyProvider};
use tempfile::TempDir;
use tokio::time::{sleep, timeout};

pub fn test_db_path(dir: &TempDir, name: &str) -> PathBuf {
    dir.path().join(name)
}

pub fn make_provider(keyfile: &Path) -> Arc<dyn KmsProvider> {
    Arc::new(DeviceKeyProvider::from_keyfile(keyfile.to_path_buf()))
}

pub async fn wait_until(
    within: Duration,
    mut predicate: impl FnMut() -> bool,
) -> anyhow::Result<()> {
    timeout(within, async {
        loop {
            if predicate() {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("timed out after {within:?}"))?;
    Ok(())
}

pub fn sqlite_api_is_available() -> bool {
    std::panic::catch_unwind(|| unsafe {
        libsqlite3_sys::sqlite3_libversion_number();
    })
    .is_ok()
}
