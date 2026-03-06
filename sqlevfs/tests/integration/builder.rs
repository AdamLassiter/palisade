use std::fs;

use sqlevfs::{EvfsBuilder, Mode};
use tempfile::TempDir;

#[test_log::test]
fn test_builder_device_key_with_keyfile() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let keyfile = temp_dir.path().join("test.key");
    fs::write(&keyfile, vec![0xAA; 32])?;

    let mode = Mode::DeviceKey {
        keyfile: Some(keyfile),
        passphrase: None,
    };

    let builder = EvfsBuilder::new(mode);
    assert_eq!(builder.name, "evfs");
    assert_eq!(builder.page_size, 4096);
    assert_eq!(builder.reserve_size, 48);

    Ok(())
}

#[test_log::test]
fn test_builder_device_key_with_passphrase() {
    let mode = Mode::DeviceKey {
        keyfile: None,
        passphrase: Some("test_password".to_string()),
    };

    let builder = EvfsBuilder::new(mode);
    assert_eq!(builder.page_size, 4096);
}

#[test_log::test]
#[should_panic(expected = "DeviceKey mode requires keyfile or passphrase")]
fn test_builder_device_key_no_source_panics() {
    let mode = Mode::DeviceKey {
        keyfile: None,
        passphrase: None,
    };

    let _builder = EvfsBuilder::new(mode);
}

#[test_log::test]
fn test_builder_tenant_key() {
    let mode = Mode::TenantKey {
        key_id: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
            .to_string(),
        endpoint: Some("https://kms.us-east-1.amazonaws.com".to_string()),
    };

    let builder = EvfsBuilder::new(mode);
    assert_eq!(builder.page_size, 4096);
}

#[test_log::test]
fn test_builder_chaining() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let keyfile = temp_dir.path().join("test.key");
    fs::write(&keyfile, vec![0xBB; 32])?;

    let mode = Mode::DeviceKey {
        keyfile: Some(keyfile),
        passphrase: None,
    };

    let builder = EvfsBuilder::new(mode)
        .page_size(8192)
        .reserve_size(64)
        .vfs_name("custom_evfs");

    assert_eq!(builder.name, "custom_evfs");
    assert_eq!(builder.page_size, 8192);
    assert_eq!(builder.reserve_size, 64);

    Ok(())
}
