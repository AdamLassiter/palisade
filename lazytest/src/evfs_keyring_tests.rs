use sqlevfs::{crypto::keys::KeyScope, keyring::Keyring};

use crate::helpers::{TestDir, TestRunner, make_provider};

pub(crate) fn run_evfs_keyring_tests(t: &mut TestRunner) {
    t.section("EVFS Keyring - Scope Resolution");

    let tmp = TestDir::new("evfs-keyring-");
    let kf = tmp.write_keyfile("keyring.key", [0x99; 32]);
    let provider = make_provider(&kf);
    let keyring = Keyring::new(provider);

    let dek1 = match keyring.dek_for(&KeyScope::Database) {
        Ok(d) => {
            t.ok("dek_for(Database) first call");
            d
        }
        Err(e) => {
            t.fail("dek_for(Database)", &e);
            return;
        }
    };

    match keyring.dek_for(&KeyScope::Database) {
        Ok(dek1b) => {
            if dek1b.as_bytes() == dek1.as_bytes() {
                t.ok("dek_for(Database) returns cached key");
            } else {
                t.fail("dek cache", &"second call returned different key");
            }
        }
        Err(e) => t.fail("dek_for(Database) second call", &e),
    }

    match keyring.dek_for(&KeyScope::Table("users".into())) {
        Ok(dek_users) => {
            if dek_users.as_bytes() != dek1.as_bytes() {
                t.ok("Table('users') DEK differs from Database DEK");
            } else {
                t.fail("table scope", &"table DEK same as database DEK");
            }
        }
        Err(e) => t.fail("dek_for(Table('users'))", &e),
    }

    match keyring.dek_for(&KeyScope::Column {
        table: "users".into(),
        column: "ssn".into(),
    }) {
        Ok(dek_col) => {
            if dek_col.as_bytes() != dek1.as_bytes() {
                t.ok("Column('users.ssn') DEK differs from Database DEK");
            } else {
                t.fail("column scope", &"column DEK same as database DEK");
            }
        }
        Err(e) => t.fail("dek_for(Column)", &e),
    }

    t.section("EVFS Keyring - Sidecar Persistence");

    let fake_db = tmp.path("persist-test.db");
    std::fs::write(&fake_db, b"fake").unwrap();
    keyring.set_sidecar_path(&fake_db);

    let _ = keyring.dek_for(&KeyScope::Database).unwrap();

    let sidecar = fake_db.with_extension("evfs-keyring");
    if sidecar.exists() {
        t.ok("sidecar file created");
        let contents = std::fs::read_to_string(&sidecar).unwrap();
        if contents.contains("database") {
            t.ok("sidecar contains 'database' scope entry");
        } else {
            t.fail("sidecar contents", &"missing 'database' key");
        }
    } else {
        t.fail("sidecar", &"file not created");
    }

    t.section("EVFS Keyring - Rewrap All");

    match keyring.rewrap_all() {
        Ok(()) => t.ok("rewrap_all succeeded"),
        Err(e) => t.fail("rewrap_all", &e),
    }
}
