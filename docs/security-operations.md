# Security Operations

## Key Generations And Rotation

EVFS stores wrapped DEKs per key scope in the keyring sidecar. New writes use the
currently loaded DEK for the database scope. Existing pages remain readable as
long as the keyring contains the wrapping metadata needed to unwrap the DEK with
the configured KEK.

Backup KEK rotation is implemented by `sqlevfs::backup::rotate_backup_kek`: it
unwraps the backup DEK with the old KEK and re-wraps the same backup DEK under
the new KEK without rewriting backup page ciphertext.

Operational rotation steps:

1. Validate the database with `loadtest`/`chaostest` or the doctor checklist.
2. Create and verify an encrypted backup.
3. Rotate backup KEK metadata or create a new database/keyring and restore into
   it for data-at-rest DEK replacement.
4. Re-run visibility, audit, encryption leakage, and logical invariant checks.
5. Retain old key material only for the recovery window required by policy.

Audit records must describe rotation events by operation, actor/context, target,
and generation identifiers only. They must never contain raw KEK/DEK material or
wrapped key bytes.

## Tamper-Evident Audit Chain

Canonical audit-row serialization is stable JSON with sorted keys and explicit
field names:

```json
{
  "audit_id": 1,
  "logical_table": "orders",
  "operation": "UPDATE",
  "outcome": "success",
  "row_pk_json": "{\"id\":7}",
  "changed_columns_json": "[\"status\"]",
  "context_json": "{\"role\":[\"admin\"]}",
  "row_label_id": 2,
  "error": null,
  "created_at": "sqlite-current-timestamp"
}
```

The chain model stores `previous_hash`, `event_hash`, and chain-head metadata.
Verification recomputes each event hash from canonical row content and verifies
that every row points at the previous row's hash. Deletes, reorders, and updates
are detected as long as the verifier has a trusted chain head or external anchor.
Without external anchoring, a database owner who can rewrite the entire table can
replace both data and chain metadata.

## Backup And Restore

Backup files begin with `EVFSBKUP`, a bincode header, and encrypted page payloads.
The header includes version, page size, page count, reserve size, and a wrapped
backup DEK. Restores validate the header, unwrap the backup DEK, decrypt every
page, re-encrypt with the target keyring DEK, and write the restored database.

Safety notes:

- Run a SQLite checkpoint or stop writers before backup when using live DBs.
- Verify backups with the intended KEK before deleting source artifacts.
- Wrong keys and corrupted backup pages fail authentication.
- Cluster restores should restore database content and then re-create or validate
  Raft state before exposing the node.
