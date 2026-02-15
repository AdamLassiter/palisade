use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 256-bit data encryption key. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct Dek {
    bytes: [u8; 32],
}

/// A wrapped (ciphertext) DEK - safe to persist to disk.
#[derive(Clone, Debug, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub struct WrappedDek {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    /// Identifies which KEK wrapped this DEK.
    pub kek_id: KekId,
}

/// Opaque KEK identifier.
#[derive(Clone, Debug, Hash, Eq, PartialEq, bincode::Encode, bincode::Decode)]
pub struct KekId(pub String);

/// Which scope a DEK protects.
#[derive(Clone, Debug, Hash, Eq, PartialEq, bincode::Encode, bincode::Decode)]
pub enum KeyScope {
    /// Whole database.
    Database,
    /// Single table (by name).
    Table(String),
    /// Single column.
    Column { table: String, column: String },
}

impl Dek {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("getrandom failed");
        Self { bytes }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl fmt::Debug for Dek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Dek(***)")
    }
}

impl fmt::Display for KeyScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyScope::Database => write!(f, "database"),
            KeyScope::Table(t) => write!(f, "table:{t}"),
            KeyScope::Column { table, column } => {
                write!(f, "column:{table}.{column}")
            }
        }
    }
}
