//! Pure Rust implementation of Nix store path hashing.
//!
//! ## Modules
//!
//! | Module         | Purpose                                                              |
//! | -------------- | -------------------------------------------------------------------- |
//! | [`nix32`]      | Nix's custom base-32 encoding (lowercase alphanumeric minus e,o,u,t) |
//! | [`hash`]       | Hash algorithms (MD5, SHA-1, SHA-256, SHA-512), compression, SRI     |
//! | [`store_path`] | Store path construction via `makeStorePath` and friends              |
//!
//! ## Quickstart
//!
//! ```rust
//! use nix_hash::store_path::StoreDir;
//!
//! let store = StoreDir::default();
//! let path = store.make_store_path("output:out", "sha256:abc123", "hello-1.0");
//! assert!(path.ends_with("-hello-1.0"));
//! ```
pub mod hash;
pub mod nix32;
pub mod store_path;

// Re-export the most commonly used items at the crate root for convenience.
pub use hash::{
    compress_hash, hash_bytes, hash_sha256, hash_string, parse_sri, to_sri, HashAlgorithm,
};
pub use nix32::Nix32;
pub use store_path::{check_name, output_path_name, FileIngestionMethod, StoreDir};
