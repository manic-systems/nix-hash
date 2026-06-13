# nix-hash

Pure Rust implementation of the hashing algorithms used by the Nix package
manager. Based on Eelco Dolstra's PhD thesis _The Purely Functional Software
Deployment Model_ (2006) and the Nix C++ reference implementation. Can do
**Nix32 encoding and decoding** using Nix's custom base-32 alphabet (digits +
lowercase letters minus e, o, u, t) and provides various hash functions such as
MD5, SHA-1, SHA-256, SHA-512 via the `hash` module. Hash compression is also
possible, you may compress a 32-byte SHA-256 hash to 20 bytes via cyclic XOR.
This is used for store path hashes.

Other features:

- **SRI formatting** - `algo-base64` (W3C Subresource Integrity, used by
  `nix hash to-sri`)
- **Store path construction** - `makeStorePath`, `makeOutputPath`,
  `makeFixedOutputPath` as described in the thesis

## Usage

```rust
use nix_hash::store_path::StoreDir;
use nix_hash::nix32::Nix32;
use nix_hash::hash::{hash_string, to_sri, HashAlgorithm};

// Compute a store path
let store = StoreDir::default(); // /nix/store
let path = store.make_store_path("output:out", "sha256:abc123", "hello-1.0");
assert!(path.ends_with("-hello-1.0"));

// Format a hash as SRI
let hash = hash_string(HashAlgorithm::Sha256, "hello");
let sri = to_sri(HashAlgorithm::Sha256, &hash);
assert_eq!(sri, "sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=");
```
