use std::fmt;

/// Hash algorithms supported by Nix.
///
/// Corresponds to `nix::HashAlgorithm` in the C++ implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
  Md5,
  Sha1,
  Sha256,
  Sha512,
  Blake3,
}

impl HashAlgorithm {
  /// The size of the hash output in bytes.
  #[must_use]
  pub const fn hash_size(self) -> usize {
    match self {
      Self::Md5 => 16,
      Self::Sha1 => 20,
      Self::Sha256 => 32,
      Self::Sha512 => 64,
      Self::Blake3 => 32,
    }
  }

  /// The SRI prefix string (e.g. `"sha256"`).
  #[must_use]
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Md5 => "md5",
      Self::Sha1 => "sha1",
      Self::Sha256 => "sha256",
      Self::Sha512 => "sha512",
      Self::Blake3 => "blake3",
    }
  }

  /// Parse from an SRI algorithm name. Returns `None` if unrecognised.
  #[must_use]
  pub fn parse(s: &str) -> Option<Self> {
    match s {
      "md5" => Some(Self::Md5),
      "sha1" => Some(Self::Sha1),
      "sha256" => Some(Self::Sha256),
      "sha512" => Some(Self::Sha512),
      "blake3" => Some(Self::Blake3),
      _ => None,
    }
  }
}

impl fmt::Display for HashAlgorithm {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(self.as_str())
  }
}

/// Hash a byte slice with the given algorithm, returning raw bytes.
pub fn hash_bytes(algo: HashAlgorithm, data: &[u8]) -> Vec<u8> {
  match algo {
    HashAlgorithm::Md5 => {
      use md5::Digest;
      md5::Md5::digest(data).to_vec()
    },
    HashAlgorithm::Sha1 => {
      use sha1::Digest;
      sha1::Sha1::digest(data).to_vec()
    },
    HashAlgorithm::Sha256 => {
      use sha2::Digest;
      sha2::Sha256::digest(data).to_vec()
    },
    HashAlgorithm::Sha512 => {
      use sha2::Digest;
      sha2::Sha512::digest(data).to_vec()
    },
    HashAlgorithm::Blake3 => blake3::hash(data).as_bytes().to_vec(),
  }
}

/// Hash a string with the given algorithm, returning raw bytes.
pub fn hash_string(algo: HashAlgorithm, data: &str) -> Vec<u8> {
  hash_bytes(algo, data.as_bytes())
}

/// Hash a byte slice with SHA-256 (the most common algorithm in Nix).
///
/// Convenience wrapper around [`hash_bytes`]`(`[`HashAlgorithm::Sha256`]`,
/// data)`.
pub fn hash_sha256(data: &[u8]) -> Vec<u8> {
  hash_bytes(HashAlgorithm::Sha256, data)
}

/// Compress a hash to `new_size` bytes by cyclically XORing bytes together.
///
/// Nix uses this to compress a 32-byte SHA-256 hash to 20 bytes for the
/// hash part of a store path.
pub fn compress_hash(hash: &[u8], new_size: usize) -> Vec<u8> {
  let mut out = vec![0u8; new_size];
  for (i, byte) in hash.iter().enumerate() {
    out[i % new_size] ^= byte;
  }
  out
}

/// Format a hash as a Subresource Integrity string: `algo-base64`.
///
/// This is the W3C SRI format used by `nix hash to-sri`.
pub fn to_sri(algo: HashAlgorithm, hash: &[u8]) -> String {
  use base64::Engine;
  let b64 = base64::engine::general_purpose::STANDARD.encode(hash);
  format!("{algo}-{b64}")
}

/// Parse an SRI string into an (algorithm, hash bytes) pair.
///
/// Accepts strings like
/// `"sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="`. Returns `None` if
/// the format or algorithm is invalid.
pub fn parse_sri(s: &str) -> Option<(HashAlgorithm, Vec<u8>)> {
  use base64::Engine;

  let (algo_str, b64) = s.split_once('-')?;
  let algo = HashAlgorithm::parse(algo_str)?;
  let hash = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
  Some((algo, hash))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn hash_sizes() {
    assert_eq!(HashAlgorithm::Md5.hash_size(), 16);
    assert_eq!(HashAlgorithm::Sha1.hash_size(), 20);
    assert_eq!(HashAlgorithm::Sha256.hash_size(), 32);
    assert_eq!(HashAlgorithm::Sha512.hash_size(), 64);
    assert_eq!(HashAlgorithm::Blake3.hash_size(), 32);
  }

  #[test]
  fn hash_string_is_deterministic() {
    let a = hash_string(HashAlgorithm::Sha256, "hello");
    let b = hash_string(HashAlgorithm::Sha256, "hello");
    assert_eq!(a, b);
    assert_eq!(a.len(), 32);
  }

  #[test]
  fn hash_algorithms_produce_different_output() {
    let input = b"test";
    let md5 = hash_bytes(HashAlgorithm::Md5, input);
    let sha1 = hash_bytes(HashAlgorithm::Sha1, input);
    let sha256 = hash_bytes(HashAlgorithm::Sha256, input);
    let sha512 = hash_bytes(HashAlgorithm::Sha512, input);

    assert_eq!(md5.len(), 16);
    assert_eq!(sha1.len(), 20);
    assert_eq!(sha256.len(), 32);
    assert_eq!(sha512.len(), 64);

    // All should differ from each other
    assert_ne!(md5, sha1);
    assert_ne!(sha1, sha256);
    assert_ne!(sha256, sha512);
  }

  #[test]
  fn compress_hash_256_to_160() {
    let hash: Vec<u8> = (0..32).collect();
    let compressed = compress_hash(&hash, 20);
    assert_eq!(compressed.len(), 20);
    // Byte 0 = hash[0] ^ hash[20] = 0 ^ 20
    assert_eq!(compressed[0], 20);
    assert_eq!(compressed[1], 1 ^ 21);
  }

  #[test]
  fn sri_roundtrip() {
    let hash: Vec<u8> = (0..32).collect();
    let sri = to_sri(HashAlgorithm::Sha256, &hash);
    assert!(sri.starts_with("sha256-"));
    let (algo, decoded) = parse_sri(&sri).unwrap();
    assert_eq!(algo, HashAlgorithm::Sha256);
    assert_eq!(decoded, hash);
  }

  #[test]
  fn sri_rejects_invalid() {
    assert!(parse_sri("not-sri").is_none());
    assert!(parse_sri("sha256-not-base64!!!").is_none());
    assert!(parse_sri("unknown-aGVsbG8=").is_none());
  }

  #[test]
  fn sri_matches_nix_cli() {
    // SHA-256 of "hello", verified against `nix hash to-sri --type sha256`
    let bytes = hex::decode(
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    )
    .unwrap();
    let sri = to_sri(HashAlgorithm::Sha256, &bytes);
    assert_eq!(sri, "sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=");
  }
}
