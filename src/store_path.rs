use crate::{
  hash::{HashAlgorithm, compress_hash, hash_string},
  nix32::Nix32,
};

/// The number of nix32 characters in a store path hash (160 bits = 20 bytes).
pub const STORE_PATH_HASH_LEN: usize = 32;

/// The `.drv` file extension.
pub const DRV_EXTENSION: &str = ".drv";

/// The default Nix store directory.
pub const DEFAULT_STORE_DIR: &str = "/nix/store";

/// Validate a store path name component.
///
/// Valid characters: `[0-9a-zA-Z+-._?=]`. The first dash-separated component
/// must not be `.` or `..`. Max length is 211 characters.
pub fn check_name(name: &str) -> Result<(), String> {
  if name.is_empty() {
    return Err("name must not be empty".into());
  }
  if name.len() > 211 {
    return Err(format!(
      "name '{name}' must be no longer than 211 characters"
    ));
  }
  if name.starts_with('.')
    && (name.len() == 1
      || name == ".."
      || name.starts_with(".-")
      || name.starts_with("..-"))
  {
    return Err(format!("name '{name}' is not valid"));
  }
  for c in name.chars() {
    if !(c.is_ascii_alphanumeric()
      || matches!(c, '+' | '-' | '.' | '_' | '?' | '='))
    {
      return Err(format!("name '{name}' contains illegal character '{c}'"));
    }
  }
  Ok(())
}

/// Compute the output path name from a derivation name and output name.
///
/// If the output name is `"out"`, the result is just the derivation name.
/// Otherwise it's `<drv-name>-<output-name>`.
#[must_use]
pub fn output_path_name(drv_name: &str, output_name: &str) -> String {
  if output_name == "out" {
    drv_name.to_owned()
  } else {
    format!("{drv_name}-{output_name}")
  }
}

/// How a file is ingested into the Nix store for content-addressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileIngestionMethod {
  /// The file is stored as-is (flat file).
  Flat,
  /// The file/directory is serialised as a Nix Archive (NAR).
  NixArchive,
}

impl FileIngestionMethod {
  /// The prefix used in the fixed-output payload (e.g. `"r:"` for NAR).
  fn prefix(self) -> &'static str {
    match self {
      Self::Flat => "",
      Self::NixArchive => "r:",
    }
  }
}

/// Configuration for computing store path hashes.
///
/// Typically constructed with the default store directory `"/nix/store"`.
#[derive(Debug, Clone)]
pub struct StoreDir {
  /// The store directory path (e.g. `"/nix/store"`).
  pub store_dir: String,
}

impl Default for StoreDir {
  fn default() -> Self {
    Self {
      store_dir: DEFAULT_STORE_DIR.to_owned(),
    }
  }
}

impl StoreDir {
  /// Create a new `StoreDir` with the given store directory.
  #[must_use]
  pub fn new(store_dir: &str) -> Self {
    Self {
      store_dir: store_dir.to_owned(),
    }
  }

  /// Compute a store path from a type string, a hash string, and a name.
  ///
  /// This is the core function from the Nix PhD thesis:
  ///
  /// 1. Construct the string `type:hash:storeDir:name`
  /// 2. SHA-256 hash it
  /// 3. Compress the 32-byte hash to 20 bytes via cyclic XOR
  /// 4. Encode the 20 bytes in nix32
  /// 5. Return `<nix32>-<name>`
  #[must_use]
  pub fn make_store_path(
    &self,
    ty: &str,
    hash_str: &str,
    name: &str,
  ) -> String {
    let input = format!(
      "{ty}:{hash_str}:{store_dir}:{name}",
      store_dir = self.store_dir
    );
    let sha = hash_string(HashAlgorithm::Sha256, &input);
    let compressed = compress_hash(&sha, 20);
    let nix32_hash = Nix32::encode(&compressed);
    format!("{nix32_hash}-{name}")
  }

  /// Compute a store path from a type string, raw hash bytes, and a name.
  ///
  /// Like [`make_store_path`](Self::make_store_path) but auto-formats the
  /// hash as `"sha256:<base16>"`.
  #[must_use]
  pub fn make_store_path_from_hash(
    &self,
    ty: &str,
    hash: &[u8],
    name: &str,
  ) -> String {
    let hash_str = format!("sha256:{}", hex_str(hash));
    self.make_store_path(ty, &hash_str, name)
  }

  /// Compute an output path for a derivation output.
  #[must_use]
  pub fn make_output_path(
    &self,
    output_name: &str,
    drv_hash: &[u8],
    drv_name: &str,
  ) -> String {
    let ty = format!("output:{output_name}");
    let name = output_path_name(drv_name, output_name);
    self.make_store_path_from_hash(&ty, drv_hash, &name)
  }

  /// Compute a fixed-output path from a content-addressing method and
  /// content hash.
  ///
  /// For NAR + SHA-256 this uses the `"source"` type, including references.
  /// For other methods, a unique digest is computed via
  /// `make_store_path("output:out", digest, name)`.
  #[must_use]
  pub fn make_fixed_output_path(
    &self,
    name: &str,
    method: FileIngestionMethod,
    hash: &[u8],
    references: &[String],
  ) -> String {
    let hash_str = format!("sha256:{}", hex_str(hash));

    if method == FileIngestionMethod::NixArchive {
      let mut ty = String::from("source");
      for r in references {
        ty.push(':');
        ty.push_str(r);
      }
      self.make_store_path(&ty, &hash_str, name)
    } else {
      let payload = format!("fixed:out:{}{hash_str}:", method.prefix());
      let digest = hash_string(HashAlgorithm::Sha256, &payload);
      self.make_store_path_from_hash("output:out", &digest, name)
    }
  }

  /// Compute the store path for a derivation `.drv` file.
  ///
  /// The derivation is content-addressed via text hashing: SHA-256 of
  /// the derivation ATerm content.
  #[must_use]
  pub fn make_text_path(
    &self,
    suffix: &str,
    content_hash: &[u8],
    references: &[String],
  ) -> String {
    let hash_str = format!("sha256:{}", hex_str(content_hash));
    let mut ty = String::from("text");
    for r in references {
      ty.push(':');
      ty.push_str(r);
    }
    self.make_store_path(&ty, &hash_str, suffix)
  }

  /// Check whether a store path name is a derivation.
  #[must_use]
  pub fn is_derivation(name: &str) -> bool {
    name.ends_with(DRV_EXTENSION)
  }

  /// Parse a store path back into its (hash_part, name) components.
  ///
  /// Returns `None` if the path is not a valid store path.
  pub fn parse_store_path(path: &str) -> Option<(&str, &str)> {
    let base = path.rsplit('/').next()?;
    let (hash_part, name) = base.split_once('-')?;
    if hash_part.len() != STORE_PATH_HASH_LEN {
      return None;
    }
    for c in hash_part.chars() {
      Nix32::lookup(c)?;
    }
    check_name(name).ok()?;
    Some((hash_part, name))
  }
}

fn hex_str(data: &[u8]) -> String {
  data.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn check_name_accepts_valid() {
    assert!(check_name("foo").is_ok());
    assert!(check_name("foo-1.0").is_ok());
    assert!(check_name("hello+world").is_ok());
    assert!(check_name("x86_64-linux").is_ok());
    assert!(check_name("foo?bar=baz").is_ok());
  }

  #[test]
  fn check_name_rejects_reserved() {
    assert!(check_name("").is_err());
    assert!(check_name(".").is_err());
    assert!(check_name("..").is_err());
    assert!(check_name(".-foo").is_err());
    assert!(check_name("..-foo").is_err());
    assert!(check_name("foo bar").is_err());
    assert!(check_name("foo/bar").is_err());
  }

  #[test]
  fn output_path_name_for_out() {
    assert_eq!(output_path_name("hello", "out"), "hello");
    assert_eq!(output_path_name("hello", "dev"), "hello-dev");
  }

  #[test]
  fn store_path_contains_name() {
    let sd = StoreDir::default();
    let path = sd.make_store_path("output:out", "sha256:deadbeef", "hello");
    let (hash_part, name) = path.split_once('-').expect("should have dash");
    assert_eq!(hash_part.len(), 32);
    assert_eq!(name, "hello");
  }

  #[test]
  fn store_path_hash_is_valid_nix32() {
    let sd = StoreDir::default();
    let path = sd.make_store_path("output:out", "sha256:abc123", "foo-1.0");
    let (hash_part, _) = path.split_once('-').unwrap();
    for c in hash_part.chars() {
      assert!(
        Nix32::lookup(c).is_some(),
        "char '{c}' in '{hash_part}' should be valid nix32"
      );
    }
  }

  #[test]
  fn deterministic_output() {
    let sd = StoreDir::default();
    let a = sd.make_store_path("output:out", "sha256:abc", "foo");
    let b = sd.make_store_path("output:out", "sha256:abc", "foo");
    assert_eq!(a, b);
  }

  #[test]
  fn different_inputs_different_paths() {
    let sd = StoreDir::default();
    let a = sd.make_store_path("output:out", "sha256:abc", "foo");
    let b = sd.make_store_path("output:out", "sha256:abd", "foo");
    assert_ne!(a, b);
  }

  #[test]
  fn different_store_dirs_different_paths() {
    let a = StoreDir::new("/nix/store").make_store_path(
      "output:out",
      "sha256:abc",
      "foo",
    );
    let b = StoreDir::new("/gnu/store").make_store_path(
      "output:out",
      "sha256:abc",
      "foo",
    );
    assert_ne!(a, b);
  }

  #[test]
  fn parse_valid_store_path() {
    let path = "r7r1sd2lq3n2lb72vf1aaq3syy0kj9bq-hello-2.12.1";
    let (hp, name) =
      StoreDir::parse_store_path(path).expect("valid store path");
    assert_eq!(hp.len(), 32);
    assert_eq!(name, "hello-2.12.1");
  }

  #[test]
  fn parse_rejects_bad_hash() {
    assert!(
      StoreDir::parse_store_path("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-x")
        .is_none()
    );
    assert!(StoreDir::parse_store_path("short-x").is_none());
  }

  #[test]
  fn derivation_detection() {
    assert!(StoreDir::is_derivation("foo.drv"));
    assert!(!StoreDir::is_derivation("foo"));
  }

  #[test]
  fn known_derivation_path_produces_valid_output() {
    let sd = StoreDir::default();
    let drv_aterm = "Derive([(\"out\",\"/nix/store/\
                     d3dyc8y0vkqh4khsliq89zw6c5g0nqwz-test\",\"\",\"\")],[],[\\
                     "/bin/sh\"],\"x86_64-linux\",\"\",[]]";
    let content_hash =
      crate::hash::hash_string(HashAlgorithm::Sha256, drv_aterm);
    let suffix = "test.drv";
    let path = sd.make_text_path(suffix, &content_hash, &[]);
    let (hp, name) = path.split_once('-').unwrap();
    assert_eq!(hp.len(), 32);
    assert_eq!(name, suffix);
  }
}
