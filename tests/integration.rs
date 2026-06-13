use nix_hash::{
  FileIngestionMethod,
  HashAlgorithm,
  Nix32,
  StoreDir,
  check_name,
  compress_hash,
  hash_bytes,
  hash_sha256,
  hash_string,
  output_path_name,
  parse_sri,
  to_sri,
};

#[test]
fn algorithm_hash_sizes() {
  assert_eq!(HashAlgorithm::Md5.hash_size(), 16);
  assert_eq!(HashAlgorithm::Sha1.hash_size(), 20);
  assert_eq!(HashAlgorithm::Sha256.hash_size(), 32);
  assert_eq!(HashAlgorithm::Sha512.hash_size(), 64);
  assert_eq!(HashAlgorithm::Blake3.hash_size(), 32);
}

#[test]
fn algorithm_as_str_and_display() {
  for (algo, s) in [
    (HashAlgorithm::Md5, "md5"),
    (HashAlgorithm::Sha1, "sha1"),
    (HashAlgorithm::Sha256, "sha256"),
    (HashAlgorithm::Sha512, "sha512"),
    (HashAlgorithm::Blake3, "blake3"),
  ] {
    assert_eq!(algo.as_str(), s);
    assert_eq!(algo.to_string(), s);
  }
}

#[test]
fn algorithm_parse_valid() {
  for s in ["md5", "sha1", "sha256", "sha512", "blake3"] {
    let algo = HashAlgorithm::parse(s).expect(s);
    assert_eq!(algo.as_str(), s);
  }
}

#[test]
fn algorithm_parse_invalid() {
  assert!(HashAlgorithm::parse("").is_none());
  assert!(HashAlgorithm::parse("SHA256").is_none());
  assert!(HashAlgorithm::parse("md4").is_none());
  assert!(HashAlgorithm::parse("unknown").is_none());
}

#[test]
fn algorithm_debug_and_eq() {
  let a = HashAlgorithm::Sha256;
  let b = HashAlgorithm::Sha256;
  assert_eq!(a, b);
  let _ = format!("{a:?}");
  let c = a;
  assert_eq!(a, c);
}

#[test]
fn hash_bytes_output_length_matches_algo() {
  for algo in [
    HashAlgorithm::Md5,
    HashAlgorithm::Sha1,
    HashAlgorithm::Sha256,
    HashAlgorithm::Sha512,
    HashAlgorithm::Blake3,
  ] {
    let h = hash_bytes(algo, b"test");
    assert_eq!(h.len(), algo.hash_size());
  }
}

#[test]
fn hash_bytes_deterministic() {
  for algo in [
    HashAlgorithm::Md5,
    HashAlgorithm::Sha1,
    HashAlgorithm::Sha256,
    HashAlgorithm::Sha512,
    HashAlgorithm::Blake3,
  ] {
    let a = hash_bytes(algo, b"some data");
    let b = hash_bytes(algo, b"some data");
    assert_eq!(a, b, "algo {algo} not deterministic");
  }
}

#[test]
fn hash_bytes_different_inputs_different_output() {
  for algo in [
    HashAlgorithm::Md5,
    HashAlgorithm::Sha1,
    HashAlgorithm::Sha256,
    HashAlgorithm::Sha512,
    HashAlgorithm::Blake3,
  ] {
    let a = hash_bytes(algo, b"a");
    let b = hash_bytes(algo, b"b");
    assert_ne!(a, b, "algo {algo} should produce different output");
  }
}

#[test]
fn hash_string_equals_hash_bytes() {
  assert_eq!(
    hash_string(HashAlgorithm::Sha256, "hello"),
    hash_bytes(HashAlgorithm::Sha256, b"hello")
  );
  assert_eq!(
    hash_string(HashAlgorithm::Md5, "world"),
    hash_bytes(HashAlgorithm::Md5, b"world")
  );
}

#[test]
fn hash_sha256_equals_hash_bytes_sha256() {
  assert_eq!(
    hash_sha256(b"convenience"),
    hash_bytes(HashAlgorithm::Sha256, b"convenience")
  );
}

#[test]
fn hash_empty_input_all_algos() {
  for algo in [
    HashAlgorithm::Md5,
    HashAlgorithm::Sha1,
    HashAlgorithm::Sha256,
    HashAlgorithm::Sha512,
    HashAlgorithm::Blake3,
  ] {
    let h = hash_bytes(algo, b"");
    assert_eq!(h.len(), algo.hash_size());
  }
}

#[test]
fn hash_large_input_all_algos() {
  let meg = vec![0xA5u8; 1_000_000];
  for algo in [
    HashAlgorithm::Md5,
    HashAlgorithm::Sha1,
    HashAlgorithm::Sha256,
    HashAlgorithm::Sha512,
    HashAlgorithm::Blake3,
  ] {
    let h = hash_bytes(algo, &meg);
    assert_eq!(h.len(), algo.hash_size());
  }
}

#[test]
fn kat_md5_empty() {
  let h = hex::encode(hash_bytes(HashAlgorithm::Md5, b""));
  assert_eq!(h, "d41d8cd98f00b204e9800998ecf8427e");
}

#[test]
fn kat_md5_hello() {
  let h = hex::encode(hash_bytes(HashAlgorithm::Md5, b"hello"));
  assert_eq!(h, "5d41402abc4b2a76b9719d911017c592");
}

#[test]
fn kat_sha1_empty() {
  let h = hex::encode(hash_bytes(HashAlgorithm::Sha1, b""));
  assert_eq!(h, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

#[test]
fn kat_sha1_hello() {
  let h = hex::encode(hash_bytes(HashAlgorithm::Sha1, b"hello"));
  assert_eq!(h, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
}

#[test]
fn kat_sha256_empty() {
  let h = hex::encode(hash_bytes(HashAlgorithm::Sha256, b""));
  assert_eq!(
    h,
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  );
}

#[test]
fn kat_sha256_hello() {
  let h = hex::encode(hash_bytes(HashAlgorithm::Sha256, b"hello"));
  assert_eq!(
    h,
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
  );
}

#[test]
fn kat_sha512_empty() {
  let h = hex::encode(hash_bytes(HashAlgorithm::Sha512, b""));
  assert_eq!(
    h,
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
     47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
  );
}

#[test]
fn kat_sha512_hello() {
  let h = hex::encode(hash_bytes(HashAlgorithm::Sha512, b"hello"));
  assert_eq!(
    h,
    "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7\
     2323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"
  );
}

#[test]
fn kat_blake3_empty() {
  let h = hex::encode(hash_bytes(HashAlgorithm::Blake3, b""));
  assert_eq!(
    h,
    "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
  );
}

#[test]
fn kat_blake3_hello() {
  let h = hex::encode(hash_bytes(HashAlgorithm::Blake3, b"hello"));
  assert_eq!(
    h,
    "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f"
  );
}

#[test]
fn compress_32_to_20_bytes() {
  let input: Vec<u8> = (0..32).collect();
  let out = compress_hash(&input, 20);
  assert_eq!(out.len(), 20);
  assert_eq!(out[0], 20);
  assert_eq!(out[1], 1 ^ 21);
  assert_eq!(out[11], 11 ^ 31);
  assert_eq!(out[12], 12);
}

#[test]
fn compress_identity() {
  let input: Vec<u8> = (0..16).collect();
  let out = compress_hash(&input, 16);
  assert_eq!(out, input);
}

#[test]
fn compress_to_larger_than_input() {
  let input = vec![0xABu8; 4];
  let out = compress_hash(&input, 8);
  assert_eq!(out.len(), 8);
  assert_eq!(&out[..4], &[0xAB; 4]);
  assert_eq!(&out[4..], &[0x00; 4]);
}

#[test]
fn compress_empty_to_nonzero() {
  let out = compress_hash(&[], 5);
  assert_eq!(out, vec![0u8; 5]);
}

#[test]
fn compress_to_one_byte() {
  let input: Vec<u8> = (0..10).collect();
  let out = compress_hash(&input, 1);
  let expected: u8 = (0..10u8).fold(0, |a, x| a ^ x);
  assert_eq!(out.len(), 1);
  assert_eq!(out[0], expected);
}

#[test]
fn sri_roundtrip_all_algos() {
  for algo in [
    HashAlgorithm::Md5,
    HashAlgorithm::Sha1,
    HashAlgorithm::Sha256,
    HashAlgorithm::Sha512,
    HashAlgorithm::Blake3,
  ] {
    let hash = vec![0x42u8; algo.hash_size()];
    let sri = to_sri(algo, &hash);
    let (parsed, out) = parse_sri(&sri).expect("roundtrip");
    assert_eq!(parsed, algo);
    assert_eq!(out, hash);
  }
}

#[test]
fn sri_format_has_prefix_dash_b64() {
  let hash = vec![0u8; 32];
  let sri = to_sri(HashAlgorithm::Sha256, &hash);
  assert!(sri.starts_with("sha256-"));
  assert_eq!(sri.len(), 7 + 44);
}

#[test]
fn sri_nix_cli_sha256_hello() {
  let bytes = hex::decode(
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  )
  .unwrap();
  let sri = to_sri(HashAlgorithm::Sha256, &bytes);
  assert_eq!(sri, "sha256-LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=");
}

#[test]
fn sri_rejects_missing_dash() {
  assert!(parse_sri("sha256").is_none());
  assert!(parse_sri("").is_none());
}

#[test]
fn sri_rejects_bad_base64() {
  assert!(parse_sri("sha256-!!!not-base64!!!").is_none());
}

#[test]
fn sri_rejects_unknown_algo() {
  assert!(parse_sri("unknown-aGVsbG8=").is_none());
  assert!(parse_sri("md4-aGVsbG8=").is_none());
}

#[test]
fn sri_empty_hash() {
  let sri = to_sri(HashAlgorithm::Sha256, &[]);
  assert_eq!(sri, "sha256-");
  let (algo, hash) = parse_sri(&sri).unwrap();
  assert_eq!(algo, HashAlgorithm::Sha256);
  assert!(hash.is_empty());
}

#[test]
fn nix32_encode_empty() {
  assert_eq!(Nix32::encode(b""), "");
}

#[test]
fn nix32_decode_empty() {
  assert_eq!(Nix32::decode("").unwrap(), b"");
}

#[test]
fn nix32_encoded_len() {
  assert_eq!(Nix32::encoded_len(0), 0);
  assert_eq!(Nix32::encoded_len(1), 2);
  assert_eq!(Nix32::encoded_len(5), 8);
  assert_eq!(Nix32::encoded_len(20), 32);
  for len in 1..=100 {
    assert_eq!(Nix32::encoded_len(len), (len * 8).div_ceil(5));
  }
}

#[test]
fn nix32_roundtrip_pseudorandom() {
  for len in 0..=64 {
    let data: Vec<u8> = (0..len)
      .map(|i| ((i as u32).wrapping_mul(0x9E37_791B)) as u8)
      .collect();
    let enc = Nix32::encode(&data);
    let dec = Nix32::decode(&enc).expect("decode");
    let expected_len = if enc.is_empty() {
      0
    } else {
      (enc.len() * 5) / 8
    };
    assert_eq!(
      &dec[..expected_len.min(len)],
      &data[..expected_len.min(len)]
    );
  }
}

#[test]
fn nix32_encode_output_only_has_alphabet_chars() {
  for len in [1, 7, 13, 20, 32, 100] {
    let data: Vec<u8> = (0_u32..len as u32)
      .map(|i| i.wrapping_mul(13) as u8)
      .collect();
    for c in Nix32::encode(&data).chars() {
      assert!(Nix32::lookup(c).is_some(), "unexpected char '{c}'");
    }
  }
}

#[test]
fn nix32_lookup_all_valid() {
  for c in "0123456789abcdfghijklmnpqrsvwxyz".chars() {
    assert!(Nix32::lookup(c).is_some());
  }
}

#[test]
fn nix32_lookup_uppercase() {
  for c in "ABCDFGHIJKLMNPQRSVWXYZ".chars() {
    assert!(Nix32::lookup(c).is_some(), "uppercase '{c}' failed");
  }
}

#[test]
fn nix32_rejects_forbidden_chars() {
  for c in ['e', 'o', 'u', 't'] {
    assert!(Nix32::lookup(c).is_none());
  }
}

#[test]
fn nix32_decode_rejects_non_alphabet() {
  assert!(Nix32::decode("e").is_none());
  assert!(Nix32::decode("!").is_none());
  assert!(Nix32::decode(" ").is_none());
  assert!(Nix32::decode("é").is_none());
}

#[test]
fn nix32_decode_case_insensitive() {
  let data = b"nix-hash";
  let lower = Nix32::encode(data);
  let upper = lower.to_ascii_uppercase();
  assert_eq!(
    Nix32::decode(&upper).unwrap(),
    Nix32::decode(&lower).unwrap()
  );
}

#[test]
fn nix32_nix_cli_base32_hello() {
  let bytes = hex::decode(
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  )
  .unwrap();
  let enc = Nix32::encode(&bytes);
  assert_eq!(enc, "094qif9n4cq4fdg459qzbhg1c6wywawwaaivx0k0x8xhbyx4vwic");
  let dec = Nix32::decode(&enc).unwrap();
  assert_eq!(&dec[..bytes.len()], &bytes[..]);
}

#[test]
fn nix32_encode_length_matches_encoded_len() {
  for len in 0..=80 {
    let data = vec![0xA3u8; len];
    let enc = Nix32::encode(&data);
    assert_eq!(enc.len(), Nix32::encoded_len(len));
  }
}

#[test]
fn check_name_accepts() {
  for name in [
    "foo",
    "foo-1.0",
    "hello+world",
    "x86_64-linux",
    "foo?bar=baz",
  ] {
    assert!(check_name(name).is_ok(), "should accept '{name}'");
  }
}

#[test]
fn check_name_rejects() {
  for name in ["", ".", "..", ".-x", "..-x", "a b", "a/b", "a\nb"] {
    let escaped = name.escape_default().to_string();
    assert!(check_name(name).is_err(), "should reject '{escaped}'");
  }
}

#[test]
fn check_name_length_boundary() {
  let ok = "a".repeat(211);
  assert!(check_name(&ok).is_ok());

  let bad = "a".repeat(212);
  assert!(check_name(&bad).is_err());
}

#[test]
fn check_name_rejects_forbidden_first_component() {
  assert!(check_name(".-foo").is_err());
  assert!(check_name("..-foo").is_err());
  assert!(check_name("foo.-bar").is_ok());
}

#[test]
fn output_path_name_defaults_to_drv_name_when_out() {
  assert_eq!(output_path_name("hello-1.0", "out"), "hello-1.0");
}

#[test]
fn output_path_name_appends_output_name() {
  assert_eq!(output_path_name("hello-1.0", "dev"), "hello-1.0-dev");
  assert_eq!(output_path_name("hello-1.0", "doc"), "hello-1.0-doc");
}

#[test]
fn file_ingestion_method_debug_and_eq() {
  assert_eq!(FileIngestionMethod::Flat, FileIngestionMethod::Flat);
  assert_ne!(FileIngestionMethod::Flat, FileIngestionMethod::NixArchive);
  let _ = format!("{:?}", FileIngestionMethod::NixArchive);
}

#[test]
fn make_store_path_contains_name() {
  let sd = StoreDir::default();
  let p = sd.make_store_path("output:out", "sha256:deadbeef", "hello-1.0");
  assert!(p.ends_with("-hello-1.0"));
  let (hash_part, name) = p.split_once('-').unwrap();
  assert_eq!(hash_part.len(), 32);
  assert_eq!(name, "hello-1.0");
}

#[test]
fn make_store_path_hash_is_valid_nix32() {
  let sd = StoreDir::default();
  let p = sd.make_store_path("output:out", "sha256:abc", "foo");
  let (hash_part, _) = p.split_once('-').unwrap();
  for c in hash_part.chars() {
    assert!(Nix32::lookup(c).is_some());
  }
}

#[test]
fn make_store_path_deterministic() {
  let sd = StoreDir::default();
  let a = sd.make_store_path("output:out", "sha256:abc", "foo");
  let b = sd.make_store_path("output:out", "sha256:abc", "foo");
  assert_eq!(a, b);
}

#[test]
fn make_store_path_different_hash_different_path() {
  let sd = StoreDir::default();
  assert_ne!(
    sd.make_store_path("output:out", "sha256:abc", "foo"),
    sd.make_store_path("output:out", "sha256:def", "foo"),
  );
}

#[test]
fn make_store_path_different_type_different_path() {
  let sd = StoreDir::default();
  assert_ne!(
    sd.make_store_path("output:out", "sha256:abc", "foo"),
    sd.make_store_path("text", "sha256:abc", "foo"),
  );
}

#[test]
fn make_store_path_different_store_dir_different_path() {
  let a = StoreDir::new("/nix/store");
  let b = StoreDir::new("/gnu/store");
  assert_ne!(
    a.make_store_path("output:out", "sha256:abc", "foo"),
    b.make_store_path("output:out", "sha256:abc", "foo"),
  );
}

#[test]
fn make_store_path_from_hash_uses_sha256_prefix() {
  let sd = StoreDir::default();
  let hash = vec![0xABu8; 32];
  let p1 = sd.make_store_path_from_hash("output:out", &hash, "foo");
  let p2 = sd.make_store_path(
    "output:out",
    &format!("sha256:{}", hex_str(&hash)),
    "foo",
  );
  assert_eq!(p1, p2);
}

#[test]
fn make_output_path_default_output() {
  let sd = StoreDir::default();
  let drv_hash = hash_bytes(HashAlgorithm::Sha256, b"dummy");
  let p = sd.make_output_path("out", &drv_hash, "hello-1.0");
  let (hp, name) = p.split_once('-').unwrap();
  assert_eq!(hp.len(), 32);
  assert_eq!(name, "hello-1.0");
}

#[test]
fn make_output_path_named_output() {
  let sd = StoreDir::default();
  let drv_hash = hash_bytes(HashAlgorithm::Sha256, b"dummy");
  let p = sd.make_output_path("dev", &drv_hash, "hello-1.0");
  let (hp, name) = p.split_once('-').unwrap();
  assert_eq!(hp.len(), 32);
  assert_eq!(name, "hello-1.0-dev");
}

#[test]
fn fixed_output_path_flat() {
  let sd = StoreDir::default();
  let hash = hash_bytes(HashAlgorithm::Sha256, b"my content");
  let p =
    sd.make_fixed_output_path("my-pkg", FileIngestionMethod::Flat, &hash, &[]);
  let (hp, name) = p.split_once('-').unwrap();
  assert_eq!(hp.len(), 32);
  assert_eq!(name, "my-pkg");
}

#[test]
fn fixed_output_path_flat_deterministic() {
  let sd = StoreDir::default();
  let hash = hash_bytes(HashAlgorithm::Sha256, b"content");
  let a =
    sd.make_fixed_output_path("pkg", FileIngestionMethod::Flat, &hash, &[]);
  let b =
    sd.make_fixed_output_path("pkg", FileIngestionMethod::Flat, &hash, &[]);
  assert_eq!(a, b);
}

#[test]
fn fixed_output_path_nar() {
  let sd = StoreDir::default();
  let hash = hash_bytes(HashAlgorithm::Sha256, b"nar content");
  let p = sd.make_fixed_output_path(
    "pkg",
    FileIngestionMethod::NixArchive,
    &hash,
    &[],
  );
  let (hp, name) = p.split_once('-').unwrap();
  assert_eq!(hp.len(), 32);
  assert_eq!(name, "pkg");
}

#[test]
fn fixed_output_path_flat_vs_nar_differ() {
  let sd = StoreDir::default();
  let hash = hash_bytes(HashAlgorithm::Sha256, b"same");
  let flat =
    sd.make_fixed_output_path("pkg", FileIngestionMethod::Flat, &hash, &[]);
  let nar = sd.make_fixed_output_path(
    "pkg",
    FileIngestionMethod::NixArchive,
    &hash,
    &[],
  );
  assert_ne!(flat, nar);
}

#[test]
fn fixed_output_path_nar_with_references() {
  let sd = StoreDir::default();
  let refs = vec![
    "r7r1sd2lq3n2lb72vf1aaq3syy0kj9bq-dep-1".to_owned(),
    "r7r1sd2lq3n2lb72vf1aaq3syy0kj9bq-dep-2".to_owned(),
  ];
  let hash = hash_bytes(HashAlgorithm::Sha256, b"content");
  let no_refs = sd.make_fixed_output_path(
    "pkg",
    FileIngestionMethod::NixArchive,
    &hash,
    &[],
  );
  let with_refs = sd.make_fixed_output_path(
    "pkg",
    FileIngestionMethod::NixArchive,
    &hash,
    &refs,
  );
  assert_ne!(no_refs, with_refs);
  let (hp, _) = with_refs.split_once('-').unwrap();
  assert_eq!(hp.len(), 32);
}

#[test]
fn make_text_path_no_refs() {
  let sd = StoreDir::default();
  let hash = hash_bytes(HashAlgorithm::Sha256, b"drv content");
  let p = sd.make_text_path("foo.drv", &hash, &[]);
  let (hp, name) = p.split_once('-').unwrap();
  assert_eq!(hp.len(), 32);
  assert_eq!(name, "foo.drv");
}

#[test]
fn make_text_path_with_refs() {
  let sd = StoreDir::default();
  let refs = vec!["r7r1sd2lq3n2lb72vf1aaq3syy0kj9bq-dep-1".to_owned()];
  let hash = hash_bytes(HashAlgorithm::Sha256, b"drv content");
  let no_refs = sd.make_text_path("bar.drv", &hash, &[]);
  let with_refs = sd.make_text_path("bar.drv", &hash, &refs);
  assert_ne!(no_refs, with_refs);
}

#[test]
fn is_derivation_detection() {
  assert!(StoreDir::is_derivation("foo.drv"));
  assert!(!StoreDir::is_derivation("foo"));
  assert!(!StoreDir::is_derivation("foo.drv.tar"));
}

#[test]
fn parse_valid_store_path() {
  let (hp, name) =
    StoreDir::parse_store_path("r7r1sd2lq3n2lb72vf1aaq3syy0kj9bq-hello-2.12.1")
      .unwrap();
  assert_eq!(hp.len(), 32);
  assert_eq!(name, "hello-2.12.1");
}

#[test]
fn parse_store_path_with_full_prefix() {
  let (hp, name) = StoreDir::parse_store_path(
    "/nix/store/r7r1sd2lq3n2lb72vf1aaq3syy0kj9bq-hello-2.12.1",
  )
  .unwrap();
  assert_eq!(hp, "r7r1sd2lq3n2lb72vf1aaq3syy0kj9bq");
  assert_eq!(name, "hello-2.12.1");
}

#[test]
fn parse_rejects_bad_nix32() {
  assert!(
    StoreDir::parse_store_path("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-x").is_none()
  );
}

#[test]
fn parse_rejects_short_hash() {
  assert!(StoreDir::parse_store_path("short-x").is_none());
}

#[test]
fn parse_rejects_invalid_name() {
  assert!(
    StoreDir::parse_store_path("r7r1sd2lq3n2lb72vf1aaq3syy0kj9bq- ").is_none()
  );
}

#[test]
fn full_pipeline_output_path() {
  let sd = StoreDir::default();
  let raw = b"some derivation content";
  let drv_hash = hash_sha256(raw);
  let path = sd.make_output_path("out", &drv_hash, "hello-2.12.1");

  assert!(!path.starts_with(&sd.store_dir));
  let base = path.rsplit('/').next().unwrap_or(&path);
  assert!(StoreDir::parse_store_path(base).is_some());
}

#[test]
fn full_pipeline_fixed_output_nar() {
  let sd = StoreDir::default();
  let content = b"tarball contents go here";
  let nar_hash = hash_sha256(content);
  let path = sd.make_fixed_output_path(
    "hello-2.12.1",
    FileIngestionMethod::NixArchive,
    &nar_hash,
    &[],
  );
  let base = path.rsplit('/').next().unwrap_or(&path);
  assert!(StoreDir::parse_store_path(base).is_some());
}

#[test]
fn full_pipeline_text_path() {
  let sd = StoreDir::default();
  let drv_aterm = "Derive([(\"out\",\"/nix/store/\
                   r7r1sd2lq3n2lb72vf1aaq3syy0kj9bq-test\",\"\",\"\")],[],[\"/\
                   bin/sh\"],\"x86_64-linux\",\"\",[])";
  let content_hash = hash_string(HashAlgorithm::Sha256, drv_aterm);
  let path = sd.make_text_path("test.drv", &content_hash, &[]);
  let base = path.rsplit('/').next().unwrap_or(&path);
  assert!(StoreDir::parse_store_path(base).is_some());
}

fn hex_str(data: &[u8]) -> String {
  data.iter().map(|b| format!("{b:02x}")).collect()
}
