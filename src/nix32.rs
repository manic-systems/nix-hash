/// Nix's custom base-32 alphabet: digits + lowercase letters minus e, o, u, t.
///
/// The characters e, o, u, t are omitted to prevent forming English words
/// (like "output" or "store") in hash parts of store paths.
const ALPHABET: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

/// Nix32 encoding and decoding.
pub struct Nix32;

impl Nix32 {
  /// Number of base-32 characters needed to represent `byte_len` bytes.
  #[must_use]
  pub const fn encoded_len(byte_len: usize) -> usize {
    if byte_len == 0 {
      return 0;
    }
    (byte_len * 8).div_ceil(5)
  }

  /// Encode raw bytes as a nix32 string.
  pub fn encode(data: &[u8]) -> String {
    if data.is_empty() {
      return String::new();
    }

    let len = Self::encoded_len(data.len());
    let mut out = String::with_capacity(len);

    for n in (0..len).rev() {
      let b = n * 5;
      let i = b / 8;
      let j = b % 8;
      let hi = if i + 1 < data.len() {
        u16::from(data[i + 1]) << (8 - j)
      } else {
        0
      };
      let c = (u16::from(data[i]) >> j) | hi;
      out.push(ALPHABET[(c & 0x1F) as usize] as char);
    }

    out
  }

  /// Decode a nix32 string back into raw bytes.
  ///
  /// Returns `None` if the input contains characters outside the nix32
  /// alphabet.
  pub fn decode(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() {
      return Some(Vec::new());
    }

    let byte_len = (s.len() * 5) / 8;
    let mut res = vec![0u8; byte_len + 1];

    for (n, ch) in s.chars().rev().enumerate() {
      let digit = Self::lookup(ch)?;
      let b = n * 5;
      let i = b / 8;
      let j = b % 8;

      res[i] |= digit << j;
      if j != 0 && digit >> (8 - j) != 0 {
        if i + 1 >= res.len() {
          res.push(0);
        }
        res[i + 1] |= digit >> (8 - j);
      }
    }

    while res.last() == Some(&0) && res.len() > 1 {
      let needed = (s.len() * 5).div_ceil(8);
      if res.len() <= needed {
        break;
      }
      res.pop();
    }

    Some(res)
  }

  /// Build the reverse lookup table at compile time.
  #[allow(clippy::needless_range_loop)]
  const fn make_reverse_map() -> [u8; 256] {
    let mut map = [0xFFu8; 256];
    let mut i = 0;
    while i < ALPHABET.len() {
      let c = ALPHABET[i];
      map[c as usize] = i as u8;
      map[c.to_ascii_uppercase() as usize] = i as u8;
      i += 1;
    }
    map
  }

  const REVERSE_MAP: [u8; 256] = Self::make_reverse_map();

  /// Look up a character in the nix32 alphabet. Returns its 5-bit value
  /// (0-31), or `None` if the character is not in the alphabet.
  #[inline]
  pub fn lookup(c: char) -> Option<u8> {
    let b = c as u32;
    if b > 255 {
      return None;
    }
    let v = Self::REVERSE_MAP[b as usize];
    if v == 0xFF { None } else { Some(v) }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn alphabet_length() {
    assert_eq!(ALPHABET.len(), 32);
  }

  #[test]
  fn rejects_forbidden_chars() {
    for c in ['e', 'o', 'u', 't'] {
      assert!(Nix32::lookup(c).is_none(), "char '{c}' should be forbidden");
    }
  }

  #[test]
  fn roundtrip_various_lengths() {
    for len in [0, 1, 16, 20, 32, 64] {
      let data: Vec<u8> = (0..len).map(|i| (i * 7 + 13) as u8).collect();
      let encoded = Nix32::encode(&data);
      let decoded = Nix32::decode(&encoded).expect("decode should succeed");
      assert_eq!(decoded[..len], data, "roundtrip failed for length {len}");
    }
  }

  #[test]
  fn decode_rejects_forbidden() {
    assert!(Nix32::decode("eeee").is_none());
    assert!(Nix32::decode("!!!!").is_none());
  }

  #[test]
  fn matches_nix_cli_base32() {
    // SHA-256 of "hello", verified against `nix hash to-base32 --type sha256`
    let bytes = hex::decode(
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    )
    .unwrap();
    let encoded = Nix32::encode(&bytes);
    assert_eq!(
      encoded,
      "094qif9n4cq4fdg459qzbhg1c6wywawwaaivx0k0x8xhbyx4vwic"
    );
    let decoded = Nix32::decode(&encoded).unwrap();
    assert_eq!(&decoded[..bytes.len()], &bytes[..]);
  }
}
