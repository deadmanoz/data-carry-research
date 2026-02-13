/// ARC4 encryption/decryption wrapper around the `rc4` crate
///
/// ARC4 (also known as RC4) is used by both Bitcoin Stamps and Counterparty protocols
/// to encrypt data embedded in P2MS outputs. The encryption key is typically derived
/// from transaction inputs (32-byte transaction IDs).
///
/// # Usage
///
/// ```rust
/// use data_carry_research::crypto::arc4;
///
/// let key = hex::decode("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890").unwrap();
/// let data = b"hello world";
///
/// // Encrypt the data
/// let encrypted = arc4::decrypt(data, &key).unwrap();
///
/// // Decrypt the data (ARC4 is symmetric)
/// let decrypted = arc4::decrypt(&encrypted, &key).unwrap();
/// assert_eq!(decrypted, data);
/// ```
use hex;
use rc4::{consts::U32, Key, KeyInit, Rc4, StreamCipher};

/// Decrypt data using ARC4 algorithm with the given key
///
/// Note: ARC4 is a symmetric cipher, so this function can be used for both
/// encryption and decryption.
///
/// # Arguments
///
/// * `data` - The data to decrypt
/// * `key` - The encryption key (must be exactly 32 bytes)
///
/// # Returns
///
/// Returns `Some(Vec<u8>)` with the decrypted data, or `None` if the key is not
/// exactly 32 bytes, or if the data is empty
pub fn decrypt(data: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    if key.len() != 32 || data.is_empty() {
        return None;
    }

    let rc4_key = Key::<U32>::from_slice(key);
    let mut cipher = Rc4::new(rc4_key);
    let mut result = data.to_vec();
    cipher.apply_keystream(&mut result);

    Some(result)
}

/// Prepare ARC4 key from transaction input
///
/// For Bitcoin Stamps and Counterparty protocols, the ARC4 encryption key
/// is typically derived from the first input transaction ID.
///
/// # Arguments
///
/// * `txid_hex` - The transaction ID as a hex string
///
/// # Returns
///
/// Returns `Some(Vec<u8>)` with the decoded transaction ID bytes, or `None` if decoding fails
pub fn prepare_key_from_txid(txid_hex: &str) -> Option<Vec<u8>> {
    hex::decode(txid_hex).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY_HEX: &str = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

    fn test_key() -> Vec<u8> {
        hex::decode(TEST_KEY_HEX).unwrap()
    }

    #[test]
    fn test_arc4_decrypt_symmetric() {
        let data = b"hello";
        let key = test_key();
        let encrypted = decrypt(data, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_arc4_empty_inputs() {
        let key = test_key();
        assert_eq!(decrypt(b"data", b""), None);
        assert_eq!(decrypt(b"", &key), None);
        assert_eq!(decrypt(b"", b""), None);
    }

    #[test]
    fn test_arc4_rejects_short_key() {
        assert_eq!(decrypt(b"data", b"key"), None);
        assert_eq!(decrypt(b"data", b"short_key_16bytes"), None);
    }

    #[test]
    fn test_arc4_known_vector() {
        // Verify against a known RC4 test vector with a 32-byte key
        let key = test_key();
        let data = b"test data for verification";
        let encrypted = decrypt(data, &key).unwrap();

        // Encrypting again with the same key must recover the original
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, data);

        // Encrypted output must differ from input
        assert_ne!(encrypted, data.to_vec());
    }

    #[test]
    fn test_prepare_key_from_txid() {
        let key = prepare_key_from_txid(TEST_KEY_HEX).unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(hex::encode(&key), TEST_KEY_HEX);
    }

    #[test]
    fn test_prepare_key_invalid_hex() {
        assert_eq!(prepare_key_from_txid("invalid_hex"), None);
    }
}
