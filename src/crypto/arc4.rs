/// ARC4 encryption/decryption implementation for Bitcoin data-carrying protocols
///
/// ARC4 (also known as RC4) is used by both Bitcoin Stamps and Counterparty protocols
/// to encrypt data embedded in P2MS outputs. The encryption key is typically derived
/// from transaction inputs.
///
/// # Implementation Notes
///
/// This implementation follows the standard ARC4 algorithm:
/// 1. Key-scheduling algorithm (KSA) to initialise the S-box
/// 2. Pseudo-random generation algorithm (PRGA) to generate keystream
/// 3. XOR the data with the keystream
///
/// # Usage
///
/// ```rust
/// use data_carry_research::crypto::arc4;
///
/// let data = b"hello world";
/// let key = b"secret";
///
/// // Encrypt the data
/// let encrypted = arc4::decrypt(data, key).unwrap();
///
/// // Decrypt the data (ARC4 is symmetric)
/// let decrypted = arc4::decrypt(&encrypted, key).unwrap();
/// assert_eq!(decrypted, data);
/// ```
use hex;

/// Decrypt data using ARC4 algorithm with the given key
///
/// Note: ARC4 is a symmetric cipher, so this function can be used for both
/// encryption and decryption.
///
/// # Arguments
///
/// * `data` - The data to decrypt
/// * `key` - The encryption key
///
/// # Returns
///
/// Returns `Some(Vec<u8>)` with the decrypted data, or `None` if the key or data is empty
pub fn decrypt(data: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    if key.is_empty() || data.is_empty() {
        return None;
    }

    // Initialise S-box
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j = 0u8;

    // Key-scheduling algorithm (KSA)
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }

    // Pseudo-random generation algorithm (PRGA)
    let mut result = Vec::with_capacity(data.len());
    let mut i = 0u8;
    j = 0;

    for &byte in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        result.push(byte ^ k);
    }

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

    #[test]
    fn test_arc4_decrypt_symmetric() {
        let data = b"hello";
        let key = b"key";
        let encrypted = decrypt(data, key).unwrap();
        let decrypted = decrypt(&encrypted, key).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_arc4_empty_inputs() {
        assert_eq!(decrypt(b"data", b""), None);
        assert_eq!(decrypt(b"", b"key"), None);
        assert_eq!(decrypt(b"", b""), None);
    }

    #[test]
    fn test_prepare_key_from_txid() {
        let txid = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let key = prepare_key_from_txid(txid).unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(hex::encode(&key), txid);
    }

    #[test]
    fn test_prepare_key_invalid_hex() {
        assert_eq!(prepare_key_from_txid("invalid_hex"), None);
    }
}
