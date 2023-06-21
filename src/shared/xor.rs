pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    (0..a.len()).map(|i| a[i] ^ b[i]).collect()
}

pub fn xor_with_key(a: &[u8], key: u8) -> Vec<u8> {
    (0..a.len()).map(|i| a[i] ^ key).collect()
}

pub fn xor_with_repeating_key(a: &[u8], key: &[u8]) -> Vec<u8> {
    (0..a.len()).map(|i| a[i] ^ key[i % key.len()]).collect()
}
