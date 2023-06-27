pub fn hamming_distance(x: &str, y: &str) -> u32 {
    assert_eq!(x.len(), y.len());
    hamming_distance_bytes(x.as_bytes(), y.as_bytes())
}

pub fn hamming_distance_bytes(x: &[u8], y: &[u8]) -> u32 {
    assert_eq!(x.len(), y.len());
    x.iter()
        .zip(y)
        .fold(0, |a, (b, c)| a + (*b ^ *c).count_ones())
}
