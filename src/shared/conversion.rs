fn hex_char_to_byte(c: u8) -> u8 {
    match c {
        b'A'..=b'F' => c - b'A' + 10, // make 'A' => 11, B => 12 etc
        b'a'..=b'f' => c - b'a' + 10,
        b'0'..=b'9' => c - b'0', // make '0' => 0 etc
        _ => panic!("Could not convert {:?}", c),
    }
}

#[must_use]
pub fn hex_to_bytes<T: AsRef<[u8]>>(s: T) -> Result<Vec<u8>, &'static str> {
    let hex = s.as_ref();
    if hex.len() % 2 != 0 {
        return Err("bad length");
    }
    hex.chunks(2)
        .enumerate()
        .map(|(_, pair)| {
            let first_hex = hex_char_to_byte(pair[0]);
            let second_hex = hex_char_to_byte(pair[1]);
            return Ok(first_hex << 4 | second_hex);
        })
        .collect()
}

#[must_use]
pub fn bytes_to_hex(s: Vec<u8>) -> String {
    s.iter()
        .map(|b| format!("{:02x}", b).to_string())
        .collect::<Vec<String>>()
        .join("")
}

#[must_use]
pub fn bytes_to_base64(bytes: &[u8]) -> String {
    let ch = bytes
        .chunks(3)
        .map(|c| {
            let a = c.get(0).unwrap_or(&0);
            let b = c.get(1).unwrap_or(&0);
            let c = c.get(2).unwrap_or(&0);
            vec![
                a >> 2,
                (a & 0b00000011) << 4 | b >> 4,
                (b & 0b00001111) << 2 | c >> 6,
                c & 0b00111111,
            ]
        })
        .flat_map(encode_chunk);

    return String::from_iter(ch);
}

fn encode_chunk(chunk: Vec<u8>) -> Vec<char> {
    let mut out = vec!['='; 4];
    const BASE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    for i in 0..chunk.len() {
        let x = chunk[i] as usize;
        let chr = BASE_CHARS[x];
        out[i] = chr as char;
    }

    out
}

pub fn transpose(ct: &[u8], key_size: usize, offset: usize) -> Vec<u8> {
    let mut transposed = Vec::new();
    let mut i = 0;
    while i + offset < ct.len() {
        transposed.push(ct[i + offset]);
        i += key_size;
    }
    transposed
}
