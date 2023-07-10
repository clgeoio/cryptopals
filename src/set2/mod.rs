#[cfg(test)]
mod tests {
    use std::fs::read_to_string;

    use base64::{engine::general_purpose, Engine};

    use crate::shared::aes::{
        decrypt_cbc, decrypt_ecb, detect_block_and_suffix_size, detect_ebc, encrypt_ecb,
        get_encryption_oracle, get_encryption_oracle_with_suffix, pkcs7_padding,
    };

    #[test]
    fn test_challenge_0() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let v = "YELLOW SUBMARINE".as_bytes();

        let e = encrypt_ecb(key, v.to_vec());

        let d = String::from_utf8(decrypt_ecb(key, e)).unwrap();

        assert_eq!(d, "YELLOW SUBMARINE");
    }

    #[test]
    fn test_challenge_1() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let padded = pkcs7_padding(key, 20);

        println!("{:?}", String::from_utf8(padded));
    }

    #[test]
    fn test_challenge_1a() {
        let key = "YLLWSUBMARINE".as_bytes();
        let padded = pkcs7_padding(key, 16);
        println!("{:?}", String::from_utf8(padded.clone()));
        assert_eq!(padded.len(), 16 as usize);
    }

    #[test]
    fn test_challenge_1b() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let padded = pkcs7_padding(key, 16);
        println!("{:?}", String::from_utf8(padded.clone()));
        assert_eq!(padded.len(), 32 as usize);
    }

    #[test]
    fn test_challenge_2() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let decoded = general_purpose::STANDARD
            .decode(&read_to_string("src/set2/10.txt").unwrap().replace("\n", ""))
            .unwrap();

        let iv = vec![0; 16];

        let d = decrypt_cbc(key, decoded, &iv);
        println!("{}", String::from_utf8(d).unwrap());
    }

    #[test]
    fn test_challenge_3() {
        // we need to craft out input such that we can see if the enc is ECB
        // all we can alter is the length of the input
        // so if we can provide at least 32 bytes, they _should_ be broken into two blocks.

        // however, we know that some padding (min 10, max 20) would be added that could split these blocks
        // so if we provide the same character "A" for (32 + (11) + (11)) then we are sure that the 11 + 5 (16)
        // will result in two same blocks
        let encryption_oracle = get_encryption_oracle();
        let input = vec![0; 54];

        let d = encryption_oracle(&input);

        let is_ecb = detect_ebc(&d.1);
        assert_eq!(is_ecb, d.0);
    }

    #[test]
    fn test_challenge_4() {
        let encryption_oracle = get_encryption_oracle_with_suffix();

        let sizes = detect_block_and_suffix_size(&encryption_oracle);

        // detect if EBC by filling all zeros with at least two block sizes worth of info + the suffix.
        let detect_input = vec![0; sizes.block_size * 2 + sizes.suffix_size + 2];
        let encrypted = encryption_oracle(&detect_input);
        let is_ebc = detect_ebc(&encrypted);

        assert_eq!(is_ebc, true);

        let one_byte_targets = (0..sizes.block_size)
            .map(|len| {
                return encryption_oracle(&vec![0; len]);
            })
            .collect::<Vec<Vec<u8>>>();

        let r = (0..sizes.suffix_size).fold(Vec::new(), |mut recovered, recovered_len: usize| {
            let padding_len = (sizes.block_size - 1) - (recovered_len % sizes.block_size);

            let one_byte_target = &one_byte_targets[padding_len];
            let block_to_compare = ((recovered.len() / sizes.block_size) as f32).floor() as usize;

            let block_start = block_to_compare * sizes.block_size;
            let block_end = (block_to_compare + 1) * sizes.block_size;

            let mut to_enc = [vec![0; padding_len], recovered.to_vec(), [0].to_vec()].concat();
            let enc_len = padding_len + recovered.len();

            let byte = (0..=255u8).find_map(|f| {
                to_enc[enc_len] = f;
                let target = &encryption_oracle(&to_enc);

                if one_byte_target[block_start..block_end] == target[block_start..block_end] {
                    return Some(f);
                }
                return None;
            });

            recovered.push(byte.unwrap());
            recovered
        });

        let recovered = String::from_utf8(r).unwrap();
        println!("{}", recovered);
    }
}
