#[cfg(test)]
mod tests {
    use std::fs::read_to_string;

    use base64::{engine::general_purpose, Engine};

    use crate::shared::aes::{
        decrypt_cbc, decrypt_ecb, detect_ebc, encrypt_ecb, encryption_oracle, pkcs7_padding,
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

        let input = vec![0; 54];

        let d = encryption_oracle(&input);

        let is_ecb = detect_ebc(&d.1);
        assert_eq!(is_ecb, d.0);
    }
}
