#[cfg(test)]
mod tests {
    use std::fs::read_to_string;

    use base64::{engine::general_purpose, Engine};

    use crate::shared::aes::{decrypt_aes, decrypt_cbc, encrypt_aes, encrypt_cbc, pkcs7_padding};

    #[test]
    fn test_challenge_0() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let v = "YELLOW SUBMARINE".as_bytes();

        let e = encrypt_aes(key, v.to_vec());

        let d = String::from_utf8(decrypt_aes(key, e)).unwrap();

        assert_eq!(d, "YELLOW SUBMARINE");
    }

    #[test]
    fn test_challenge_1() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let padded = pkcs7_padding(key, 21);

        println!("{:?}", String::from_utf8(padded));
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
}
