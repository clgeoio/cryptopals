#[cfg(test)]
mod tests {
    use std::fs::read_to_string;

    use base64::{engine::general_purpose, Engine};
    use pretty_assertions::assert_eq;
    use rand::Rng;

    use crate::shared::{
        analysis::{freq_analysis, freq_analysis_iter, most_likely_encoded},
        conversion::{bytes_to_base64, bytes_to_hex, hex_to_bytes},
        hamming::{hamming_distance, hamming_distance_bytes},
        xor::{xor, xor_with_key, xor_with_repeating_key},
    };

    #[test]
    fn test_challenge_1() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let bytes = hex_to_bytes(hex).unwrap();
        let base64 = bytes_to_base64(&bytes);
        assert_eq!(
            base64,
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    #[test]
    fn test_challenge_2() {
        let a = hex_to_bytes("1c0111001f010100061a024b53535009181c").unwrap();
        let b = hex_to_bytes("686974207468652062756c6c277320657965").unwrap();
        let modified = xor(&a, &b);
        let res = bytes_to_hex(modified);
        assert_eq!(res, "746865206b696420646f6e277420706c6179");
    }

    #[test]
    fn test_challenge_3() {
        let t = hex_to_bytes("5468697320697320746865206c6173742074696d6520746861742049276d20657665722077616c6b696e6720686f6d6520616761696e0d0a").unwrap();
        let x = rand::thread_rng().gen_range(0..255);

        let enc = xor_with_key(&t, x);

        let _a = hex_to_bytes("62696e672062616e6720626f6e67").unwrap();
        let mut res = freq_analysis(&enc);
        res.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

        println!("{:#?}", res.iter().take(1).collect::<Vec<_>>());
    }

    #[test]
    fn test_challenge_4() {
        let j = read_to_string("src/set1/4.txt").unwrap();
        let input = j.lines().collect::<Vec<&str>>();

        let res = most_likely_encoded(input);
        println!("{:#?}", res);
    }

    #[test]
    fn test_challenge_5() {
        let a = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
            .as_bytes();
        let modified = xor_with_repeating_key(&a, "ICE".as_bytes());
        let res = bytes_to_hex(modified);
        assert_eq!(
            res,
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        );
    }

    #[test]
    fn test_challenge_6a() {
        assert_eq!(hamming_distance("this is a test", "wokka wokka!!!"), 37);
    }

    #[test]
    fn test_challenge_6b() {
        let decoded = general_purpose::STANDARD
            .decode(&read_to_string("src/set1/6.txt").unwrap().replace("\n", ""))
            .unwrap();

        // find keysize.
        let (key_sz, _key_dist) = (2..=40)
            .map(|keysize| {
                let mut distance = 0;
                let mut i = 0;
                while (i + 2) * keysize < decoded.len() {
                    distance += hamming_distance_bytes(
                        &decoded[i * keysize..(i + 1) * keysize],
                        &decoded[(i + 1) * keysize..(i + 2) * keysize],
                    );
                    i += 2;
                }

                let normalized_distance =
                    f64::from(distance) / f64::from(u32::try_from(i / 2 * keysize).unwrap());
                (keysize, normalized_distance)
            })
            .min_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
            .unwrap();

        println!("{:?}", key_sz);

        let key = (0..key_sz)
            .map(|offset| {
                let transposed = transpose(&decoded, key_sz, offset);
                let best = freq_analysis_iter(&transposed)
                    .min_by(|a: &(f64, u8, String), b| a.0.partial_cmp(&b.0).unwrap());

                match best {
                    Some((_, k, _)) => return Some(k),
                    None => return None,
                }
            })
            .filter(|k| k.is_some())
            .map(|f| f.unwrap() as char);

        println!("{:?}", String::from_iter(key));
    }

    fn transpose(ct: &[u8], key_size: usize, offset: usize) -> Vec<u8> {
        let mut transposed = Vec::new();
        let mut i = 0;
        while i + offset < ct.len() {
            transposed.push(ct[i + offset]);
            i += key_size;
        }
        transposed
    }
}
