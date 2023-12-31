use std::collections::HashMap;

use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};
use base64::{engine::general_purpose, Engine};
use rand::{distributions::Standard, Rng};

use super::xor::xor;

pub fn decrypt_ecb(key: &[u8], bytes: Vec<u8>) -> Vec<u8> {
    let cipher = Aes128::new(key.into());

    let full = bytes
        .as_slice()
        .chunks(16)
        .flat_map(|chunk| {
            let mut block = *GenericArray::from_slice(chunk);
            cipher.decrypt_block(&mut block);
            block
        })
        .collect::<Vec<u8>>();
    full
}

pub fn encrypt_ecb(key: &[u8], bytes: Vec<u8>) -> Vec<u8> {
    let cipher = Aes128::new(key.into());

    let full = bytes
        .as_slice()
        .chunks(16)
        .flat_map(|chunk| {
            let mut block = *GenericArray::from_slice(chunk);
            cipher.encrypt_block(&mut block);
            block
        })
        .collect::<Vec<u8>>();
    full
}

pub fn pkcs7_padding(bytes: &[u8], block_size: usize) -> Vec<u8> {
    let bs = block_size;
    let mut v = Vec::from(bytes);
    let diff = bs - (bytes.len() % bs);
    v.resize_with(bytes.len() + diff, || diff as u8);
    v
}

pub fn encrypt_cbc(key: &[u8], bytes: Vec<u8>, iv: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(key.into());

    let full = bytes
        .as_slice()
        .chunks(16)
        .fold((iv.to_vec(), Vec::new()), |acc, plain_text| {
            let (iv, existing_encrypted_bytes) = acc;
            // XOR the previous and plain text
            let xor_d_block = xor(&plain_text, &iv);

            // block cipher the XORd plaintext+iv
            let mut block = *GenericArray::from_slice(&xor_d_block);
            cipher.encrypt_block(&mut block);
            let cipher_text: Vec<u8> = block.to_vec();

            // append the new encrypted text, to the existing chain
            let mut new_encrypted_bytes: Vec<u8> = Vec::from(existing_encrypted_bytes);
            new_encrypted_bytes.extend(&cipher_text);

            // use the new cipher text as the next IV
            (cipher_text, new_encrypted_bytes)
        });

    return full.1;
}

pub fn decrypt_cbc(key: &[u8], bytes: Vec<u8>, iv: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(key.into());

    let full = bytes
        .as_slice()
        .chunks(16)
        .fold((iv.to_vec(), Vec::new()), |acc, chunk| {
            let (iv, chained_bytes) = acc;

            // decrypt the cipher text with the key
            let mut decrypted_text = *GenericArray::from_slice(chunk);
            cipher.decrypt_block(&mut decrypted_text);

            let plain_text = xor(&decrypted_text.to_vec(), &iv);
            let mut new_decrypted_bytes: Vec<u8> = Vec::from(chained_bytes);
            new_decrypted_bytes.extend(&plain_text);

            // pass the original cipher text as the next IV
            (chunk.to_vec(), new_decrypted_bytes)
        });

    return full.1;
}

pub fn detect_ebc(input: &[u8]) -> bool {
    let mut map = HashMap::new();
    input.chunks(16).for_each(|c| {
        let key = c.to_owned();
        *map.entry(key).or_insert(0) += 1;
    });

    if map.values().any(|f| f > &1) {
        return true;
    }
    return false;
}

pub fn get_encryption_oracle() -> impl Fn(&[u8]) -> (bool, Vec<u8>) {
    let mut rng = rand::thread_rng();
    // do all the random things
    let key: [u8; 16] = rng.gen();

    let encryption_oracle = move |input: &[u8]| {
        let mut rng = rand::thread_rng();
        let prefix_size = rng.gen_range(5..10);
        let suffix_size = rng.gen_range(5..10);
        let prefix: Vec<u8> = (&mut rng).sample_iter(Standard).take(prefix_size).collect();
        let suffix: Vec<u8> = (&mut rng).sample_iter(Standard).take(suffix_size).collect();
        let cbc_mode: bool = rng.gen();

        let mut plain_text = [prefix, input.to_vec(), suffix].concat();
        plain_text = pkcs7_padding(&plain_text, 16);

        if cbc_mode {
            let iv: [u8; 16] = rng.gen();
            let encrypted = encrypt_cbc(&key, plain_text, &iv);

            return (false, encrypted);
        } else {
            let encrypted = encrypt_ecb(&key, plain_text);
            return (true, encrypted);
        }
    };

    return encryption_oracle;
}

pub fn get_encryption_oracle_with_suffix() -> impl Fn(&[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let suffix = general_purpose::STANDARD
    .decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    .unwrap();

    // do all the random things
    let key: [u8; 16] = rng.gen();

    let encryption_oracle = move |input: &[u8]| {
        let mut plain_text = [input.to_vec(), suffix.to_vec()].concat();
        plain_text = pkcs7_padding(&plain_text, 16);

        let encrypted = encrypt_ecb(&key, plain_text);
        return encrypted;
    };

    return encryption_oracle;
}

#[derive(Debug)]
pub struct EncSize {
    pub block_size: usize,
    pub suffix_size: usize,
}

pub fn detect_block_and_suffix_size(oracle: impl Fn(&[u8]) -> Vec<u8>) -> EncSize {
    let mut i = 0;
    loop {
        let l1 = oracle(&vec![0; i]).len();
        let l2 = oracle(&vec![0; i + 1]).len();

        if l1 < l2 {
            break EncSize {
                block_size: l2 - l1,
                suffix_size: l1 - i,
            };
        }

        if i > 2000 {
            panic!("TOO LARGE!")
        }
        i += 1;
    }
}
