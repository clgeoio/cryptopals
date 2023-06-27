use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};

use super::xor::xor;

pub fn decrypt_aes(key: &[u8], bytes: Vec<u8>) -> Vec<u8> {
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

pub fn encrypt_aes(key: &[u8], bytes: Vec<u8>) -> Vec<u8> {
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

pub fn pkcs7_padding(bytes: &[u8], len: usize) -> Vec<u8> {
    assert!(len < 256);
    let mut v = Vec::from(bytes);
    let diff = len - bytes.len();
    if diff <= 0 {
        return v;
    } else {
        v.resize_with(len, || diff as u8);
        return v;
    }
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
