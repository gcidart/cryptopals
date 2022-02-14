use super::super::set1::challenge6;
use super::super::set2::challenge10;
use super::super::set2::challenge14;
use super::super::set2::challenge15;

///decrypt block of 16 bytes using CBC padding oracle attack
fn decrypt_cipher_block(cipher_block: &[u8], key: &[u8]) -> Vec<u8> {
    let mut prefix = vec![0 as u8; key.len()];
    let mut decrypted_bytes = vec![0 as u8; key.len()];
    let mut decrypted_index = key.len() - 1;
    for decrypted_size in 0u8..16u8 {
        let mut i: usize = 0;
        let mut index = key.len() - 1;
        while i < decrypted_size.into() {
            prefix[index] ^= decrypted_size ^ (decrypted_size + 1);
            index -= 1;
            i += 1;
        }
        let mut framed_bytes = Vec::with_capacity(2 * key.len());
        i = 0;
        while i < key.len() {
            framed_bytes.push(prefix[i]);
            i += 1;
        }
        i = 0;
        while i < key.len() {
            framed_bytes.push(cipher_block[i]);
            i += 1;
        }
        for j in 0..=255 {
            framed_bytes[index] = j;
            match challenge15::pkcs7_padding_bytes_strip(
                &challenge10::decrypt_aes128_cbc_hexbytes_into_vec(&framed_bytes, key)[0..32],
            ) {
                Ok(_) => {
                    decrypted_bytes[decrypted_index] = j ^ (decrypted_size + 1);
                    prefix[index] = j;
                    break;
                }
                Err(_) => continue,
            }
        }
        if decrypted_index > 0 {
            decrypted_index -= 1;
        }
    }
    decrypted_bytes
}

///decrypt ciphertext using CBC padding oracle attack
pub fn cbc_padding_oracle(ciphertext: &str, key: &[u8]) -> String {
    let cipherbytes = challenge14::hex_text_to_hex_bytes(&challenge6::base64_to_hex(&ciphertext));
    let mut index = 0;
    let mut decrypted_bytes = Vec::with_capacity(cipherbytes.len());
    while index < cipherbytes.len() {
        let mut cipher_block = Vec::with_capacity(key.len());
        for i in index..(index + 16) {
            cipher_block.push(cipherbytes[i]);
        }
        index += 16;
        let decrypted_block = decrypt_cipher_block(&cipher_block, key);
        for b in decrypted_block.into_iter() {
            decrypted_bytes.push(b);
        }
    }
    for i in 0..(cipherbytes.len() - key.len()) {
        decrypted_bytes[i + key.len()] = decrypted_bytes[i + key.len()] ^ cipherbytes[i];
    }
    challenge15::pkcs7_padding_strip(&String::from_utf8_lossy(&decrypted_bytes).to_string())
        .unwrap()
}
