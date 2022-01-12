use std::fs::File;
extern crate openssl;
use openssl::symm::*;

/// decrypt Base64-encoded content in file via AES-128 in ECB mode under the key
pub fn decrypt_aes128_ecb(file: File, key: &str) -> String {
    use super::challenge6;
    let hex_text = challenge6::get_hex_text_from_file(file);
    let hex_text_chars: Vec<char> = hex_text.chars().collect();
    let mut index = 0;
    let mut hex_text_u8: Vec<u8> = Vec::with_capacity(hex_text_chars.len() / 2);
    while index + 1 < hex_text_chars.len() {
        let nibble1 = hex_text_chars[index].to_digit(16).unwrap();
        let nibble0 = hex_text_chars[index + 1].to_digit(16).unwrap();
        hex_text_u8.push((nibble1 << 4 | nibble0) as u8);
        index += 2;
    }
    let cipher = Cipher::aes_128_ecb();
    let iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let ciphertext = decrypt(cipher, key.as_bytes(), Some(iv), &hex_text_u8).unwrap();
    let decoded_string = String::from_utf8(ciphertext).unwrap();
    decoded_string
}
