use std::fs::File;
extern crate openssl;
use openssl::symm::*;

/// using ecb-decrypt function, decrypt Base64-encoded content in file via AES-128 in CBC mode under the key
pub fn decrypt_aes128_cbc(file: File, key: &str) -> String {
    use super::super::set1::challenge6;
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
    decrypt_aes128_cbc_hexbytes(&hex_text_u8, key)
}

/// using ecb-decrypt function, decrypt bytes via AES-128 in CBC mode under the key
pub fn decrypt_aes128_cbc_hexbytes(hex_text_u8: &[u8], key: &str) -> String {
    let cipher = Cipher::aes_128_ecb();
    let iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let mut decrypted = Crypter::new(cipher, Mode::Decrypt, &key.as_bytes(), None).unwrap();
    let mut output = vec![0 as u8; hex_text_u8.len() + Cipher::aes_128_ecb().block_size()];

    let decrypted_result = decrypted.update(&hex_text_u8, &mut output);
    match decrypted_result {
        Ok(_) => {
            let mut i = 0;
            let mut j = 0;
            while j < 16 {
                output[j] = output[j] ^ iv[j];
                j += 1;
            }
            while j < hex_text_u8.len() {
                output[j] = output[j] ^ hex_text_u8[i];
                i += 1;
                j += 1;
            }
            output.resize(
                hex_text_u8.len() - (output[hex_text_u8.len() - 1] as usize),
                0,
            );
            String::from_utf8_lossy(&output).to_string()
        }
        Err(_) => String::new(),
    }
}
