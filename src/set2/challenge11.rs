use std::fs::File;
use std::io::{BufRead, BufReader};
extern crate openssl;
use super::super::set1::challenge1;
use super::super::set1::challenge6;
use super::super::set1::challenge8;
use super::challenge9;
use openssl::symm::*;
use rand::{thread_rng, Rng};

/// encrypt text in file via AES-128 in ECB mode under the key
pub fn encrypt_aes128_ecb(file: File, key: &str) -> String {
    let buf = BufReader::new(file);
    let test_input: String = buf
        .lines()
        .map(|l| l.expect("Could not parse line"))
        .collect::<Vec<String>>()
        .join("\n");
    encrypt_string_aes128_ecb(&test_input, key)
}

/// encrypt input string via AES-128 in ECB mode under the key
pub fn encrypt_string_aes128_ecb(input: &str, key: &str) -> String {
    let file_bytes = input.as_bytes();
    let cipher = Cipher::aes_128_ecb();
    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, &key.as_bytes(), None).unwrap();
    let mut output = vec![0 as u8; file_bytes.len() + Cipher::aes_128_ecb().block_size()];
    match encrypter.update(&file_bytes, &mut output) {
        Ok(s) => {
            let tl = encrypter.finalize(&mut output[s..]).unwrap();
            let hex_alphabet: Vec<char> = "0123456789abcdef".chars().collect();
            let mut hex_str = String::with_capacity((output.len() - 16) * 2);
            for i in 0..(s + tl) {
                let nibble0 = output[i] & 0xf;
                let nibble1 = output[i] >> 4;
                hex_str.push(hex_alphabet[nibble1 as usize]);
                hex_str.push(hex_alphabet[nibble0 as usize]);
            }
            challenge1::hex_to_base64(&hex_str)
        }
        Err(_) => String::new(),
    }
}

/// encrypt text in file via AES-128 in CBC mode under the key
pub fn encrypt_aes128_cbc(file: File, key: &str) -> String {
    let buf = BufReader::new(file);
    let test_input: String = buf
        .lines()
        .map(|l| l.expect("Could not parse line"))
        .collect::<Vec<String>>()
        .join("\n");
    encrypt_string_aes128_cbc(&test_input, key)
}

/// encrypt input string via AES-128 in CBC mode under the key
pub fn encrypt_string_aes128_cbc(input: &str, key: &str) -> String {
    let hex_alphabet: Vec<char> = "0123456789abcdef".chars().collect();
    let test_input = challenge9::pkcs7_padding(input, Cipher::aes_128_ecb().block_size());
    let mut file_bytes = test_input.into_bytes();
    let mut iv = vec![0 as u8; 16];
    let cipher = Cipher::aes_128_ecb();
    let mut encrypter = Crypter::new(cipher, Mode::Encrypt, &key.as_bytes(), None).unwrap();
    let mut hex_str =
        String::with_capacity((file_bytes.len() + Cipher::aes_128_ecb().block_size()) * 2);
    let mut index = 0;
    while index < file_bytes.len() {
        let mut output = vec![0 as u8; 2 * Cipher::aes_128_ecb().block_size()];
        for i in index..index + Cipher::aes_128_ecb().block_size() {
            file_bytes[i] = file_bytes[i] ^ iv[i - index];
        }
        match encrypter.update(
            &file_bytes[index..index + Cipher::aes_128_ecb().block_size()],
            &mut output,
        ) {
            Ok(_) => {
                for i in 0..Cipher::aes_128_ecb().block_size() {
                    let nibble0 = output[i] & 0xf;
                    let nibble1 = output[i] >> 4;
                    hex_str.push(hex_alphabet[nibble1 as usize]);
                    hex_str.push(hex_alphabet[nibble0 as usize]);
                    iv[i] = output[i];
                }
            }
            Err(_) => return String::new(),
        }
        index += Cipher::aes_128_ecb().block_size();
    }
    challenge1::hex_to_base64(&hex_str)
}

/// generate random 16 byte AES key
pub fn generate_aes_key() -> String {
    let mut rng = thread_rng();
    let mut aes_key = String::with_capacity(16);
    for _ in 0..16 {
        let num: u8 = rng.gen_range(32..=126);
        aes_key.push(num as char);
    }
    aes_key
}

/// encrypt with random key via AES-128 in CBC or ECB mode
pub fn encryption_oracle(input: &str) -> (String, u8) {
    let key = generate_aes_key();
    let mut rng = thread_rng();
    let mut plaintext = String::with_capacity(input.len() + 20);
    let pre_size = rng.gen_range(5..=10);
    for _ in 0..pre_size {
        let num: u8 = rng.gen_range(0..=255);
        plaintext.push(num as char);
    }
    plaintext.push_str(input);
    let post_size = rng.gen_range(5..=10);
    for _ in 0..post_size {
        let num: u8 = rng.gen_range(0..=255);
        plaintext.push(num as char);
    }
    let choice = rng.gen_range(0..=1);
    if choice == 0 {
        // ECB mode
        (encrypt_string_aes128_ecb(&plaintext, &key), choice)
    } else {
        // CBC mode
        (encrypt_string_aes128_cbc(&plaintext, &key), choice)
    }
}

/// find encryption mode
pub fn detect_encryption_mode(input: &str) -> u8 {
    let mut inputs: Vec<String> = Vec::new();
    inputs.push(challenge6::base64_to_hex(input).to_string());
    if challenge8::detect_aes_in_ecb_mode(inputs) == "" {
        // CBC mode
        1
    } else {
        // ECB mode
        0
    }
}
