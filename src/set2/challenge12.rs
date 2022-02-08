extern crate lazy_static;
extern crate openssl;
use super::super::set1::challenge6;
use super::challenge11;
use lazy_static::lazy_static;
use std::collections::HashMap;

lazy_static! {
    static ref KEY: String = challenge11::generate_aes_key();
}

///find block size
fn find_block_size() -> u8 {
    let input = "A";
    let encryption_output = challenge6::base64_to_hex(&encryption_oracle(input));
    (encryption_output.len() / 2).try_into().unwrap()
}

/// encrypt with consistent unknown key via AES-128 ECB mode
pub fn encryption_oracle(plaintext: &str) -> String {
    let key = KEY.clone();
    let encrypted = challenge11::encrypt_string_aes128_ecb(plaintext, &key);
    encrypted
}

/// decrypt the input byte by byte when the key is consistent but unknown
pub fn byte_at_a_time_ecb_decryption_simple(input: &str) -> String {
    let block_size = find_block_size() as usize;
    let mut test_string = String::with_capacity((block_size * 3).into());
    for _ in 0..block_size * 3 {
        test_string.push('A');
    }
    // make sure that encryption oracle is using ECB mode
    if challenge11::detect_encryption_mode(&encryption_oracle(&test_string)) == 1 {
        return String::new();
    }

    let mut decrypted_string = String::with_capacity(input.len());
    for _ in 0..input.len() {
        let mut test_input = String::with_capacity(input.len() + block_size);
        for _ in 0..(block_size - decrypted_string.len() % block_size - 1) {
            test_input.push('A');
        }
        let mut encrypted_length_to_check = 0;
        let mut possible_characters = HashMap::new();
        for i in 1u8..128u8 {
            let mut test_input_copy = test_input.clone();
            test_input_copy.push_str(&decrypted_string);
            test_input_copy.push(i as char);
            encrypted_length_to_check = test_input_copy.len() * 2;
            let encrypted_of_test = challenge6::base64_to_hex(&encryption_oracle(&test_input_copy));
            let mut key_to_be_inserted = String::with_capacity(encrypted_length_to_check);
            for (j, c) in encrypted_of_test.chars().enumerate() {
                if j == encrypted_length_to_check {
                    break;
                }
                key_to_be_inserted.push(c);
            }
            possible_characters.insert(key_to_be_inserted, i);
        }
        test_input.push_str(&input);
        let encrypted_of_crafted = challenge6::base64_to_hex(&encryption_oracle(&test_input));
        let mut key_to_check = String::with_capacity(encrypted_length_to_check);
        for (i, c) in encrypted_of_crafted.chars().enumerate() {
            if i == encrypted_length_to_check {
                break;
            }
            key_to_check.push(c);
        }
        let value = possible_characters.get(&key_to_check).unwrap();
        decrypted_string.push(*value as char);
    }
    decrypted_string
}
