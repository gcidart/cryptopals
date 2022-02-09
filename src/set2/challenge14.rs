extern crate lazy_static;
extern crate openssl;
use super::super::set1::challenge6;
use super::challenge11;
use lazy_static::lazy_static;
use rand::{thread_rng, Rng};
use std::collections::HashMap;

lazy_static! {
    static ref KEY: String = challenge11::generate_aes_key();
    static ref PREFIX: String = generate_random_prefix();
}

/// convert hex string to vector of bytes
pub fn hex_text_to_hex_bytes(hex_text: &str) -> Vec<u8> {
    let hex_chars: Vec<char> = hex_text.chars().collect();
    let mut hex_bytes: Vec<u8> = Vec::with_capacity(hex_text.len() / 2);
    let mut index = 0;
    while index + 1 < hex_chars.len() {
        let nibble0 = hex_chars[index].to_digit(16).unwrap();
        let nibble1 = hex_chars[index + 1].to_digit(16).unwrap();
        hex_bytes.push((nibble0 << 4 | nibble1).try_into().unwrap());
        index += 2;
    }
    hex_bytes
}

/// generate random  prefix
fn generate_random_prefix() -> String {
    let mut rng = thread_rng();
    let prefix_size: usize = rng.gen_range(4..=31);
    let mut prefix = String::with_capacity(prefix_size);
    for _ in 0..prefix_size {
        let num: u8 = rng.gen_range(32..=126);
        prefix.push(num as char);
    }
    prefix
}

///find possible input size
///actual input size would be +/- blocksize because of padding
fn find_possible_input_size(target_input: &str) -> usize {
    let mut input_size = 0;
    let mut input_a = String::with_capacity(target_input.len() + 1);
    let mut input_b = String::with_capacity(target_input.len() + 1);
    input_a.push('a');
    input_a.push_str(target_input);
    let encrypted_base64_a = encryption_oracle(&input_a);
    let encrypted_hex_text_a = challenge6::base64_to_hex(&encrypted_base64_a);
    let encrypted_bytes_a = hex_text_to_hex_bytes(&encrypted_hex_text_a);
    input_b.push('b');
    input_b.push_str(target_input);
    let encrypted_base64_b = encryption_oracle(&input_b);
    let encrypted_hex_text_b = challenge6::base64_to_hex(&encrypted_base64_b);
    let encrypted_bytes_b = hex_text_to_hex_bytes(&encrypted_hex_text_b);
    let mut index = encrypted_bytes_b.len() - 1;
    loop {
        if encrypted_bytes_a[index] == encrypted_bytes_b[index] {
            input_size += 1;
        } else {
            break;
        }
        if index == 0 {
            break;
        }
        index -= 1;
    }
    input_size
}

///find prefix  size
fn find_prefix_size(target_input: &str, target_input_size: usize) -> usize {
    let mut prefix_size = 10000000;
    for i in 0..16 {
        let mut attacker_controlled_and_target_input = String::with_capacity(target_input_size + i);
        for _ in 0..i {
            attacker_controlled_and_target_input.push('A');
        }
        attacker_controlled_and_target_input.push_str(target_input);
        let encrypted_base64 = encryption_oracle(&attacker_controlled_and_target_input);
        let encrypted_hex_text = challenge6::base64_to_hex(&encrypted_base64);
        let encrypted_bytes = hex_text_to_hex_bytes(&encrypted_hex_text);
        if encrypted_bytes.len() - target_input_size - i < prefix_size {
            prefix_size = encrypted_bytes.len() - target_input_size - i;
        }
    }
    // when input length is same as block size, block_size number of padding bytes are added
    prefix_size -= 1;
    prefix_size.try_into().unwrap()
}

/// add a consistent prefix and encrypt with consistent unknown key via AES-128 ECB mode
fn encryption_oracle(plaintext: &str) -> String {
    let key = KEY.clone();
    let prefix = PREFIX.clone();
    let mut mod_plaintext = String::with_capacity(plaintext.len() + prefix.len());
    mod_plaintext.push_str(&prefix);
    mod_plaintext.push_str(&plaintext);
    let encrypted = challenge11::encrypt_string_aes128_ecb(&mod_plaintext, &key);
    encrypted
}

/// decrypt the input byte by byte when the key is consistent but unknown
/// and unknown prefix is added before encyption
pub fn byte_at_a_time_ecb_decryption_hard(input: &str) -> String {
    let block_size = 16;
    let mut test_string = String::with_capacity((block_size * 3).into());
    for _ in 0..block_size * 3 {
        test_string.push('A');
    }
    // make sure that encryption oracle is using ECB mode
    if challenge11::detect_encryption_mode(&encryption_oracle(&test_string)) == 1 {
        return String::new();
    }
    let possible_input_size = find_possible_input_size(input);
    for input_size in (possible_input_size - block_size)..(possible_input_size + block_size + 1) {
        let prefix_size = find_prefix_size(input, input_size);
        let prefix_padding_size = block_size - prefix_size % block_size;

        let mut decrypted_string = String::with_capacity(input_size.into());
        let mut valid_input_size = true;
        for _ in 0..input_size {
            let mut test_input =
                String::with_capacity((prefix_padding_size + input_size + block_size).into());
            for _ in 0..(prefix_padding_size + block_size - decrypted_string.len() % block_size - 1)
            {
                test_input.push('A');
            }
            let mut encrypted_length_to_check = 0;
            let mut possible_characters = HashMap::new();
            for i in 1u8..128u8 {
                let mut test_input_copy = test_input.clone();
                test_input_copy.push_str(&decrypted_string);
                test_input_copy.push(i as char);
                encrypted_length_to_check =
                    (block_size - decrypted_string.len() % block_size + decrypted_string.len()) * 2;
                //encrypted_length_to_check = test_input_copy.len() * 2;
                let encrypted_of_test =
                    challenge6::base64_to_hex(&encryption_oracle(&test_input_copy));
                let mut key_to_be_inserted = String::with_capacity(encrypted_length_to_check);
                for (j, c) in encrypted_of_test.chars().enumerate() {
                    if j < ((prefix_size + prefix_padding_size) * 2).into() {
                        continue;
                    }
                    if key_to_be_inserted.len() == encrypted_length_to_check {
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
                if i < ((prefix_size + prefix_padding_size) * 2).into() {
                    continue;
                }
                if key_to_check.len() == encrypted_length_to_check {
                    break;
                }
                key_to_check.push(c);
            }
            //println!("{} {} {}" ,test_input, key_to_check, key_to_check.len());
            match possible_characters.get(&key_to_check) {
                Some(value) => decrypted_string.push(*value as char),
                None => valid_input_size = false,
            }
            if !valid_input_size {
                break;
            }
            /*let value = possible_characters.get(&key_to_check).unwrap();
            decrypted_string.push(*value as char);*/
        }
        if !valid_input_size {
            continue;
        }
        return decrypted_string;
    }
    return String::new();
}
