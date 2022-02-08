extern crate lazy_static;
extern crate openssl;
use super::super::set1::challenge6;
use super::challenge11;
use super::challenge9;
use lazy_static::lazy_static;
use openssl::symm::*;

lazy_static! {
    static ref KEY: String = challenge11::generate_aes_key();
}

/// parse key1=value1&key2=value2&.....
pub fn kv_parse(input: &str) -> String {
    let input_chars: Vec<char> = input.chars().collect();
    let mut keys: Vec<String> = Vec::new();
    let mut values: Vec<String> = Vec::new();
    let mut key_phase = true;
    let mut key: String = String::new();
    let mut value: String = String::new();
    for c in input_chars.iter() {
        if *c == '=' {
            key_phase = false;
        } else if *c == '&' {
            keys.push(key);
            values.push(value);
            key = String::new();
            value = String::new();
            key_phase = true;
        } else {
            if key_phase {
                key.push(*c);
            } else {
                value.push(*c);
            }
        }
    }
    keys.push(key);
    values.push(value);
    let mut object = String::new();
    object.push('{');
    for i in 0..keys.len() {
        object.push_str(&keys[i]);
        object.push(':');
        object.push(' ');
        object.push('\'');
        object.push_str(&values[i]);
        object.push('\'');
        if i != keys.len() - 1 {
            object.push(',');
        }
    }
    object.push('}');
    object
}

///use email to return encoded profile
fn profile_for(email: &str) -> String {
    let mut filtered_email = String::with_capacity(email.len());
    let email_chars: Vec<char> = email.chars().collect();
    for c in email_chars.iter() {
        if *c != '&' && *c != '=' {
            filtered_email.push(*c);
        }
    }
    format!("email={}&uid=10&role=user", filtered_email)
}

/// encrypt with consistent unknown key via AES-128 ECB mode
pub fn encryption_oracle(plaintext: &str) -> String {
    let key = KEY.clone();
    let encrypted = challenge11::encrypt_string_aes128_ecb(plaintext, &key);
    encrypted
}

///decrypt and decode the profile
pub fn decrypt_encoded_profile(cipher_bytes: &Vec<u8>) -> String {
    let key = KEY.clone();
    let cipher = Cipher::aes_128_ecb();
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, &key.as_bytes(), None).unwrap();
    let mut output = vec![0 as u8; cipher_bytes.len() + cipher.block_size()];
    match decrypter.update(&cipher_bytes, &mut output) {
        Ok(s) => {
            let tl = decrypter.finalize(&mut output[s..]).unwrap();
            output.truncate(s + tl);
            let decrypted = String::from_utf8(output).unwrap();
            kv_parse(&decrypted)
        }
        Err(_) => String::new(),
    }
}
/// change role to admin in encrypted profile generated from a crafted email id  
pub fn ecb_cut_and_paste() -> String {
    let crafted_block = challenge9::pkcs7_padding("admin", 16);
    let mut email_id = String::new();
    email_id.push_str("crypt@abc."); // 10 bytes
    email_id.push_str(&crafted_block);
    email_id.push_str("com"); // 3 bytes
    let encrypted_encoded_profile =
        challenge6::base64_to_hex(&encryption_oracle(&profile_for(&email_id)));
    let ee_profile_chars: Vec<char> = encrypted_encoded_profile.chars().collect();
    let mut cipher_bytes: Vec<u8> = Vec::with_capacity(ee_profile_chars.len() / 2);
    let mut index = 0;
    while index < ee_profile_chars.len() {
        let nibble0 = ee_profile_chars[index].to_digit(16).unwrap();
        let nibble1 = ee_profile_chars[index + 1].to_digit(16).unwrap();
        cipher_bytes.push((nibble0 << 4 | nibble1).try_into().unwrap());
        index += 2;
    }

    let mut cut_and_paste_profile = Vec::with_capacity(cipher_bytes.len());
    for i in 0..16 {
        cut_and_paste_profile.push(cipher_bytes[i]);
    }
    for i in 32..48 {
        cut_and_paste_profile.push(cipher_bytes[i]);
    }
    for i in 16..32 {
        cut_and_paste_profile.push(cipher_bytes[i]);
    }
    decrypt_encoded_profile(&cut_and_paste_profile)
}
