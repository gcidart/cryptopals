extern crate lazy_static;
use super::super::set2::challenge11;
use super::super::set3::challenge18;
use lazy_static::lazy_static;
use rand::{thread_rng, Rng};

lazy_static! {
    static ref KEY: String = challenge11::generate_aes_key();
    static ref NONCE: u64 = thread_rng().gen_range(5..=u64::MAX);
}

/// add a prefix and suffix, remove characters ';' and '='
/// and encrypt with consistent unknown key via AES 128 CTR
fn encryption_oracle(plaintext: &str) -> Vec<u8> {
    let key = KEY.clone();
    let prefix = "comment1=cooking%20MCs;userdata=";
    let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";
    let mut mod_plaintext = String::with_capacity(plaintext.len() + prefix.len() + suffix.len());
    mod_plaintext.push_str(prefix);
    for (_, c) in plaintext.chars().enumerate() {
        if c != ';' && c != '=' {
            mod_plaintext.push(c);
        }
    }
    mod_plaintext.push_str(suffix);
    let encrypted = challenge18::ctr_function(&mod_plaintext.as_bytes(), &key.as_bytes(), 0);
    encrypted
}

///decrypt under AES-128 CTR and check for ";admin=true;"
fn decrypt_and_check_for_admin(ciphertext: &[u8]) -> bool {
    let key = KEY.clone();
    let decrypted = challenge18::ctr_function(&ciphertext, &key.as_bytes(), 0);
    let decrypted = String::from_utf8_lossy(&decrypted).to_string();
    decrypted.contains(";admin=true;")
}

/// modify ciphertext so that ";admin=true;" is present in the decrypted string
pub fn ctr_bitflipping_attack() -> bool {
    if decrypt_and_check_for_admin(&encryption_oracle("data;admin=true")) {
        return false;
    }
    let ciphertext = encryption_oracle("data-admin-true");
    for i in 0..(ciphertext.len() - 16) {
        let mut mod_ciphertext: Vec<u8> = Vec::with_capacity(ciphertext.len());
        for j in 0..ciphertext.len() {
            if i == j {
                // ascii('-') = 0x2d; ascii(';') = 0x3b
                mod_ciphertext.push(ciphertext[j] ^ 0x2d ^ 0x3b);
            } else if (i + 6) == j {
                // ascii('-') = 0x2d; ascii('=') = 0x3d
                mod_ciphertext.push(ciphertext[j] as u8 ^ 0x2d ^ 0x3d);
            } else {
                mod_ciphertext.push(ciphertext[j]);
            }
        }
        if decrypt_and_check_for_admin(&mod_ciphertext) {
            return true;
        }
    }
    return false;
}
