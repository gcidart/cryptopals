///  find the string encoded with single character xor
use super::challenge3;
pub fn detect_single_character_xor(hex_str_vec: Vec<String>) -> String {
    let mut max_score = 0;
    let mut buf = String::with_capacity(hex_str_vec[0].len());
    for item in &hex_str_vec {
        let decrypted_string = challenge3::single_byte_xor_cipher(&item);
        //println!("{} {} ", item, decrypted_string);
        let this_score = score_string(&decrypted_string);
        if this_score > max_score {
            max_score = this_score;
            buf = decrypted_string;
        }
    }
    buf
}

// returns the number of characters in the string
pub fn score_string(string_to_be_scored: &str) -> u32 {
    let tbs_string = String::from(string_to_be_scored);
    let mut score = 0;
    for c in tbs_string.chars() {
        if c.is_ascii_alphabetic() {
            score += 1;
        }
        if c == ' ' {
            score += 1;
        }
    }

    score
}
