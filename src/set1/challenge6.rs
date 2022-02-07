use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

/// decrypt the file whose contents are base64-encoded after encrypting with repeating-key xor
pub fn break_repeating_key_xor(file: File) -> String {
    use super::challenge3;
    use super::challenge4;
    let hex_text = get_hex_text_from_file(file);
    let mut hamming_vec = Vec::with_capacity(100);
    let mut keysize = 2;
    while keysize <= 100 {
        let string1 = &hex_text[..keysize * 2];
        let string2 = &hex_text[2 * keysize..4 * keysize];
        hamming_vec.push((
            (hamming_distance(string1, string2) as f32) / (keysize as f32),
            keysize,
        ));
        keysize += 1;
    }
    hamming_vec.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let mut num_keysize = 0;
    let hex_text_chars: Vec<char> = hex_text.chars().collect();
    let mut max_score = 0;
    let mut decoded_string = String::with_capacity(hex_text_chars.len());
    while num_keysize < 10 {
        keysize = hamming_vec[num_keysize].1;
        let mut transpose_strings = Vec::with_capacity(keysize);
        let mut numstrings = 0;
        while numstrings < keysize {
            let mut temp_string = String::new();
            let mut idx = 0 + numstrings * 2;
            while idx + 1 < hex_text_chars.len() {
                temp_string.push(hex_text_chars[idx]);
                temp_string.push(hex_text_chars[idx + 1]);
                idx += 2 * keysize;
            }
            transpose_strings.push(temp_string);
            numstrings += 1;
        }
        let mut transpose_strings_decoded = Vec::with_capacity(keysize);
        for s in transpose_strings {
            transpose_strings_decoded.push(challenge3::single_byte_xor_cipher(&s));
        }
        let mut candidate_vec = Vec::new();
        candidate_vec.resize(hex_text_chars.len() / 2, ' ');
        numstrings = 0;
        while numstrings < keysize {
            let transpose_str_decoded_chars: Vec<char> =
                transpose_strings_decoded[numstrings].chars().collect();
            let mut i = 0;
            while i < transpose_str_decoded_chars.len() {
                candidate_vec[i * keysize + numstrings] = transpose_str_decoded_chars[i];
                i += 1;
            }
            numstrings += 1;
        }
        let possible_decoded: String = candidate_vec.into_iter().collect();
        let this_score = challenge4::score_string(&possible_decoded);
        if this_score > max_score {
            max_score = this_score;
            decoded_string = possible_decoded;
        }
        num_keysize += 1;
    }

    decoded_string
}

/// find hamming distance between string1 and string2
pub fn hamming_distance(string1: &str, string2: &str) -> u32 {
    use std::cmp;
    let string1_chars: Vec<char> = string1.chars().collect();
    let string2_chars: Vec<char> = string2.chars().collect();
    let mut index = 0;
    let mut dist = 0;
    while index < cmp::min(string1_chars.len(), string2_chars.len()) {
        let b = (string1_chars[index] as u8) ^ (string2_chars[index] as u8);
        dist += b.count_ones();
        index += 1;
    }
    if string2_chars.len() < string1_chars.len() {
        while index < string1_chars.len() {
            let b = string1_chars[index] as u8;
            dist += b.count_ones();
            index += 1;
        }
    } else {
        while index < string2_chars.len() {
            let b = string2_chars[index] as u8;
            dist += b.count_ones();
            index += 1;
        }
    }
    dist
}

/// Read base64 encoded text from file and return hex string
pub fn get_hex_text_from_file(file: File) -> String {
    let buf = BufReader::new(file);
    let test_input: String = buf
        .lines()
        .map(|l| l.expect("Could not parse line"))
        .collect::<Vec<String>>()
        .join("");
    base64_to_hex(&test_input)
}

/// convert base64 to hex
pub fn base64_to_hex(base64_text: &str) -> String {
    let hex_alphabet: Vec<char> = "0123456789abcdef".chars().collect();
    let base64_alphabet: Vec<char> =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            .chars()
            .collect();
    let mut base64_hex_map = HashMap::new();
    let mut i = 0;
    for ch in base64_alphabet {
        base64_hex_map.insert(ch, i);
        i += 1;
    }
    base64_hex_map.insert('=', 0);
    let mut hex_text = String::with_capacity(2 * base64_text.len());
    let line_chars: Vec<char> = base64_text.chars().collect();
    let mut index = 0;
    while index + 3 < line_chars.len() {
        let s0 = base64_hex_map.get(&line_chars[index]).unwrap();
        let s1 = base64_hex_map.get(&line_chars[index + 1]).unwrap();
        let s2 = base64_hex_map.get(&line_chars[index + 2]).unwrap();
        let s3 = base64_hex_map.get(&line_chars[index + 3]).unwrap();
        let b3 = s0 << 6 | s1;
        let nibble0 = b3 >> 8;
        let nibble1 = (b3 >> 4) & 0xf;
        let nibble2 = b3 & 0xf;
        let b3 = s2 << 6 | s3;
        hex_text.push(hex_alphabet[nibble0 as usize]);
        hex_text.push(hex_alphabet[nibble1 as usize]);
        // Account for padding character
        if line_chars[index + 2] != '=' {
            hex_text.push(hex_alphabet[nibble2 as usize]);
            let nibble0 = b3 >> 8;
            let nibble1 = (b3 >> 4) & 0xf;
            let nibble2 = b3 & 0xf;
            hex_text.push(hex_alphabet[nibble0 as usize]);
            if line_chars[index + 3] != '=' {
                hex_text.push(hex_alphabet[nibble1 as usize]);
                hex_text.push(hex_alphabet[nibble2 as usize]);
            }
        }
        index += 4;
    }
    hex_text
}
