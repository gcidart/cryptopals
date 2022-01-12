/// decrypts the hex encoded string which has been XOR'd against a single character
pub fn single_byte_xor_cipher(hex_str: &str) -> String {
    let hex_alphabet: Vec<char> = "0123456789abcdef".chars().collect();
    let mut index;
    let mut max_score = 0;
    let mut single_char = 0;
    let mut char_it = 0;
    while char_it <= 0xff {
        let mut hex_string = String::from(hex_str);
        let mut buf = String::with_capacity(hex_str.len());
        index = 0;
        while index + 1 < hex_str.len() {
            let nibble0 = hex_string.pop().unwrap().to_digit(16).unwrap();
            let nibble1 = hex_string.pop().unwrap().to_digit(16).unwrap();
            let combined_nibble = (nibble1 << 4 | nibble0) ^ char_it;
            let idx0 = (combined_nibble & 0xf) as usize;
            let idx1 = (combined_nibble >> 4) as usize;
            let hex_char = hex_alphabet[idx1];
            buf.push(hex_char);
            let hex_char = hex_alphabet[idx0];
            buf.push(hex_char);
            index = index + 2;
        }
        let this_score = score_string(&buf);
        //println!("{} {} {}", buf, this_score, char_it);
        if this_score > max_score {
            max_score = this_score;
            single_char = char_it;
        }
        char_it += 1;
    }
    //println!("{} ", single_char);
    let mut hex_string = String::from(hex_str);
    let mut buf = String::with_capacity(hex_str.len());
    index = 0;
    while index < hex_str.len() {
        let nibble0 = hex_string.pop().unwrap().to_digit(16).unwrap();
        let nibble1 = hex_string.pop().unwrap().to_digit(16).unwrap();
        let combined_nibble = (nibble1 << 4 | nibble0) ^ single_char;
        buf.push(combined_nibble as u8 as char);
        // Commented portion to be used if hex string is needed
        /*let idx0 = (combined_nibble & 0xf) as usize;
        let idx1 = (combined_nibble >> 4) as usize;
        let hex_char = hex_alphabet[idx0];
        buf.push(hex_char);
        let hex_char = hex_alphabet[idx1];
        buf.push(hex_char);*/
        index = index + 2;
    }

    buf.chars().rev().collect::<String>()
}

// returns the number of characters in the string
fn score_string(hex_str: &str) -> u32 {
    let mut hex_string = String::from(hex_str);
    let mut index = 0;
    let mut score = 0;
    while index < hex_str.len() {
        let nibble0 = hex_string.pop().unwrap();
        let nibble1 = hex_string.pop().unwrap();
        if let Some(i) = nibble0.to_digit(16) {
            if let Some(j) = nibble1.to_digit(16) {
                let combined_nibble = j << 4 | i;
                if combined_nibble >= 97 && combined_nibble <= 122 {
                    score += 1;
                }
                if combined_nibble >= 65 && combined_nibble <= 90 {
                    score += 1;
                }
                if combined_nibble == 32 {
                    score += 1;
                }
            }
        }
        index = index + 2;
    }
    score
}
