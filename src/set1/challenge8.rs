/// return the one string in vector of hex-encoded ciphertexts  which is encrypted in ECB mode
pub fn detect_aes_in_ecb_mode(ciphertexts: Vec<String>) -> String {
    let mut max_sum_score = 0;
    let mut max_max_score = 0;
    let mut detected_string = String::new();
    for hex_text in ciphertexts {
        let hex_text_chars: Vec<char> = hex_text.chars().collect();
        let mut index = 0;
        let mut hex_text_u8: Vec<u8> = Vec::with_capacity(hex_text_chars.len() / 2);
        while index + 1 < hex_text_chars.len() {
            let nibble1 = hex_text_chars[index].to_digit(16).unwrap();
            let nibble0 = hex_text_chars[index + 1].to_digit(16).unwrap();
            hex_text_u8.push((nibble1 << 4 | nibble0) as u8);
            index += 2;
        }
        index = 0;
        let mut split_text: Vec<Vec<u8>> = Vec::with_capacity(hex_text_u8.len() / 16);
        while index < hex_text_u8.len() {
            let mut temp = Vec::with_capacity(16);
            let mut i = 0;
            while i < 16 {
                temp.push(hex_text_u8[index]);
                i += 1;
                index += 1;
            }
            split_text.push(temp);
        }
        let mut max_score = 0;
        let mut sum_score = 0;
        for i in 0..(hex_text_u8.len() / 16) {
            for j in i + 1..(hex_text_u8.len() / 16) {
                let mut score = 0;
                for k in 0..16 {
                    if split_text[i][k] == split_text[j][k] {
                        score += 1;
                    }
                }
                sum_score = sum_score + score;
                if score > max_score {
                    max_score = score;
                }
            }
        }

        if sum_score > max_sum_score {
            max_sum_score = sum_score;
        }
        if max_score > max_max_score {
            max_max_score = max_score;
            detected_string = hex_text;
        }
    }
    detected_string.to_string()
}
