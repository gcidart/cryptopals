///by guessing, break bunch of ciphertexts generated using fixed nonce CTR
pub fn break_fixed_nonce_ctr_using_substitutions(ciphers: Vec<Vec<u8>>) -> Vec<String> {
    let mut longest_cipher_length = 0;
    for i in 0..ciphers.len() {
        if longest_cipher_length < ciphers[i].len() {
            longest_cipher_length = ciphers[i].len();
        }
    }
    let mut keystream = Vec::with_capacity(longest_cipher_length);
    let mut index = 0;
    while index < longest_cipher_length {
        let mut max_score = 0;
        let mut optimum_byte = 0;
        for byte in 0..255 {
            let mut score = 0;
            for i in 0..ciphers.len() {
                if index < ciphers[i].len() {
                    let xor_byte = ciphers[i][index] ^ byte;
                    if xor_byte == 32 && index != ciphers[i].len() - 1 {
                        //Space
                        score += 1;
                    }
                    //Uppercase letter
                    if xor_byte >= 65 && xor_byte <= 90 {
                        score += 1;
                    }
                    //Lowercase letter
                    if index != 0 && xor_byte >= 97 && xor_byte <= 122 {
                        score += 1;
                    }
                    if xor_byte < 32 || xor_byte == 127 || (xor_byte >= 35 && xor_byte <= 38) {
                        score -= 100;
                    }
                    if xor_byte >= 40 && xor_byte <= 43 {
                        score -= 100;
                    }
                    //assuming that no numbers are present
                    if xor_byte >= 48 && xor_byte <= 57 {
                        score -= 10;
                    }
                }
            }
            if score > max_score {
                max_score = score;
                optimum_byte = byte;
            }
        }
        keystream.push(optimum_byte);
        index += 1;
    }
    let mut decoded_plaintexts = Vec::new();
    for i in 0..ciphers.len() {
        let mut plaintext_bytes = Vec::with_capacity(ciphers[i].len());
        for j in 0..ciphers[i].len() {
            plaintext_bytes.push(ciphers[i][j] ^ keystream[j]);
        }
        decoded_plaintexts.push(String::from_utf8_lossy(&plaintext_bytes).to_string());
    }
    //println!("{:?}", decoded_plaintexts);

    decoded_plaintexts
}
