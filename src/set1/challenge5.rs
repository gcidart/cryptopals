/// encrpyt line_to_be_encoded by sequentially applying each byte of the xor_key

pub fn repeating_key_xor(line_to_be_encoded: &str, xor_key: &str) -> String {
    let hex_alphabet: Vec<char> = "0123456789abcdef".chars().collect();
    let mut buf = String::with_capacity(2 * line_to_be_encoded.len());
    let key_chars: Vec<char> = xor_key.chars().collect();
    let mut index = 0;
    for ch in line_to_be_encoded.chars() {
        let b = (ch as u8) ^ (key_chars[index] as u8);
        let nibble0 = b & 0xf;
        let nibble1 = b >> 4;
        buf.push(hex_alphabet[nibble1 as usize]);
        buf.push(hex_alphabet[nibble0 as usize]);
        //println!("{} {} {} {}", ch , key_chars[index], nibble0, nibble1);
        index += 1;
        if index == key_chars.len() {
            index = 0;
        }
    }

    buf
}
