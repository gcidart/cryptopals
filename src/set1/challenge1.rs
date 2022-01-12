/// Convert hex to base64
pub fn hex_to_base64(hex_str: &str) -> String {
    let base64_alphabet: Vec<char> =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            .chars()
            .collect();
    let mut hex_string = String::from(hex_str);
    let mut buf = String::with_capacity(hex_str.len());
    let mut index = 0;
    while index + 3 <= hex_str.len() {
        let nibble0 = hex_string.pop().unwrap().to_digit(16).unwrap();
        let nibble1 = hex_string.pop().unwrap().to_digit(16).unwrap();
        let nibble2 = hex_string.pop().unwrap().to_digit(16).unwrap();
        let combined_nibble = nibble2 << 8 | nibble1 << 4 | nibble0;
        let idx0 = (combined_nibble & 0x3f) as usize;
        let idx1 = (combined_nibble >> 6) as usize;
        let base64_char0 = base64_alphabet[idx0];
        let base64_char1 = base64_alphabet[idx1];
        index = index + 3;
        buf.push(base64_char0);
        buf.push(base64_char1);
        //println!("{:?} {:?} {:?} {} {} {}", nibble0, nibble1, nibble2, index, base64_char0, base64_char1);
    }

    if index + 2 <= hex_str.len() {
        let nibble0 = hex_string.pop().unwrap().to_digit(16).unwrap();
        let nibble1 = hex_string.pop().unwrap().to_digit(16).unwrap();
        let combined_nibble = nibble1 << 4 | nibble0;
        let idx0 = (combined_nibble & 0x3f) as usize;
        let base64_char0 = base64_alphabet[idx0];
        buf.push(base64_char0);
    } else if index + 1 <= hex_str.len() {
        let nibble0 = hex_string.pop().unwrap().to_digit(16).unwrap();
        let combined_nibble = nibble0;
        let idx0 = (combined_nibble & 0x3f) as usize;
        let base64_char0 = base64_alphabet[idx0];
        buf.push(base64_char0);
    }

    buf.chars().rev().collect::<String>()
}
