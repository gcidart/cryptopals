/// takes two equal length buffers and produces their XOR combination
pub fn fixed_xor(hex_str_a: &str, hex_str_b: &str) -> String {
    let hex_alphabet: Vec<char> = "0123456789abcdef".chars().collect();
    let mut hex_string_a = String::from(hex_str_a);
    let mut hex_string_b = String::from(hex_str_b);
    let mut buf = String::with_capacity(hex_str_a.len());
    let mut index = 0;
    while index < hex_str_a.len() {
        let nibblea = hex_string_a.pop().unwrap().to_digit(16).unwrap();
        let nibbleb = hex_string_b.pop().unwrap().to_digit(16).unwrap();
        let combined_nibble = nibblea ^ nibbleb;
        let idx = (combined_nibble & 0xf) as usize;
        let hex_char = hex_alphabet[idx];
        index = index + 1;
        buf.push(hex_char);
    }

    buf.chars().rev().collect::<String>()
}
