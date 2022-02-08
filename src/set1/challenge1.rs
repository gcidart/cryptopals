/// Convert hex to base64
pub fn hex_to_base64(hex_str: &str) -> String {
    let base64_alphabet: Vec<char> =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            .chars()
            .collect();
    let mut index = 0;
    let nibbles: Vec<_> = hex_str.chars().collect();
    let mut hex_bytes: Vec<u8> = Vec::with_capacity(hex_str.len() / 2);
    while index + 1 < nibbles.len() {
        let nibble0 = nibbles[index].to_digit(16).unwrap();
        let nibble1 = nibbles[index + 1].to_digit(16).unwrap();
        hex_bytes.push((nibble0 << 4 | nibble1).try_into().unwrap());
        index += 2;
    }
    index = 0;
    let mut buf = String::with_capacity(hex_str.len());
    while index + 3 <= hex_bytes.len() {
        let idx0 = hex_bytes[index] >> 2;
        let idx1 = (hex_bytes[index] & 3) << 4 | (hex_bytes[index + 1] & 0xf0) >> 4;
        let idx2 = (hex_bytes[index + 1] & 0xf) << 2 | (hex_bytes[index + 2] & 0xc0) >> 6;
        let idx3 = hex_bytes[index + 2] & 0x3f;
        buf.push(base64_alphabet[idx0 as usize]);
        buf.push(base64_alphabet[idx1 as usize]);
        buf.push(base64_alphabet[idx2 as usize]);
        buf.push(base64_alphabet[idx3 as usize]);
        index += 3;
    }
    if index + 2 == hex_bytes.len() {
        let idx0 = hex_bytes[index] >> 2;
        let idx1 = (hex_bytes[index] & 3) << 4 | (hex_bytes[index + 1] & 0xf0) >> 4;
        let idx2 = (hex_bytes[index + 1] & 0xf) << 2;
        buf.push(base64_alphabet[idx0 as usize]);
        buf.push(base64_alphabet[idx1 as usize]);
        buf.push(base64_alphabet[idx2 as usize]);
        buf.push('=');
    } else if index + 1 == hex_bytes.len() {
        let idx0 = hex_bytes[index] >> 2;
        let idx1 = (hex_bytes[index] & 3) << 4;
        buf.push(base64_alphabet[idx0 as usize]);
        buf.push(base64_alphabet[idx1 as usize]);
        buf.push('=');
        buf.push('=');
    }
    buf.chars().collect::<String>()
}
