/// strip the padding bytes for a string input
pub fn pkcs7_padding_strip(padded_text: &str) -> Result<String, &'static str> {
    let padded_chars: Vec<char> = padded_text.chars().collect();
    let last_byte = padded_chars[padded_chars.len() - 1];
    let bytes_to_be_stripped = last_byte as u8 as usize;
    if bytes_to_be_stripped > padded_text.len() || bytes_to_be_stripped == 0 {
        return Err("invalid padding");
    }
    let mut index = padded_chars.len() - 1;
    for _ in 0..bytes_to_be_stripped {
        if padded_chars[index] != last_byte {
            return Err("invalid padding");
        }
        index -= 1;
    }
    let mut stripped_string = String::with_capacity(padded_text.len() - bytes_to_be_stripped);
    for i in 0..(padded_text.len() - bytes_to_be_stripped) {
        stripped_string.push(padded_chars[i]);
    }
    Ok(stripped_string)
}
/// strip the padding bytes for a slice input
pub fn pkcs7_padding_bytes_strip(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    let last_byte = input[input.len() - 1];
    let bytes_to_be_stripped = last_byte as usize;
    if bytes_to_be_stripped > input.len() || bytes_to_be_stripped == 0 {
        return Err("invalid padding");
    }
    let mut index = input.len() - 1;
    for _ in 0..bytes_to_be_stripped {
        if input[index] != last_byte {
            return Err("invalid padding");
        }
        index -= 1;
    }
    let mut output = Vec::with_capacity(input.len() - bytes_to_be_stripped);
    for i in 0..(input.len() - bytes_to_be_stripped) {
        output.push(input[i]);
    }
    Ok(output)
}
