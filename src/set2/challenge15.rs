///  pad any block to a specific block length, by appending the number of bytes of padding to the
///  end of the block
pub fn pkcs7_padding_strip(padded_text: &str) -> Result<String, &'static str> {
    let padded_chars: Vec<char> = padded_text.chars().collect();
    let last_byte = padded_chars[padded_chars.len() - 1];
    let bytes_to_be_stripped = last_byte as u8 as usize;
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
