///  pad any block to a specific block length, by appending the number of bytes of padding to the
///  end of the block
pub fn pkcs7_padding(plaintext: &str, blocksize: usize) -> String {
    let mut buf = String::from(plaintext);
    let num_padded_bytes = blocksize - buf.len() % blocksize;
    buf.reserve(num_padded_bytes);
    for _i in 0..num_padded_bytes {
        buf.push(num_padded_bytes as u8 as char);
    }
    buf
}
