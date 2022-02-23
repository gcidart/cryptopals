use super::challenge21;
/// 16-bit seed is used to seed the MT19937 Random Number Generator
/// MT19937 RNG is used to generate the keystream
/// can be used for encryption or decryption
pub fn mt19937_stream_cipher_function(input: &[u8], seed: u16) -> Vec<u8> {
    let mut rng = challenge21::MT19937::seed_mt(seed.into());
    let mut index = 0;
    let mut output = Vec::with_capacity(input.len());
    while index < input.len() {
        let keystream = rng.extract_number();
        let keystream_be_bytes = keystream.to_be_bytes();
        for i in 0..4 {
            if index + i >= input.len() {
                break;
            }
            output.push(input[index + i] ^ keystream_be_bytes[i]);
        }
        index += 4;
    }
    output
}

pub fn recover_mt19937_stream_cipher_key(encrypted_bytes: &[u8], plaintext_suffix: &str) -> u16 {
    let plaintext_suffix_bytes = plaintext_suffix.as_bytes();
    for possible_seed in 0..=u16::MAX {
        let decrypted_bytes = mt19937_stream_cipher_function(encrypted_bytes, possible_seed);
        let mut i = decrypted_bytes.len() - 1;
        let mut j = plaintext_suffix_bytes.len() - 1;
        loop {
            if decrypted_bytes[i] != plaintext_suffix_bytes[j] {
                break;
            }
            if j == 0 {
                return possible_seed;
            }
            i -= 1;
            j -= 1;
        }
    }
    return 0;
}
