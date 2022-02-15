extern crate openssl;
use openssl::symm::*;

/// Counter(CTR) functoin which takes key and nonce as input
/// output of AES block is XOR'd with input
/// can be used for encryption or decryption
pub fn ctr_function(input: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let mut index = 0;
    let mut counter: u64 = 0;
    let mut output = Vec::with_capacity(input.len() + key.len());
    while index < input.len() {
        let nonce_le_bytes = nonce.to_le_bytes();
        let counter_le_bytes = counter.to_le_bytes();
        let mut block_input = Vec::with_capacity(key.len());
        for i in 0..8 {
            block_input.push(nonce_le_bytes[i]);
        }
        for i in 0..8 {
            block_input.push(counter_le_bytes[i]);
        }
        let mut block_output = encrypt(cipher, key, None, &block_input).unwrap();
        block_output.resize(key.len(), 0);
        output.append(&mut block_output);
        index += 16;
        counter += 1;
    }
    index = 0;
    while index < input.len() {
        output[index] = output[index] ^ input[index];
        index += 1;
    }
    output.resize(index, 0);
    output
}
