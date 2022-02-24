extern crate openssl;
use openssl::symm::*;

pub struct RandomAccessCtr {
    key: [u8; 16],
    nonce: u64,
}

impl RandomAccessCtr {
    pub fn init(key: &[u8], nonce: u64) -> RandomAccessCtr {
        let mut keycopy = [0u8; 16];
        for i in 0..16 {
            keycopy[i] = key[i];
        }
        RandomAccessCtr {
            key: keycopy,
            nonce: nonce,
        }
    }
    ///allows to seek into the ciphertext, decrypt, and re-encrypt with different plaintext bytes
    pub fn edit_aes_ctr_ciphertext(
        &mut self,
        cipherbytes: &mut [u8],
        offset: usize,
        newbytes: &[u8],
    ) {
        let cipher = Cipher::aes_128_ecb();
        let mut counter = offset / cipher.block_size();
        let mut block_idx = offset % cipher.block_size();
        let mut index = offset;
        while index < newbytes.len() {
            let nonce_le_bytes = self.nonce.to_le_bytes();
            let counter_le_bytes = counter.to_le_bytes();
            let mut block_input = Vec::with_capacity(self.key.len());
            for i in 0..8 {
                block_input.push(nonce_le_bytes[i]);
            }
            for i in 0..8 {
                block_input.push(counter_le_bytes[i]);
            }
            let mut block_output = encrypt(cipher, &self.key, None, &block_input).unwrap();
            block_output.resize(cipher.block_size(), 0);
            while block_idx < 16 {
                cipherbytes[index] = newbytes[index - offset] ^ block_output[block_idx];
                block_idx += 1;
                index += 1;
                if index >= newbytes.len() {
                    break;
                }
            }
            block_idx = 0;
            counter += 1;
        }
    }
    ///given random access api for AES CTR, recover the plaintext
    pub fn break_random_access_aes_ctr(&mut self, cipherbytes: &mut [u8]) {
        let mut newbytes = Vec::with_capacity(cipherbytes.len());
        for i in 0..cipherbytes.len() {
            newbytes.push(cipherbytes[i]);
        }
        self.edit_aes_ctr_ciphertext(cipherbytes, 0, &newbytes);
    }
}
