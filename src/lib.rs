mod set1;
mod set2;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hex_to_base64_test() {
        let test_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let test_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(test_output, set1::challenge1::hex_to_base64(test_input))
    }
    #[test]
    fn fixed_xor_test() {
        let test_inputa = "1c0111001f010100061a024b53535009181c";
        let test_inputb = "686974207468652062756c6c277320657965";
        let test_output = "746865206b696420646f6e277420706c6179";
        assert_eq!(
            test_output,
            set1::challenge2::fixed_xor(test_inputa, test_inputb)
        )
    }
    #[test]
    fn single_byte_xor_cipher_test() {
        let test_input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let test_output = "Cooking MC's like a pound of bacon";
        assert_eq!(
            test_output,
            set1::challenge3::single_byte_xor_cipher(test_input)
        )
    }
    #[test]
    fn detect_single_character_xor_test() {
        use std::fs::File;
        use std::io::{BufRead, BufReader};
        let file = File::open("src/s1ch4.txt").expect("no such file");
        let buf = BufReader::new(file);
        let test_input = buf
            .lines()
            .map(|l| l.expect("Could not parse line"))
            .collect();
        let test_output = "Now that the party is jumping\n";
        assert_eq!(
            test_output,
            set1::challenge4::detect_single_character_xor(test_input)
        )
    }
    #[test]
    fn repeating_key_xor_test() {
        let test_input =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let test_key = "ICE";
        let test_output = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assert_eq!(
            test_output,
            set1::challenge5::repeating_key_xor(test_input, test_key)
        )
    }
    #[test]
    fn hamming_distance_test() {
        assert_eq!(
            37,
            set1::challenge6::hamming_distance("this is a test", "wokka wokka!!!")
        )
    }
    #[test]
    fn break_repeating_key_xor_test() {
        use std::fs::File;
        use std::io::{BufRead, BufReader};
        let file = File::open("src/s1ch6.txt").expect("no such file");
        let output_file = File::open("src/s1ch6_lyrics.txt").expect("no such file");
        let buf = BufReader::new(output_file);
        let test_output: String = buf
            .lines()
            .map(|l| l.expect("Could not parse line"))
            .collect::<Vec<String>>()
            .join("\n");
        assert_eq!(test_output, set1::challenge6::break_repeating_key_xor(file))
    }
    #[test]
    fn decrypt_aes128_ecb_test() {
        use std::fs::File;
        use std::io::{BufRead, BufReader};
        let file = File::open("src/s1ch7.txt").expect("no such file");
        let key = "YELLOW SUBMARINE";
        let output_file = File::open("src/s1ch6_lyrics.txt").expect("no such file");
        let buf = BufReader::new(output_file);
        let test_output: String = buf
            .lines()
            .map(|l| l.expect("Could not parse line"))
            .collect::<Vec<String>>()
            .join("\n");
        assert_eq!(test_output, set1::challenge7::decrypt_aes128_ecb(file, key))
    }
    #[test]
    fn detect_aes_in_ecb_mode_test() {
        use std::fs::File;
        use std::io::{BufRead, BufReader};
        let file = File::open("src/s1ch8.txt").expect("no such file");
        let buf = BufReader::new(file);
        let test_input = buf
            .lines()
            .map(|l| l.expect("Could not parse line"))
            .collect();
        let test_output = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
        assert_eq!(
            test_output,
            set1::challenge8::detect_aes_in_ecb_mode(test_input)
        )
    }
    #[test]
    fn pkcs7_padding_test() {
        assert_eq!(
            "YELLOW SUBMARINE\x04\x04\x04\x04",
            set2::challenge9::pkcs7_padding("YELLOW SUBMARINE", 20)
        )
    }
    #[test]
    fn decrypt_aes128_cbc_test() {
        use std::fs::File;
        use std::io::{BufRead, BufReader};
        let file = File::open("src/txt/s2ch10.txt").expect("no such file");
        let key = "YELLOW SUBMARINE";
        let output_file = File::open("src/s1ch6_lyrics.txt").expect("no such file");
        let buf = BufReader::new(output_file);
        let test_output: String = buf
            .lines()
            .map(|l| l.expect("Could not parse line"))
            .collect::<Vec<String>>()
            .join("\n");
        assert_eq!(
            test_output,
            set2::challenge10::decrypt_aes128_cbc(file, key)
        )
    }
}
