mod set1;
mod set2;
mod set3;
mod set4;

use std::fs::File;
use std::io::{BufRead, BufReader};

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
    #[test]
    fn encrypt_aes128_ecb_test() {
        let file = File::open("src/s1ch6_lyrics.txt").expect("no such file");
        let key = "YELLOW SUBMARINE";
        let output_file = File::open("src/s1ch7.txt").expect("no such file");
        let buf = BufReader::new(output_file);
        let test_output: String = buf
            .lines()
            .map(|l| l.expect("Could not parse line"))
            .collect::<Vec<String>>()
            .join("");
        assert_eq!(
            test_output,
            set2::challenge11::encrypt_aes128_ecb(file, key)
        )
    }
    #[test]
    fn encrypt_aes128_cbc_test() {
        let file = File::open("src/s1ch6_lyrics.txt").expect("no such file");
        let key = "YELLOW SUBMARINE";
        let output_file = File::open("src/txt/s2ch10.txt").expect("no such file");
        let buf = BufReader::new(output_file);
        let test_output: String = buf
            .lines()
            .map(|l| l.expect("Could not parse line"))
            .collect::<Vec<String>>()
            .join("");
        assert_eq!(
            test_output,
            set2::challenge11::encrypt_aes128_cbc(file, key)
        )
    }
    #[test]
    fn detect_encryption_mode_test() {
        let mut input = String::with_capacity(96);
        for _ in 0..96 {
            input.push('A')
        }
        for _ in 0..10 {
            let (encrypted_text, choice) = set2::challenge11::encryption_oracle(&input);
            assert_eq!(
                choice,
                set2::challenge11::detect_encryption_mode(&encrypted_text)
            )
        }
    }
    #[test]
    fn byte_at_a_time_ecb_decryption_simple_test() {
        let base64_input = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
        YnkK";
        let hex_input = set1::challenge6::base64_to_hex(base64_input);
        let hex_chars: Vec<char> = hex_input.chars().collect();
        let mut hex_bytes: Vec<u8> = Vec::with_capacity(hex_input.len() / 2);
        let mut index = 0;
        while index + 1 < hex_chars.len() {
            let nibble0 = hex_chars[index].to_digit(16).unwrap();
            let nibble1 = hex_chars[index + 1].to_digit(16).unwrap();
            hex_bytes.push((nibble0 << 4 | nibble1) as u8);
            index += 2;
        }
        let input = String::from_utf8(hex_bytes).unwrap();
        assert_eq!(
            input,
            set2::challenge12::byte_at_a_time_ecb_decryption_simple(&input)
        )
    }
    #[test]
    fn kv_parse_test() {
        let input = "foo=bar&baz=qux&zap=zazzle";
        let output = "{\
          foo: 'bar',\
          baz: 'qux',\
          zap: 'zazzle'\
          }";
        assert_eq!(output, set2::challenge13::kv_parse(&input))
    }
    #[test]
    fn ecb_cut_and_paste_test() {
        let output = "{\
          email: 'crypt@abc.com',\
          uid: '10',\
          role: 'admin'\
          }";
        assert_eq!(output, set2::challenge13::ecb_cut_and_paste())
    }
    #[test]
    fn byte_at_a_time_ecb_decryption_hard_test() {
        let base64_input = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
        YnkK";
        let hex_input = set1::challenge6::base64_to_hex(base64_input);
        let hex_chars: Vec<char> = hex_input.chars().collect();
        let mut hex_bytes: Vec<u8> = Vec::with_capacity(hex_input.len() / 2);
        let mut index = 0;
        while index + 1 < hex_chars.len() {
            let nibble0 = hex_chars[index].to_digit(16).unwrap();
            let nibble1 = hex_chars[index + 1].to_digit(16).unwrap();
            hex_bytes.push((nibble0 << 4 | nibble1) as u8);
            index += 2;
        }
        let input = String::from_utf8(hex_bytes).unwrap();
        assert_eq!(
            input,
            set2::challenge14::byte_at_a_time_ecb_decryption_hard(&input)
        )
    }
    #[test]
    fn pkcs7_padding_strip_test() {
        assert_eq!(
            Ok("ICE ICE BABY".to_string()),
            set2::challenge15::pkcs7_padding_strip("ICE ICE BABY\x04\x04\x04\x04")
        );
        assert_eq!(
            Err("invalid padding"),
            set2::challenge15::pkcs7_padding_strip("ICE ICE BABY\x05\x05\x05\x05")
        );
        assert_eq!(
            Err("invalid padding"),
            set2::challenge15::pkcs7_padding_strip("ICE ICE BABY\x01\x02\x03\x04")
        )
    }
    #[test]
    fn cbc_bitflipping_attack_test() {
        assert_eq!(true, set2::challenge16::cbc_bitflipping_attack())
    }
    #[test]
    fn cbc_padding_oracle_test() {
        let file = File::open("src/txt/s3ch17.txt").expect("no such file");
        let buf = BufReader::new(file);
        let test_inputs: Vec<String> = buf
            .lines()
            .map(|l| l.expect("Could not parse line"))
            .collect();
        for input in test_inputs.iter() {
            let decoded_bytes =
                set2::challenge14::hex_text_to_hex_bytes(&set1::challenge6::base64_to_hex(&input));
            let key = set2::challenge11::generate_aes_key();
            let test_output = String::from_utf8(decoded_bytes).unwrap();
            let ciphertext = set2::challenge11::encrypt_string_aes128_cbc(&test_output, &key);
            assert_eq!(
                test_output,
                set3::challenge17::cbc_padding_oracle(&ciphertext, &key.as_bytes())
            )
        }
    }
    #[test]
    fn ctr_test() {
        let input = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
        let key = "YELLOW SUBMARINE";
        let hex_input =
            set2::challenge14::hex_text_to_hex_bytes(&set1::challenge6::base64_to_hex(&input));
        let decrypted_bytes = set3::challenge18::ctr_function(&hex_input, &key.as_bytes(), 0);
        let test_output = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ";
        assert_eq!(
            test_output,
            String::from_utf8_lossy(&decrypted_bytes).to_string()
        );
        let encrypted_bytes = set3::challenge18::ctr_function(&decrypted_bytes, &key.as_bytes(), 0);
        assert_eq!(input, set1::challenge1::bytes_to_base64(&encrypted_bytes));
    }
    #[test]
    fn break_fixed_nonce_ctr_using_substitutions_test() {
        let file = File::open("src/txt/s3ch19.txt").expect("no such file");
        let buf = BufReader::new(file);
        let test_inputs: Vec<String> = buf
            .lines()
            .map(|l| l.expect("Could not parse line"))
            .collect();
        let key = set2::challenge11::generate_aes_key();
        let mut ciphers: Vec<Vec<u8>> = Vec::new();
        let mut inputs = Vec::new();
        for input in test_inputs.iter() {
            let input_bytes =
                set2::challenge14::hex_text_to_hex_bytes(&set1::challenge6::base64_to_hex(&input));
            let encrypted_bytes = set3::challenge18::ctr_function(&input_bytes, &key.as_bytes(), 0);
            ciphers.push(encrypted_bytes);
            let input = String::from_utf8(input_bytes).unwrap();
            //println!("{} ", &input);
            inputs.push(input);
        }
        let decrypted_outputs =
            set3::challenge19::break_fixed_nonce_ctr_using_substitutions(ciphers);
        let mut wrong_chars = 0;
        let mut total_chars = 0;
        for i in 0..inputs.len() {
            let input_chars: Vec<char> = inputs[i].chars().collect();
            let output_chars: Vec<char> = decrypted_outputs[i].chars().collect();
            for j in 0..input_chars.len() {
                total_chars += 1;
                if input_chars[j] != output_chars[j] {
                    wrong_chars += 1;
                }
            }
        }
        //println!("{} {}", wrong_chars, total_chars);
        assert_eq!(true, wrong_chars * 10 < total_chars)
    }
    #[test]
    fn break_fixed_nonce_ctr_statistically_test() {
        let file = File::open("src/txt/s3ch20.txt").expect("no such file");
        let buf = BufReader::new(file);
        let test_inputs: Vec<String> = buf
            .lines()
            .map(|l| l.expect("Could not parse line"))
            .collect();
        let key = set2::challenge11::generate_aes_key();
        let mut ciphers: Vec<Vec<u8>> = Vec::new();
        let mut inputs = Vec::new();
        for input in test_inputs.iter() {
            let input_bytes =
                set2::challenge14::hex_text_to_hex_bytes(&set1::challenge6::base64_to_hex(&input));
            let encrypted_bytes = set3::challenge18::ctr_function(&input_bytes, &key.as_bytes(), 0);
            ciphers.push(encrypted_bytes);
            let input = String::from_utf8(input_bytes).unwrap();
            inputs.push(input);
        }
        let decrypted_outputs = set3::challenge20::break_fixed_nonce_ctr_statistically(ciphers);
        let mut wrong_chars = 0;
        let mut total_chars = 0;
        for i in 0..inputs.len() {
            //println!("{} ", inputs[i]);
            //println!("{} ", decrypted_outputs[i]);
            let input_chars: Vec<char> = inputs[i].chars().collect();
            let output_chars: Vec<char> = decrypted_outputs[i].chars().collect();
            for j in 0..input_chars.len() {
                total_chars += 1;
                if input_chars[j] != output_chars[j] {
                    wrong_chars += 1;
                }
            }
        }
        //println!("{} {}", wrong_chars, total_chars);
        assert_eq!(true, wrong_chars * 50 < total_chars)
    }
    #[test]
    fn mt19937_rng_test() {
        let mut rng = set3::challenge21::MT19937::seed_mt(0);
        assert_eq!(2357136044, rng.extract_number());
        assert_eq!(2546248239, rng.extract_number());
        assert_eq!(3071714933, rng.extract_number());
        assert_eq!(3626093760, rng.extract_number());
        assert_eq!(2588848963, rng.extract_number());
        assert_eq!(3684848379, rng.extract_number());
    }
    #[test]
    fn crack_mt19937_seed_test() {
        use rand::{thread_rng, Rng};
        use std::time::{SystemTime, UNIX_EPOCH};
        let mut rng = thread_rng();
        let delay1 = rng.gen_range(40..=1000);
        let mut unix_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        unix_timestamp += delay1;
        let mut custom_rng = set3::challenge21::MT19937::seed_mt(unix_timestamp);
        let pseudo_random_number = custom_rng.extract_number();
        let delay2 = rng.gen_range(40..=1000);
        assert_eq!(
            unix_timestamp,
            set3::challenge22::crack_mt19937_seed(pseudo_random_number, unix_timestamp + delay2)
        );
    }
    #[test]
    fn mt19937_rng_clone_test() {
        let mut rng = set3::challenge21::MT19937::seed_mt(0);
        let mut rng_clone = set3::challenge23::MT19937::init();
        for _ in 0..624 {
            rng_clone.tap(rng.extract_number());
        }
        for _ in 0..1500 {
            assert_eq!(rng_clone.extract_number(), rng.extract_number());
        }
    }
    #[test]
    fn mt19937_stream_cipher_test() {
        let input = "YELLOW SUBMARINE";
        let seed = 27343;
        let hex_input = input.as_bytes();
        let encrypted_bytes = set3::challenge24::mt19937_stream_cipher_function(&hex_input, seed);
        let decrypted_bytes =
            set3::challenge24::mt19937_stream_cipher_function(&encrypted_bytes, seed);
        assert_eq!(input, String::from_utf8_lossy(&decrypted_bytes).to_string());
    }
    #[test]
    fn recover_mt19937_stream_cipher_key_test() {
        use rand::{distributions::Alphanumeric, thread_rng, Rng};
        let input = "YELLOW SUBMARINE";
        let num_random_characters = thread_rng().gen_range(5..=10);
        let s: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(num_random_characters)
            .map(char::from)
            .collect();
        let mut modified_input = String::with_capacity(input.len() + num_random_characters);
        modified_input.push_str(&s);
        modified_input.push_str(input);
        let seed = 27343;
        let hex_input = modified_input.as_bytes();
        let encrypted_bytes = set3::challenge24::mt19937_stream_cipher_function(&hex_input, seed);
        let recovered_seed =
            set3::challenge24::recover_mt19937_stream_cipher_key(&encrypted_bytes, &input);
        assert_eq!(seed, recovered_seed);
    }
    #[test]
    fn break_random_access_aes_ctr_test() {
        use rand::{thread_rng, Rng};
        let file = File::open("src/txt/s4ch25.txt").expect("no such file");
        let buf = BufReader::new(file);
        let test_input: String = buf
            .lines()
            .map(|l| l.expect("Could not parse line"))
            .collect::<Vec<String>>()
            .join("");
        let key = set2::challenge11::generate_aes_key();
        let hex_input =
            set2::challenge14::hex_text_to_hex_bytes(&set1::challenge6::base64_to_hex(&test_input));
        let nonce = thread_rng().gen_range(5..=u64::MAX);
        let mut encrypted_bytes =
            set3::challenge18::ctr_function(&hex_input, &key.as_bytes(), nonce);
        let plaintext = String::from_utf8_lossy(&hex_input).to_string();
        let mut ctr_rw = set4::challenge25::RandomAccessCtr::init(&key.as_bytes(), nonce);
        ctr_rw.break_random_access_aes_ctr(&mut encrypted_bytes);
        let recovered_plaintext = String::from_utf8_lossy(&encrypted_bytes).to_string();
        assert_eq!(plaintext, recovered_plaintext);
    }
    #[test]
    fn ctr_bitflipping_attack_test() {
        assert_eq!(true, set4::challenge26::ctr_bitflipping_attack())
    }
}
