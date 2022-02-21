use super::challenge21;
///given the random number, find out the seed used for MT19937
///assumes that unix timestamp was used in last 2000s as the seed
pub fn crack_mt19937_seed(random_number: u32, unix_timestamp: u64) -> u64 {
    let start = unix_timestamp - 2000;
    for i in start..unix_timestamp {
        let mut rng = challenge21::MT19937::seed_mt(i);
        let pseudo_random_number = rng.extract_number();
        if pseudo_random_number == random_number {
            return i;
        }
    }
    0
}
