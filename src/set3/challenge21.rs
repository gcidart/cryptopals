const W: u8 = 32;
const N: usize = 624;
const M: usize = 397;
const A: u64 = 0x9908B0DF;
const U: u8 = 11;
const D: u64 = 0xFFFFFFFF;
const S: u8 = 7;
const B: u64 = 0x9D2C5680;
const T: u8 = 15;
const C: u64 = 0xEFC60000;
const L: u8 = 18;
const F: u64 = 1812433253;
const LOWER_MASK: u64 = 0x7FFFFFFF;
const UPPER_MASK: u64 = 0x80000000;

///MT19937 Mersenne Twister RNG
pub struct MT19937 {
    index: usize,
    mt: [u64; N],
}

impl MT19937 {
    pub fn seed_mt(seed: u32) -> MT19937 {
        let mut state = [0u64; N];
        state[0] = seed as u64;
        for i in 1..(N - 1) {
            state[i] = ((state[i - 1] ^ (state[i - 1] >> (W - 2))) * F + (i as u64)) & 0xFFFFFFFF;
        }
        MT19937 {
            index: N,
            mt: state,
        }
    }

    pub fn extract_number(&mut self) -> u32 {
        if self.index == N {
            self.twist();
        }
        let mut y = self.mt[self.index];
        y = y ^ ((y >> U) & D);
        y = y ^ ((y << S) & B);
        y = y ^ ((y << T) & C);
        y = y ^ (y >> L);

        self.index += 1;
        (y & (0xFFFFFFFF)).try_into().unwrap()
    }

    fn twist(&mut self) {
        for i in 0..(N - 1) {
            let x = (self.mt[i] & UPPER_MASK) + (self.mt[(i + 1) % N] & LOWER_MASK);
            let mut xa = x >> 1;
            if x % 2 != 0 {
                xa = xa ^ A;
            }
            self.mt[i] = self.mt[(i + M) % N] ^ xa;
        }
        self.index = 0;
    }
}
