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
const LOWER_MASK: u64 = 0x7FFFFFFF;
const UPPER_MASK: u64 = 0x80000000;

///MT19937 Mersenne Twister RNG with tap function to clone an MT19937
pub struct MT19937 {
    index: usize,
    mt: [u64; N],
}

impl MT19937 {
    pub fn init() -> MT19937 {
        let state = [0u64; N];
        MT19937 {
            index: 0,
            mt: state,
        }
    }

    pub fn tap(&mut self, random_number: u32) {
        let mut y: u64 = (random_number ^ (random_number >> L)).into();

        y = y ^ ((y << T) & C);

        let mask = (1 << S) - 1;
        y = y ^ ((y << S) & (B & (mask << S)));
        y = y ^ ((y << S) & (B & (mask << S * 2)));
        y = y ^ ((y << S) & (B & (mask << S * 3)));
        y = y ^ ((y << S) & (B & (mask << S * 4)));

        y = y ^ (y >> U);
        y = y ^ (y >> U);
        y = y ^ (y >> U);

        self.mt[self.index] = y.into();
        self.index += 1;
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
