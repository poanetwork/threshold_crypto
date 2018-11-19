#[derive(Debug, Clone)]
/// An iterator of bits in finite sequential data.
pub struct BitIterator<E> {
    /// Data for iterating over.
    t: E,
    /// The number of remaining bits until the end.
    n: usize,
}

impl<E: AsRef<[u8]>> BitIterator<E> {
    /// Creates a new iterator for the given data and sets the number of remaining bits.
    pub fn new(t: E) -> Self {
        let n = t.as_ref().len() * 8;
        BitIterator { t, n }
    }
}

impl<E: AsRef<[u8]>> Iterator for BitIterator<E> {
    type Item = bool;

    /// Iterates data bits starting with the least significant bit.
    fn next(&mut self) -> Option<bool> {
        if self.n == 0 {
            None
        } else {
            self.n -= 1;
            let byte = self.n / 8;
            let bit = 7 - (self.n - (8 * byte));
            Some(self.t.as_ref()[byte] & (1 << bit) > 0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BitIterator;
    use rand::{self, Rng};

    #[test]
    fn test_bit_iterator() {
        const LEN: usize = 20;
        let mut rng = rand::thread_rng();
        let u: Vec<u8> = (0..LEN).map(|_| rng.gen()).collect();
        let mut bits = BitIterator::new(u.clone());
        let mut v = Vec::new();
        for _byte in 0..LEN {
            let mut o: u8 = 0;
            for bit in 0..8 {
                if let Some(b) = bits.next() {
                    o |= (b as u8) << bit;
                }
            }
            v.push(o);
        }
        v.reverse();
        assert_eq!(u, v);
    }
}
