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

// FIXME: tests!
impl<E: AsRef<[u8]>> Iterator for BitIterator<E> {
    type Item = bool;

    fn next(&mut self) -> Option<bool> {
        if self.n == 0 {
            None
        } else {
            self.n -= 1;
            let part = self.n / 8;
            let bit = self.n - (8 * part);
            Some(self.t.as_ref()[part] & (1 << bit) > 0)
        }
    }
}
