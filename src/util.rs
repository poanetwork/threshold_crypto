use tiny_keccak::{Hasher, Sha3};

pub(crate) fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut sha3 = Sha3::v256();
    sha3.update(data);
    let mut output = [0u8; 32];
    sha3.finalize(&mut output);
    output
}
