# Examples

- [`Threshold Encryption`](threshold_enc.rs) - Demonstrates how to encrypt a
message to a group of actors with a master public-key, where the number of
actors collaborating in the decryption process must exceed a given threshold
number before the ciphertext can be successfully decrypted. This example also
demonstrates the idea of a "trusted dealer", i.e. some trusted entity that is
responsible for generating the keys.

