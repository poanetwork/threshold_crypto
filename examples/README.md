# Examples

- [`Threshold Encryption`](threshold_enc.rs) - Demonstrates how to encrypt a
message to a group of actors with a master public-key, where the number of
actors collaborating in the decryption process must exceed a given threshold
number before the ciphertext can be successfully decrypted. This example also
demonstrates the idea of a "trusted dealer", i.e. some trusted entity that is
responsible for generating the keys.

- [`Threshold Signing`](threshold_sig.rs) - Demonstrates how threshold signing
can be used to generate an append-only ledger of chat messages. Each node
running our chat protocol receives and signs messages (using its share of the
network's master secret-key). The network adds a new message to the ledger once
enough nodes (`threshold + 1`) have signed a given message.

