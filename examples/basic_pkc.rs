use bincode::{deserialize, serialize};
use serde_derive::{Deserialize, Serialize};
use threshold_crypto::{PublicKey, SecretKey, Signature};

#[derive(Deserialize, Serialize)]
struct SignedMsg {
    msg: Vec<u8>,
    sig: Signature,
}

#[derive(Debug)]
struct KeyPair {
    sk: SecretKey,
    pk: PublicKey,
}

impl KeyPair {
    fn random() -> Self {
        let sk = SecretKey::random();
        let pk = sk.public_key();
        KeyPair { sk, pk }
    }

    fn create_signed_msg(&self, msg: &[u8]) -> SignedMsg {
        let sig = self.sk.sign(msg);
        let msg = msg.to_vec();
        SignedMsg { msg, sig }
    }
}

fn main() {
    // Alice and Bob each generate a public/private key-pair.
    //
    // Note: it is against best practices to use the same key-pair for both encryption/decryption
    // and signing. The following example could be interpreted as advocating this, which it is not
    // meant to. This is just a basic example. In this example, Bob's key-pair is used for signing
    // where as Alice's is used for encryption/decryption.
    let alice = KeyPair::random();
    let bob = KeyPair::random();

    // Bob wants to send Alice a message. He signs the plaintext message with his secret key. He
    // then encrypts the signed message with Alice's public key.
    let msg = b"let's get pizza";
    let signed_msg = bob.create_signed_msg(msg);
    let serialized = serialize(&signed_msg).expect("Failed to serialize `SignedMsg`");
    let ciphertext = alice.pk.encrypt(&serialized);

    // Alice receives Bob's encrypted message. She decrypts the message using her secret key. She
    // then verifies that the signature of the plaintext is valid using Bob's public key.
    let decrypted = alice.sk.decrypt(&ciphertext).expect("Invalid ciphertext");
    let deserialized: SignedMsg =
        deserialize(&decrypted).expect("Failed to deserialize bytes to `SignedMsg`");
    assert!(bob.pk.verify(&deserialized.sig, &deserialized.msg));

    // We assert that the message that Alice received is the same message that Bob sent.
    assert_eq!(msg, &deserialized.msg[..]);
}
