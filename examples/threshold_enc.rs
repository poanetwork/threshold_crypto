extern crate rand;
extern crate threshold_crypto;

use std::collections::BTreeMap;

use threshold_crypto::{
    Ciphertext, DecryptionShare, PublicKey, PublicKeySet, PublicKeyShare, SecretKeySet,
    SecretKeyShare,
};

// In this example scenario, the `SecretSociety` is the "trusted key dealer". The trusted dealer is
// responsible for key generation. The society creates a master public-key, which anyone can use to
// encrypt a message to the society's members; the society is also responsible for giving each
// actor their respective share of the secret-key.
struct SecretSociety {
    actors: Vec<Actor>,
    pk_set: PublicKeySet,
}

impl SecretSociety {
    // Creates a new `SecretSociety`.
    //
    // # Arguments
    //
    // `n_actors` - the number of operatives in the secret society.
    // `threshold` - the number of operatives that must collaborate in in order to successfully
    // decrypt a message must exceed this `threshold`.
    fn new(n_actors: usize, threshold: usize) -> Self {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(threshold, &mut rng);
        let pk_set = sk_set.public_keys();

        let actors = (0..n_actors)
            .map(|id| {
                let sk_share = sk_set.secret_key_share(id);
                let pk_share = pk_set.public_key_share(id);
                Actor::new(id, sk_share, pk_share)
            }).collect();

        SecretSociety { actors, pk_set }
    }

    // The secret society publishes its public-key to a publicly accessible key server.
    fn publish_public_key(&self) -> PublicKey {
        self.pk_set.public_key()
    }

    fn get_actor(&mut self, id: usize) -> &mut Actor {
        self.actors
            .get_mut(id)
            .expect("No `Actor` exists with that ID")
    }

    // Starts a new meeting of the secret society. Each time the set of actors receive an encrypted
    // message, at least 2 of them (i.e. 1 more than the threshold) must work together to decrypt
    // the ciphertext.
    fn start_decryption_meeting(&self) -> DecryptionMeeting {
        DecryptionMeeting {
            pk_set: self.pk_set.clone(),
            ciphertext: None,
            dec_shares: BTreeMap::new(),
        }
    }
}

// A member of the secret society.
#[derive(Clone, Debug)]
struct Actor {
    id: usize,
    sk_share: SecretKeyShare,
    pk_share: PublicKeyShare,
    msg_inbox: Option<Ciphertext>,
}

impl Actor {
    fn new(id: usize, sk_share: SecretKeyShare, pk_share: PublicKeyShare) -> Self {
        Actor {
            id,
            sk_share,
            pk_share,
            msg_inbox: None,
        }
    }
}

// Sends an encrypted message to an `Actor`.
fn send_msg(actor: &mut Actor, enc_msg: Ciphertext) {
    actor.msg_inbox = Some(enc_msg);
}

// A meeting of the secret society. At this meeting, actors collaborate to decrypt a shared
// ciphertext.
struct DecryptionMeeting {
    pk_set: PublicKeySet,
    ciphertext: Option<Ciphertext>,
    dec_shares: BTreeMap<usize, DecryptionShare>,
}

impl DecryptionMeeting {
    // An actor contributes their decryption share to the decryption process.
    fn accept_decryption_share(&mut self, actor: &mut Actor) {
        let ciphertext = actor.msg_inbox.take().unwrap();

        // Check that the actor's ciphertext is the same that is being decrypted at the meeting.
        // The first actor to arrive at the decryption meeting sets the meeting's ciphertext.
        if let Some(ref meeting_ciphertext) = self.ciphertext {
            if ciphertext != *meeting_ciphertext {
                return;
            }
        } else {
            self.ciphertext = Some(ciphertext.clone());
        }

        let dec_share = actor.sk_share.decrypt_share(&ciphertext).unwrap();
        let dec_share_is_valid = actor
            .pk_share
            .verify_decryption_share(&dec_share, &ciphertext);
        assert!(dec_share_is_valid);
        self.dec_shares.insert(actor.id, dec_share);
    }

    // Tries to decrypt the shared ciphertext using the decryption shares.
    fn decrypt_message(&self) -> Result<Vec<u8>, ()> {
        let ciphertext = self.ciphertext.clone().unwrap();
        self.pk_set
            .decrypt(&self.dec_shares, &ciphertext)
            .map_err(|_| ())
    }
}

fn main() {
    // Create a `SecretSociety` with 3 actors. Any message encrypted with the society's public-key
    // will require 2 or more actors working together to decrypt (i.e. the decryption threshold is
    // 1). Once the secret society has created its master keys, it "deals" a secret-key share and
    // public-key share to each of its operatives. The secret society then publishes its public key
    // to a publicly accessible key-server.
    let mut society = SecretSociety::new(3, 1);
    let pk = society.publish_public_key();

    // Create a named alias for each actor in the secret society.
    let alice = society.get_actor(0).id;
    let bob = society.get_actor(1).id;
    let clara = society.get_actor(2).id;

    // I, the society's benevolent hacker, want to send an important message to each of my
    // comrades. I encrypt my message with the society's public-key, I then send the ciphertext to
    // each of the society's operatives.
    let msg = b"let's get pizza";
    let ciphertext = pk.encrypt(msg);
    send_msg(society.get_actor(alice), ciphertext.clone());
    send_msg(society.get_actor(bob), ciphertext.clone());
    send_msg(society.get_actor(clara), ciphertext.clone());

    // We start a meeting of the secret society. At the meeting, each actor contributes their
    // share of the decryption process to decrypt the ciphertext that they each received.
    let mut meeting = society.start_decryption_meeting();

    // Alice is the first actor to arrive at the meeting, she provides her decryption share. One
    // actor alone cannot decrypt the ciphertext, decryption fails.
    meeting.accept_decryption_share(society.get_actor(alice));
    assert!(meeting.decrypt_message().is_err());

    // Bob joins the meeting and provides his decryption share. Alice and Bob are now collaborating
    // to decrypt the ciphertext, they succeed because the society requires two or more actors for
    // decryption.
    meeting.accept_decryption_share(society.get_actor(bob));
    let mut res = meeting.decrypt_message();
    assert!(res.is_ok());
    assert_eq!(msg, res.unwrap().as_slice());

    // Clara joins the meeting and provides her decryption share. We already are able to decrypt
    // the ciphertext with 2 actors, but let's show that we can with 3 actors as well.
    meeting.accept_decryption_share(society.get_actor(clara));
    res = meeting.decrypt_message();
    assert!(res.is_ok());
    assert_eq!(msg, res.unwrap().as_slice());
}
