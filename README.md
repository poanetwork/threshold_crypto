# threshold_crypto

[![Build Status](https://travis-ci.org/poanetwork/threshold_crypto.svg?branch=master)](https://travis-ci.org/poanetwork/threshold_crypto)

A pairing-based threshold cryptosystem for collaborative decryption and
signatures.

Provides constructors for encrypted message handling within a public key
encryption system. It utilizes the pairing elliptic curve library to create
and enable reconstruction of public and private key shares.

In a network environment, messages are signed and encrypted, and key and
signature shares are distributed to network participants. A message can be
decrypted and authenticated only with cooperation from at least `threshold +
1` nodes.

## Usage

`Cargo.toml`:

```toml
[dependencies]
rand = "0.4"
threshold_crypto = { version = "0.1", git = "https://github.com/poanetwork/threshold_crypto" }
```

`main.rs`:

```rust
extern crate rand;
extern crate threshold_crypto;

use threshold_crypto::SecretKey;

/// Very basic secret key usage.
fn main() {
    let sk0: SecretKey = rand::random();
    let sk1: SecretKey = rand::random();

    let pk0 = sk0.public_key();

    let msg0 = b"Real news";
    let msg1 = b"Fake news";

    assert!(pk0.verify(&sk0.sign(msg0), msg0));
    assert!(!pk0.verify(&sk1.sign(msg0), msg0)); // Wrong key.
    assert!(!pk0.verify(&sk0.sign(msg1), msg0)); // Wrong message.
}
```

### More Examples

Run examples from the [`examples`](examples) directory using:

```
$ MLOCK_SECRETS=false cargo run --example <example name>
```

Also see the
[distributed_key_generation](https://github.com/poanetwork/threshold_crypto/blob/d81953b55d181311c2a4eed2b6c34059fcf3fdae/src/poly.rs#L967)
test.

## More Details

The basic usage outline is: choose a threshold value t, create a key set, then
distribute N secret key shares among the participants and publish the public
master key. A third party can now encrypt a message to the public master key
and any set of `t + 1` participants *(but no fewer!)* can collaborate to
decrypt it. Also, any `t + 1` participants can collaborate to sign a message,
producing a signature that can be verified against the public master key.

This cryptosystem has the property that signatures are unique, i.e.
independent of which particular participants produced it. If `S1` and `S2` are
signatures for the same message, produced by two different sets of `t + 1`
secret key share holders each, then they won't just both be valid, but in fact
equal. This is useful in some applications, for example it allows using the
signature of a message as a pseudorandom number that is unknown to anyone
until `t + 1` participants agree to reveal it.

In its simplest form, threshold cryptography requires a trusted dealer who
produces the secret key shares and distributes them. However, there are ways
to produce the keys themselves in a way that guarantees that nobody except the
corresponding participant knows their secret in the end, and this crate
includes the basic tools to implement such a *Distributed Key Generation*
scheme.

One major application for this library is within distributed networks that
must tolerate up to `t` adversarial (malicious or faulty) nodes. Because `t +
1` nodes are required to sign or reveal information, messages can be trusted
by third-parties as representing the consensus of the network.

## Performance

Benchmarking functionality is kept in the [`benches` directory](benches). You
can run the benchmarks with the following command:

```
$ RUSTFLAGS="-C target_cpu=native" cargo bench
```

We use the [`criterion`](https://crates.io/crates/criterion) benchmarking library.

## License

Licensed under either of:

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

See the [CONTRIBUTING](CONTRIBUTING.md) document for contribution, testing and
pull request protocol.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
