# threshold_crypto

[![Build Status](https://travis-ci.org/poanetwork/threshold_crypto.svg?branch=master)](https://travis-ci.org/poanetwork/threshold_crypto)

A pairing-based threshold cryptosystem for collaborative decryption and
signatures.

The `threshold_crypto` crate provides constructors for encrypted message handling. It utilizes the [`pairing`](https://crates.io/crates/pairing) elliptic curve library to create and enable reconstruction of public and private key shares.

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

### Examples

Run examples from the [`examples`](examples) directory using:

```
$ MLOCK_SECRETS=false cargo run --example <example name>
```

Also see the
[distributed_key_generation](https://github.com/poanetwork/threshold_crypto/blob/d81953b55d181311c2a4eed2b6c34059fcf3fdae/src/poly.rs#L967)
test.

### Environment Variables

[`MLOCK_SECRETS`](https://github.com/poanetwork/threshold_crypto/blob/master/src/lib.rs#L51): Sets whether or not the Unix syscall [`mlock`](http://man7.org/linux/man-pages/man2/mlock.2.html) or WinAPI function [`VirtualLock`](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366895(v=vs.85).aspx) is called on portions of memory containing secret values. This option is enabled by default (`MLOCK_SECRETS=true`). Disabling memory locking (`MLOCK_SECRETS=false`) allows secret values to be copied to disk, where they will not be zeroed on drop and may persist indefinitely. **Disabling memory locking should only be done in development and testing.** 

Disabling memory locking is useful because it removes the possibility of tests failing due to reaching the testing system's locked memory limit. For example, if your crate uses `threshold_crypto` and you write a test that maintains hundreds or thousands of secrets in memory simultaneously, you run the risk of reaching your system's allowed number of locked pages, which will cause this library to fail.

## Application Details

The basic usage outline is:
* choose a threshold value `t`
* create a key set
* distribute `N` secret key shares among the participants
* publish the public master key

A third party can now encrypt a message to the public master key
and any set of `t + 1` participants *(but no fewer!)* can collaborate to
decrypt it. Also, any set of `t + 1` participants can collaborate to sign a message,
producing a signature that is verifiable with the public master key.

In this system, a signature is unique and independent of
the set of participants that produced it. If `S1` and `S2` are
signatures for the same message, produced by two different sets of `t + 1`
secret key share holders, both signatures will be valid AND
equal. This is useful in some applications, for example a message signature can serve as a pseudorandom number unknown to anyone until `t + 1` participants agree to reveal it.

In its simplest form, threshold_crypto requires a trusted dealer to
produce and distribute the secret key shares. However, keys can be produced so that only the corresponding participant knows their secret in the end.  This crate
includes the basic tools to implement such a *Distributed Key Generation*
scheme.

A major application for this library is within a distributed network that
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
