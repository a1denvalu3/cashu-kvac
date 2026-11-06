# Anonymous Credentials for Cashu

`cashu-kvac` is an experimental implementation of the cryptographic primitives
behind a Cashu mint using keyed-verification anonymous credentials (KVAC).
It explores credentials that carry hidden amounts and optional spending conditions,
with zero-knowledge proofs for issuance and spending.

The Rust library provides the core cryptography, with WebAssembly bindings for
JavaScript. A Python implementation is also available in [`python/`](python/).

## What it provides

- **Amount and script commitments:** Pedersen commitments hide a credential's
  amount and optional spending conditions.
- **Credential issuance and presentation:** algebraic MACs authenticate those
  commitments, issuance proofs let wallets check the mint's response, and
  randomized presentations let wallets prove ownership to the mint.
- **Transaction proofs:** bootstrap, balance, script equality, and Bulletproof
  range proofs establish the relationships needed for mint, swap, and melt flows.
- **Amount recovery:** recovery helpers recover amounts from commitments when
  the wallet knows the blinding factors and an upper bound on the amounts.

## How it fits together

A wallet creates commitments to its attributes and sends them to the mint with
a fresh issuance nonce. The mint derives a tag from its private key and the
request, then returns a MAC and a proof of issuance. The wallet verifies that
response and keeps the attributes, nonce, tag, and MAC for later use.

To spend a credential, the wallet constructs randomized commitments and proves
that it holds a valid MAC. Balance and range proofs let the mint check the
relationship between inputs and outputs without learning their individual amounts.
Script proofs support carrying spending conditions forward or revealing them.
The mint also tracks nullifiers to prevent double spending.

This repository implements these building blocks; integrating them into a mint
requires the surrounding transaction handling, storage, and spending-condition
validation.

## Documentation

- [Usage guide and runnable Rust examples](docs/usage.md): attributes, issuance,
  hidden and revealed scripts, and a balanced swap with proof verification.
- [Development guide](docs/development.md): building, testing, benchmarks, and
  WebAssembly/JavaScript bindings.
- [Protocol explanation](docs/protocol_explanation.md): definitions and the
  credential construction (work in progress).
- [Deterministic recovery](docs/deterministic_recovery.md): recovering attributes
  and checking whether recovered credentials have been spent.

## Design notes

The construction uses secp256k1 and Pedersen commitments with generators whose
discrete logarithm relationships are unknown. It reuses the amount attribute's
blinding factor for presentation randomization, avoiding a separate serial proof.
The mint can also tweak an amount commitment by adding a public amount offset,
which can represent adjustments such as returning excess fees.

Zero-knowledge proofs use a Merlin-based transcript with domain separation for
each statement. Bulletproof range proofs constrain output amounts to 32 bits;
these checks complement balance proofs by preventing out-of-range outputs.

The design draws on:

- [WabiSabi: Centrally Coordinated CoinJoins with Variable Amounts](https://eprint.iacr.org/2021/206.pdf).
- [The Signal Private Group System and Anonymous Credentials Supporting Efficient Verifiable Encryption](https://eprint.iacr.org/2019/1416).
- [Bulletproofs](https://eprint.iacr.org/2017/1066.pdf) for range proofs.

Other range-proof constructions under consideration include
[Bulletproofs++](https://eprint.iacr.org/2022/510.pdf) and
[SHARP](https://eprint.iacr.org/2022/1153.pdf).

## Project status

This is experimental cryptographic code, and the protocol documentation is still
a work in progress. See [SECURITY.md](SECURITY.md) for vulnerability reporting and
[license](license) for licensing terms.
