# Anonymous Credentials for Cashu

Experimental implementation of the core crypto behind an anonymous credentials enabled Mint.

### Compile and Run Tests

```shell
cargo build && cargo test
```

### Run Benchmarks

```shell
cargo +nightly bench
```

### Usage Examples

Creating a `AmountAttribute`:
```rust
use cashu_kvac::models::AmountAttribute;

// Normal
let amount_attribute = AmountAttribute::new(10, None);

// Chosen blinding factor (e.g. derived from BIP32)
let custom_blinding_factor = b"deadbeefdeadbeefdeadbeefdeadbeef";
let amount_attribute_1 = AmountAttribute::new(10, Some(custom_blinding_factor));
```

Creating a `ScriptAttribute`:
```rust
use cashu_kvac::models::ScriptAttribute;

let script = b"38c3";

// Normal
let script_attribute = ScriptAttribute::new(script, None);

// Chosen blinding factor (derived from BIP32)
let custom_blinding_factor = b"deadbeefdeadbeefdeadbeefdeadbeef";
let script_attribute = ScriptAttribute::new(script, custom_blinding_factor);
```

Issuing a `MAC` on a `AmountAttribute`:
```rust
use cashu_kvac::models::{AmountAttribute, ScriptAttribute, MAC, MintPrivateKey};
use cashu_kvac::secp::Scalar;

let scalars = (0..6).map(|_| Scalar::random()).collect();
let mint_privkey = MintPrivateKey::from_scalars(&scalars).unwrap();

// Client generates these: the amount commitment and an unguessable per-request
// nonce (32 random bytes, stored with the coin for later recovery).
let amount_attribute = AmountAttribute::new(10, None);
let amount_commitment = amount_attribute.commitment();
let nonce = rand::random::<[u8; 32]>();

// Mint derives the tag statelessly from (its private key, nonce, commitments) and
// issues the MAC. Wallet-chosen tags are not accepted: a repeated tag would allow
// combining two issued MACs into a forgery over an arbitrary amount.
let (tag, mac) = MAC::generate(&mint_privkey, &nonce, amount_commitment, None).unwrap();

```

Creating `RandomizedCommitments` from attributes and MAC (mandatory before performing a swap, mint, melt):
```rust
use cashu_kvac::models::RandomizedCommitments;

// Create randomized commitments from amount attribute, script attribute, tag, and MAC
let randomized_commitments = RandomizedCommitments::from_attributes_and_mac(
    &amount_attribute,
    Some(&script_attribute), // or None if no script
    tag,
    mac,
    false // reveal_script
).unwrap();

// Randomized commitments, but the script will be revealed
let randomized_commitments_with_script_reveal = RandomizedCommitments::from_attributes_and_mac(
    &amount_attribute,
    Some(&script_attribute),
    tag,
    mac,
    true // reveal_script
).unwrap();
```

Proving the balance between inputs and outputs of a swap:
```rust
use cashu_kvac::transcript::CashuTranscript;
use cashu_kvac::models::{AmountAttribute, MAC, MintPrivateKey};
use cashu_kvac::secp::{Scalar, GroupElement};

let mut transcript = CashuTranscript::new();

let scalars = (0..6).map(|_| Scalar::random()).collect();
let mint_privkey = MintPrivateKey::from_scalars(&scalars).unwrap();

let inputs = vec![
    AmountAttribute::new(12, None),
    AmountAttribute::new(11, None),
];
let outputs = vec![AmountAttribute::new(23, None)];

// We assume the inputs were already issued a MAC previously
let tags: Vec<Scalar> = inputs.iter().map(|_| Scalar::random()).collect();
let macs: Vec<GroupElement> = inputs
    .iter()
    .zip(tags.iter())
    .map(|(input, tag)| {
        MAC::generate(&mint_privkey, input.commitment(), None, *tag).expect("MAC expected")
    })
    .collect();

let proof = BalanceProof::create(&inputs, &outputs, &mut transcript);
```

> [!NOTE]
> You can prove prove/verify arbitrary statement with `SchorrProver` and `SchnorrVerifier`

### WASM and Javascript bindings
To generate the WASM and javascript bindings, install `wasm-pack`:

```sh
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

Clone this repository:
```sh
git clone https://github.com/lollerfirst/cashu-kvac
```

Then, navigate to the repository directory generate the WASM with:
```sh
wasm-pack build --target {node|web}
```

The library will be compiled to a package under `./pkg` from the root directory of the repository.

### KVAC Scheme
The design of this library is based around the KVAC scheme, and specifically around these 2 papers:

* KVAC used for CoinJoins (WabiSabi): https://eprint.iacr.org/2021/206.pdf
* The Signal Private Group System and Anonymous Credentials Supporting Efficient Verifiable Encryption: https://eprint.iacr.org/2019/1416

### Protocol Explanation
Definitions and Protocol explaination (WIP): [HERE](protocol_explanation.md)

### Extras
* [Deterministic Recovery](deterministic_recovery.md)
* Server/Mint can tweak the amounts encoded in the attributes: $M_a' = M_a + \delta G_\text{amount}$ . This can be used to return things like excess fees in a concise way.
* **[Deviation from scheme]** Using the $r$ blinding factor in Pedersen Commitments for both blinding and randomization:
  * different generators with unknown discrete log between them guarantees hiding.
  * Benefit: no $\pi_\text{serial}$ because not needed anymore.
  * $C_a$ (Randomized Amount Commitment) is chosen to be the nullifier.

### Range proofs

Range proofs are needed to verify the outputs to the requests are within a certain range, preventing any potential overflows that could cheat the Balance Proof.

Variations:

* [x] [BULLETPROOFS](https://eprint.iacr.org/2017/1066.pdf)
* [ ] [BULLETPROOFS++](https://eprint.iacr.org/2022/510.pdf) arithmetic circuits
* [ ] [SHARP](https://eprint.iacr.org/2022/1153.pdf) which would improve creation/verification time tenfold. There are some different flavours of sharp, some of which make use of hidden order groups.

### Transcript
Every Zero-Knowledge proof uses a dedicated transcript defined in `transcript.rs` and tweaked by a domain separation byte-string for the various statements that need to be proven.