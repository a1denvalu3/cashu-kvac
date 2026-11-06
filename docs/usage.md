# Using cashu-kvac

The examples in [`docs/examples/`](examples/) are complete Rust programs with
their own imports, setup, and verification. Run them from the repository root:

```sh
cargo run --example attributes
cargo run --example issuance
cargo run --example swap
```

They use the repository's existing dependencies. Each program prints a success
message after its assertions pass. See the [development guide](development.md)
for build prerequisites, tests, benchmarks, and WebAssembly bindings.

## Attributes and commitments

[`attributes.rs`](examples/attributes.rs) creates amount and script attributes
with both random and explicitly supplied blinding factors, then computes their
public commitments.

`AmountAttribute::new(amount, None)` and `ScriptAttribute::new(script, None)`
generate random blinding factors. Pass `Some(&blinding_factor)` to choose one.
An explicit factor must encode a valid scalar as 32 big-endian bytes; an arbitrary
byte string or a hexadecimal string is not a substitute. The example generates
valid factors with `Scalar::random()` and demonstrates reconstructing the same
attributes from them. A wallet can instead derive valid factors from its seed.

Attribute values and blinding factors are wallet secrets. Commitments are the
public values sent to the mint. The script bytes in these examples are illustrative
spending-condition data.

## Issuing and presenting a credential

[`issuance.rs`](examples/issuance.rs) demonstrates the wallet and mint sides of
issuing a credential bound to both an amount and a script:

1. The mint creates a private key from six random scalars and shares its public key.
2. The wallet creates attributes and a fresh, random 32-byte issuance nonce.
3. The mint calls `MAC::generate` with the nonce and both commitments, obtaining
   the mint-derived `(tag, mac)` pair.
4. The mint creates an `IssuanceProof`; the wallet verifies it with the public key
   before accepting the credential.
5. The wallet constructs `RandomizedCommitments` and a `MacProof` of possession;
   the mint verifies that proof with its private key.

The tag is derived by the mint from its private key, nonce, and commitments.
Wallets must use the returned tag when randomizing credentials and creating
proofs. Keep the nonce with the coin, or derive it reproducibly from the wallet's
seed, for [recovery](deterministic_recovery.md). Repeating the identical issuance
request returns the same tag and MAC.

The program demonstrates two alternative presentation modes for the same
credential:

| Mode | Randomization and `MacProof::create` | `MacProof::verify` script argument |
| --- | --- | --- |
| Hidden script | `reveal_script = false` | `None` |
| Revealed script | `reveal_script = true` | `Some(script)` with the original script bytes |

Use the same mode for randomization and proof creation. Revealing a script binds
the proof to those bytes; the application must separately validate the spending
condition. For a credential without a script, pass `None` for the script attribute
and commitment throughout, and use `reveal_script = false`.

The two presentations illustrate alternatives, not two spends. A mint must check
and atomically record `RandomizedCommitments::get_nullifier()` when accepting a
spend.

## Proving a balanced swap

[`swap.rs`](examples/swap.rs) combines two previously issued inputs of 12 and 11
into one output of 23. The program first issues and verifies the input credentials
so it can run independently. It then:

1. Randomizes each input and proves possession of its MAC.
2. Proves that the input and output amounts balance with `BalanceProof::create`.
3. Creates a Bulletproof range proof for the output.
4. Verifies each input MAC proof, the balance proof, and the range proof.
5. Issues the output credential and verifies the mint's issuance proof.

`BalanceProof::verify` takes randomized input commitments, output commitments,
and a public `delta_amount` equal to the total input amount minus the total output
amount. This example uses `0`. Positive values represent value leaving the
credential balance; negative values represent value entering it. The mint must
authorize any nonzero delta through its transaction logic.

A balance proof alone does not authenticate the inputs or constrain the output
amounts. The MAC and range proofs perform those checks. This example has no
scripts; script equality proofs are additionally needed when a transaction must
carry hidden spending conditions forward.

## Transcripts and application integration

The wallet and mint each maintain their own `CashuTranscript`. They must start
from the same state and process proofs in the same order. The swap example uses
input MAC proofs first, then the balance proof, then the range proof, on both sides.
`IssuanceProof` manages a separate transcript internally.

The examples keep both participants in one process and use assertions to show
successful verification. An application must reject failed proofs, persist wallet
secrets and mint keys, transport only the appropriate public data between parties,
and commit spent nullifiers and newly issued credentials as one transaction.

For protocol details and custom statements with `SchnorrProver` and
`SchnorrVerifier`, see the [protocol explanation](protocol_explanation.md) and
[`src/kvac.rs`](../src/kvac.rs).
