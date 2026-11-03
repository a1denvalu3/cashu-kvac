use cashu_kvac::{
    kvac::RangeProof,
    models::{AmountAttribute, RangeZKP, RANGE_LIMIT},
    secp::GroupElement,
    sharp::SharpParams,
    transcript::CashuTranscript,
};
use serde_json::Value;

// Count the actual serialized scalars and compressed points, without JSON keys,
// hex expansion, vector lengths, or other framing. This is a raw payload count,
// not a claim that a compact binary wire format is implemented.
fn payload_bytes(value: &Value) -> usize {
    match value {
        Value::String(encoded) => {
            let bytes = hex::decode(encoded).expect("proof fields must be hex encoded");
            assert!(
                matches!(bytes.len(), 32 | 33),
                "unexpected proof field size"
            );
            bytes.len()
        }
        Value::Array(values) => values.iter().map(payload_bytes).sum(),
        Value::Object(fields) => fields.values().map(payload_bytes).sum(),
        _ => panic!("unexpected proof serialization format"),
    }
}

fn proof_sizes(proof: &RangeZKP, commitments: &[GroupElement]) -> (usize, usize) {
    let encoded = serde_json::to_vec(proof).expect("serialize range proof");
    let decoded: RangeZKP = serde_json::from_slice(&encoded).expect("deserialize range proof");
    assert_eq!(&decoded, proof);
    assert!(RangeProof::verify(
        &mut CashuTranscript::new(),
        commitments,
        decoded,
    ));
    let value = serde_json::to_value(proof).expect("serialize proof fields");
    (payload_bytes(&value), encoded.len())
}

fn main() {
    // Keep the fixture aligned with benches/range_proofs_bench.rs.
    const AMOUNTS: [u64; 8] = [14, 1, 11, 2, 3, 7, 42, 255];
    let mut batch_sizes: Vec<usize> = std::env::args()
        .skip(1)
        .map(|argument| {
            argument
                .parse()
                .expect("item counts must be positive integers")
        })
        .collect();
    if batch_sizes.is_empty() {
        batch_sizes = vec![1, 2, 4, 8, 16, 32];
    }

    println!("items,bulletproof_payload_bytes,sharp_poso_payload_bytes,bulletproof_json_bytes,sharp_poso_json_bytes");
    for batch_size in batch_sizes {
        assert!(batch_size > 0, "item counts must be positive");
        let attributes: Vec<_> = AMOUNTS
            .iter()
            .cycle()
            .take(batch_size)
            .map(|&amount| AmountAttribute::new(amount, None))
            .collect();
        let commitments: Vec<_> = attributes.iter().map(AmountAttribute::commitment).collect();
        let params = SharpParams::new(RANGE_LIMIT, batch_size as u64).expect("SHARP parameters");
        let bulletproof = RangeProof::create_bulletproof(&mut CashuTranscript::new(), &attributes);
        let sharp_poso =
            RangeProof::create_sharp(&mut CashuTranscript::new(), &attributes, &params)
                .expect("SHARP-PoSO proof creation failed");
        let (bp_payload, bp_json) = proof_sizes(&bulletproof, &commitments);
        let (sharp_payload, sharp_json) = proof_sizes(&sharp_poso, &commitments);
        println!("{batch_size},{bp_payload},{sharp_payload},{bp_json},{sharp_json}");
    }
}
