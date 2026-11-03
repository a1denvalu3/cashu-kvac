#![feature(test)]

extern crate test;

use cashu_kvac::{
    kvac::RangeProof,
    models::{AmountAttribute, RangeZKP, RANGE_LIMIT},
    sharp::SharpParams,
    transcript::CashuTranscript,
};
use std::hint::black_box;
use test::Bencher;

#[derive(Clone, Copy)]
enum Scheme {
    Bulletproof,
    SharpPoso,
}

impl Scheme {
    fn create(self, attributes: &[AmountAttribute], params: &SharpParams) -> RangeZKP {
        let mut transcript = CashuTranscript::new();
        match self {
            Self::Bulletproof => RangeProof::create_bulletproof(&mut transcript, attributes),
            Self::SharpPoso => RangeProof::create_sharp(&mut transcript, attributes, params)
                .expect("SHARP-PoSO proof creation failed"),
        }
    }
}

fn attributes(batch_size: usize) -> Vec<AmountAttribute> {
    // Use the same small, non-boundary amounts for both schemes. In particular,
    // SHARP's current three-square search depends on the witness value.
    const AMOUNTS: [u64; 8] = [14, 1, 11, 2, 3, 7, 42, 255];
    AMOUNTS
        .iter()
        .cycle()
        .take(batch_size)
        .map(|&amount| AmountAttribute::new(amount, None))
        .collect()
}

fn prove(bencher: &mut Bencher, batch_size: usize, scheme: Scheme) {
    let attributes = attributes(batch_size);
    let params = SharpParams::new(RANGE_LIMIT, batch_size as u64).expect("SHARP parameters");
    let commitments: Vec<_> = attributes.iter().map(AmountAttribute::commitment).collect();
    let proof = scheme.create(&attributes, &params);
    assert!(RangeProof::verify(
        &mut CashuTranscript::new(),
        &commitments,
        proof,
    ));

    bencher.iter(|| black_box(scheme.create(black_box(&attributes), black_box(&params))));
}

fn verify(bencher: &mut Bencher, batch_size: usize, scheme: Scheme) {
    let attributes = attributes(batch_size);
    let params = SharpParams::new(RANGE_LIMIT, batch_size as u64).expect("SHARP parameters");
    let commitments: Vec<_> = attributes.iter().map(AmountAttribute::commitment).collect();
    let proof = scheme.create(&attributes, &params);

    bencher.iter(|| {
        assert!(RangeProof::verify(
            &mut CashuTranscript::new(),
            black_box(&commitments),
            black_box(proof.clone()),
        ));
    });
}

macro_rules! range_benches {
    ($scheme:expr) => {
        #[bench]
        fn prove_01(bencher: &mut Bencher) {
            prove(bencher, 1, $scheme);
        }
        #[bench]
        fn prove_02(bencher: &mut Bencher) {
            prove(bencher, 2, $scheme);
        }
        #[bench]
        fn prove_04(bencher: &mut Bencher) {
            prove(bencher, 4, $scheme);
        }
        #[bench]
        fn prove_08(bencher: &mut Bencher) {
            prove(bencher, 8, $scheme);
        }
        #[bench]
        fn prove_16(bencher: &mut Bencher) {
            prove(bencher, 16, $scheme);
        }
        #[bench]
        fn prove_32(bencher: &mut Bencher) {
            prove(bencher, 32, $scheme);
        }
        #[bench]
        fn verify_01(bencher: &mut Bencher) {
            verify(bencher, 1, $scheme);
        }
        #[bench]
        fn verify_02(bencher: &mut Bencher) {
            verify(bencher, 2, $scheme);
        }
        #[bench]
        fn verify_04(bencher: &mut Bencher) {
            verify(bencher, 4, $scheme);
        }
        #[bench]
        fn verify_08(bencher: &mut Bencher) {
            verify(bencher, 8, $scheme);
        }
        #[bench]
        fn verify_16(bencher: &mut Bencher) {
            verify(bencher, 16, $scheme);
        }
        #[bench]
        fn verify_32(bencher: &mut Bencher) {
            verify(bencher, 32, $scheme);
        }
    };
}

mod bulletproof {
    use super::*;
    range_benches!(Scheme::Bulletproof);
}

mod sharp_poso {
    use super::*;
    range_benches!(Scheme::SharpPoso);
}
