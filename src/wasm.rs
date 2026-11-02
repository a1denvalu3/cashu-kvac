//! Module used to bridge the interface of cashu_kvac methods to webassembly
#![allow(non_snake_case)]
use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::JsValue;
use wasm_bindgen::{prelude::wasm_bindgen, JsError};

use crate::generators::hash_to_curve;
use crate::recovery::recover_amounts;
use crate::{
    bulletproof::BulletProof,
    kvac::{BalanceProof, BootstrapProof, IssuanceProof, MacProof, ScriptEqualityProof},
    models::{
        AmountAttribute, MintPrivateKey, MintPublicKey, RandomizedCommitments, ScriptAttribute, ZKP,
    },
    secp::{GroupElement, Scalar},
    transcript::CashuTranscript,
};

macro_rules! json {
    ($name:ident) => {
        #[wasm_bindgen]
        impl $name {
            pub fn toJSON(&self) -> JsValue {
                to_value(&self).unwrap()
            }

            pub fn fromJSON(value: JsValue) -> Result<Self, JsError> {
                let me: Self = from_value(value).map_err(|e| JsError::new(&format!("{e}")))?;
                Ok(me)
            }
        }
    };
}

json!(MintPrivateKey);
json!(Scalar);
json!(GroupElement);
json!(AmountAttribute);
json!(ScriptAttribute);
json!(RandomizedCommitments);
json!(ZKP);
json!(BulletProof);
json!(MintPublicKey);

#[wasm_bindgen]
impl Scalar {
    pub fn wasmFromBytesBE(bytes: Vec<u8>) -> JsValue {
        Self::new(&bytes).toJSON()
    }

    pub fn wasmCreateRandom() -> JsValue {
        Self::random().toJSON()
    }
}

#[wasm_bindgen]
impl GroupElement {
    pub fn wasmFromBytesBE(bytes: Vec<u8>) -> JsValue {
        Self::new(&bytes).toJSON()
    }
}

#[wasm_bindgen]
impl AmountAttribute {
    pub fn wasmCreateNew(amount: u64, blindingFactor: Option<Vec<u8>>) -> JsValue {
        match blindingFactor {
            Some(blinding_factor) => Self::new(amount, Some(&blinding_factor)).toJSON(),
            None => Self::new(amount, None).toJSON(),
        }
    }

    pub fn wasmCommitment(amountAttr: JsValue) -> Result<JsValue, JsError> {
        let amountAttr = AmountAttribute::fromJSON(amountAttr)?;
        Ok(amountAttr.commitment().toJSON())
    }

    pub fn wasmTweakAmount(amountAttr: JsValue, amount: u64) -> Result<JsValue, JsError> {
        let mut amountAttr = AmountAttribute::fromJSON(amountAttr)?;
        amountAttr.tweak_amount(amount);
        Ok(amountAttr.toJSON())
    }
}

#[wasm_bindgen]
impl ScriptAttribute {
    pub fn wasmCreateNew(script: Vec<u8>, blindingFactor: Option<Vec<u8>>) -> JsValue {
        match blindingFactor {
            Some(blinding_factor) => Self::new(&script, Some(&blinding_factor)).toJSON(),
            None => Self::new(&script, None).toJSON(),
        }
    }

    pub fn wasmCommitment(scriptAttr: JsValue) -> Result<JsValue, JsError> {
        let scriptAttr = ScriptAttribute::fromJSON(scriptAttr)?;
        Ok(scriptAttr.commitment().toJSON())
    }
}

#[wasm_bindgen]
impl RandomizedCommitments {
    pub fn wasmFromAttributesAndMac(
        amountAttr: JsValue,
        scriptAttr: JsValue,
        tag: JsValue,
        mac: JsValue,
        revealScript: bool,
    ) -> Result<JsValue, JsError> {
        let amountAttr: AmountAttribute = AmountAttribute::fromJSON(amountAttr)?;
        let scriptAttr: Option<ScriptAttribute> =
            from_value(scriptAttr).map_err(|e| JsError::new(&format!("{e}")))?;
        let tag: Scalar = Scalar::fromJSON(tag)?;
        let mac: GroupElement = GroupElement::fromJSON(mac)?;
        Ok(
            Self::from_attributes_and_mac(&amountAttr, scriptAttr.as_ref(), tag, mac, revealScript)
                .unwrap()
                .toJSON(),
        )
    }
}

#[wasm_bindgen]
impl BootstrapProof {
    pub fn wasmCreate(
        amountAttribute: JsValue,
        transcript: &mut CashuTranscript,
    ) -> Result<JsValue, JsError> {
        let amountAttr: AmountAttribute = AmountAttribute::fromJSON(amountAttribute)?;
        Ok(BootstrapProof::create(&amountAttr, transcript).toJSON())
    }

    pub fn wasmVerify(
        amountCommitment: JsValue,
        proof: JsValue,
        transcript: &mut CashuTranscript,
    ) -> Result<bool, JsError> {
        let amountComm: GroupElement = GroupElement::fromJSON(amountCommitment)?;
        let proof: ZKP = ZKP::fromJSON(proof)?;
        Ok(BootstrapProof::verify(&amountComm, proof, transcript))
    }
}

#[wasm_bindgen]
impl MacProof {
    pub fn wasmCreate(
        mintPublickey: JsValue,
        amountAttribute: JsValue,
        scriptAttribute: JsValue,
        tag: JsValue,
        randomizedCoin: JsValue,
        revealScript: bool,
        transcript: &mut CashuTranscript,
    ) -> Result<JsValue, JsError> {
        let mintPubkey: MintPublicKey = MintPublicKey::fromJSON(mintPublickey)?;
        let amountAttr: AmountAttribute = AmountAttribute::fromJSON(amountAttribute)?;
        let tag: Scalar = Scalar::fromJSON(tag)?;
        let randomizedComms: RandomizedCommitments =
            RandomizedCommitments::fromJSON(randomizedCoin)?;
        let scriptAttr: Option<ScriptAttribute> =
            from_value(scriptAttribute).map_err(|e| JsError::new(&format!("{e}")))?;
        Ok(MacProof::create(
            &mintPubkey,
            &amountAttr,
            scriptAttr.as_ref(),
            tag,
            &randomizedComms,
            revealScript,
            transcript,
        )
        .toJSON())
    }

    pub fn wasmVerify(
        mintPrivkey: JsValue,
        randomizedCoin: JsValue,
        script: Option<Vec<u8>>,
        proof: JsValue,
        transcript: &mut CashuTranscript,
    ) -> Result<bool, JsError> {
        let mintPrivkey: MintPrivateKey = MintPrivateKey::fromJSON(mintPrivkey)?;
        let randomizedCoin: RandomizedCommitments =
            RandomizedCommitments::fromJSON(randomizedCoin)?;
        let proof: ZKP = ZKP::fromJSON(proof)?;
        match script {
            None => Ok(MacProof::verify(
                &mintPrivkey,
                &randomizedCoin,
                None,
                proof,
                transcript,
            )),
            Some(script) => Ok(MacProof::verify(
                &mintPrivkey,
                &randomizedCoin,
                Some(&script),
                proof,
                transcript,
            )),
        }
    }
}

#[wasm_bindgen]
impl IssuanceProof {
    pub fn wasmCreate(
        mintPrivkey: JsValue,
        tag: JsValue,
        mac: JsValue,
        amountCommitment: JsValue,
        scriptCommitment: JsValue,
    ) -> Result<JsValue, JsError> {
        let mintPrivkey: MintPrivateKey = MintPrivateKey::fromJSON(mintPrivkey)?;
        let tag: Scalar = Scalar::fromJSON(tag)?;
        let mac: GroupElement = GroupElement::fromJSON(mac)?;
        let amountCommitment: GroupElement = GroupElement::fromJSON(amountCommitment)?;
        let scriptCommitment: Option<GroupElement> =
            from_value(scriptCommitment).map_err(|e| JsError::new(&format!("{e}")))?;
        Ok(
            IssuanceProof::create(&mintPrivkey, tag, mac, amountCommitment, scriptCommitment)
                .toJSON(),
        )
    }

    pub fn wasmVerify(
        mintPublickey: JsValue,
        tag: JsValue,
        mac: JsValue,
        amountAttr: JsValue,
        scriptAttr: JsValue,
        proof: JsValue,
    ) -> Result<bool, JsError> {
        let mintPublickey: MintPublicKey = MintPublicKey::fromJSON(mintPublickey)?;
        let amountAttr = AmountAttribute::fromJSON(amountAttr)?;
        let scriptAttr: Option<ScriptAttribute> =
            from_value(scriptAttr).map_err(|e| JsError::new(&format!("{e}")))?;
        let mac = GroupElement::fromJSON(mac)?;
        let tag = Scalar::fromJSON(tag)?;
        let proof: ZKP = ZKP::fromJSON(proof)?;
        Ok(IssuanceProof::verify(
            &mintPublickey,
            tag,
            mac,
            &amountAttr,
            scriptAttr.as_ref(),
            proof,
        ))
    }
}

#[wasm_bindgen]
impl BalanceProof {
    pub fn wasmCreate(
        inputs: JsValue,
        outputs: JsValue,
        transcript: &mut CashuTranscript,
    ) -> Result<JsValue, JsError> {
        let inputs: Vec<AmountAttribute> =
            from_value(inputs).map_err(|e| JsError::new(&format!("{e}")))?;
        let outputs: Vec<AmountAttribute> =
            from_value(outputs).map_err(|e| JsError::new(&format!("{e}")))?;
        Ok(BalanceProof::create(&inputs, &outputs, transcript).toJSON())
    }

    pub fn wasmVerify(
        inputs: JsValue,
        outputs: JsValue,
        deltaAmount: i64,
        proof: JsValue,
        transcript: &mut CashuTranscript,
    ) -> Result<bool, JsError> {
        let inputs: Vec<RandomizedCommitments> =
            from_value(inputs).map_err(|e| JsError::new(&format!("{e}")))?;
        let outputs: Vec<GroupElement> =
            from_value(outputs).map_err(|e| JsError::new(&format!("{e}")))?;
        let proof: ZKP = ZKP::fromJSON(proof)?;
        Ok(BalanceProof::verify(
            &inputs,
            &outputs,
            deltaAmount,
            proof,
            transcript,
        ))
    }
}

#[wasm_bindgen]
impl ScriptEqualityProof {
    pub fn wasmCreate(
        inputs: JsValue,           //Vec<(AmountAttribute, ScriptAttribute)>,
        randomizedInputs: JsValue, //Vec<RandomizedCommitments>,
        outputs: JsValue,          //Vec<(AmountAttribute, ScriptAttribute)>,
        transcript: &mut CashuTranscript,
    ) -> Result<JsValue, JsError> {
        let outputs: Vec<(AmountAttribute, ScriptAttribute)> =
            from_value(outputs).map_err(|e| JsError::new(&format!("{e}")))?;
        let inputs: Vec<(AmountAttribute, ScriptAttribute)> =
            from_value(inputs).map_err(|e| JsError::new(&format!("{e}")))?;
        let randomizedInputs: Vec<RandomizedCommitments> =
            from_value(randomizedInputs).map_err(|e| JsError::new(&format!("{e}")))?;
        Ok(
            ScriptEqualityProof::create(&inputs, &randomizedInputs, &outputs, transcript)
                .unwrap()
                .toJSON(),
        )
    }

    pub fn wasmVerify(
        randomizedInputs: JsValue, //Vec<RandomizedCommitments>
        outputs: JsValue,          //Vec<(GroupElement, GroupElement)>,
        proof: JsValue,
        transcript: &mut CashuTranscript,
    ) -> Result<bool, JsError> {
        let outputs: Vec<(GroupElement, GroupElement)> =
            from_value(outputs).map_err(|e| JsError::new(&format!("{e}")))?;
        let randomizedInputs: Vec<RandomizedCommitments> =
            from_value(randomizedInputs).map_err(|e| JsError::new(&format!("{e}")))?;
        let proof: ZKP = ZKP::fromJSON(proof)?;
        Ok(ScriptEqualityProof::verify(
            &randomizedInputs,
            &outputs,
            proof,
            transcript,
        ))
    }
}

#[wasm_bindgen]
impl BulletProof {
    pub fn wasmCreate(
        attributes: JsValue,
        transcript: &mut CashuTranscript,
    ) -> Result<JsValue, JsError> {
        let attributes: Vec<AmountAttribute> =
            from_value(attributes).map_err(|e| JsError::new(&format!("{e}")))?;
        Ok(Self::new(transcript, &attributes).toJSON())
    }

    pub fn wasmVerify(
        amount_commiments: JsValue,
        proof: JsValue,
        transcript: &mut CashuTranscript,
    ) -> Result<bool, JsError> {
        let amountComm: Vec<GroupElement> =
            from_value(amount_commiments).map_err(|e| JsError::new(&format!("{e}")))?;
        let proof = BulletProof::fromJSON(proof)?;
        Ok(proof.verify(transcript, &amountComm))
    }
}

#[wasm_bindgen]
impl CashuTranscript {
    pub fn wasmCreateNew() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
pub fn wasmHashToG(hex: String) -> Result<JsValue, JsError> {
    let bytes = hex::decode(hex).map_err(|e| JsError::new(&format!("{e}")))?;
    let ge = hash_to_curve(&bytes).expect("can map to GroupElement");
    Ok(ge.toJSON())
}

#[wasm_bindgen]
pub fn wasmRecoverAmounts(
    amount_commitments: JsValue,
    blinding_factors: JsValue,
    upper_bound: u64,
) -> Result<JsValue, JsError> {
    let amount_commitments: Vec<GroupElement> = from_value(amount_commitments)?;
    let blinding_factors: Vec<Scalar> = from_value(blinding_factors)?;
    let recovered_amounts = recover_amounts(&amount_commitments, &blinding_factors, upper_bound);
    Ok(to_value(&recovered_amounts)?)
}
