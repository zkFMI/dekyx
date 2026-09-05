//! Recipient-encrypted holder recovery; no plaintext witness serialization API.
//!
//! The caller pins the recovery public key and retains its independent private
//! key in authenticated custody. Recovery does not override current issuer
//! status, revocation, expiration or replay policy at presentation verification.
use super::*;
use zkfmi_crypto::{
    hybrid::kem::HybridKemKey,
    sealed::{SealedMessage, SealingPurpose},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedCredentialWitness {
    pub version: u16,
    pub credential_digest: Digest32,
    pub custody_context: Digest32,
    pub sealed: SealedMessage,
}

fn context(credential: &Credential, custody_context: &Digest32) -> Result<Digest32, DeKyxError> {
    if *custody_context == ZERO {
        return Err(DeKyxError::InvalidWitness);
    }
    Ok(Sha256::new()
        .chain_update(b"DEKYX:HOLDER-CUSTODY:v1")
        .chain_update(credential.digest()?)
        .chain_update(custody_context)
        .finalize()
        .into())
}

impl CredentialWitness {
    /// Seal this exact issued witness, including its independent ML-DSA seed.
    /// A curve-only reconstruction cannot restore an issued holder key.
    pub fn seal_custody(
        &self,
        credential: &Credential,
        recipient_public: &[u8],
        custody_context: Digest32,
    ) -> Result<EncryptedCredentialWitness, DeKyxError> {
        if credential.subject_commitment != self.subject_commitment()
            || credential.holder_public_key != self.holder_public_key()
            || credential.holder_suite != self.holder_suite()
            || credential.qualifications_root != qualification_root(&self.qualifications)?
        {
            return Err(DeKyxError::InvalidWitness);
        }
        let mut clear = SecretBytes::new(Vec::new());
        clear.extend_from_slice(self.subject_secret.as_bytes());
        clear.extend_from_slice(self.blinding.as_bytes());
        clear.extend_from_slice(&self.holder_key.custody_seed());
        // Qualifications are private too; encrypt them with the secret scalars.
        serde_json::to_writer(&mut *clear, &self.qualifications)
            .map_err(|_| DeKyxError::InvalidWitness)?;
        let sealed = SealedMessage::seal(
            recipient_public,
            SealingPurpose::CredentialCustody,
            &context(credential, &custody_context)?,
            &clear,
        )
        .map_err(|_| DeKyxError::InvalidWitness)?;
        Ok(EncryptedCredentialWitness {
            version: 1,
            credential_digest: credential.digest()?,
            custody_context,
            sealed,
        })
    }
}

impl EncryptedCredentialWitness {
    pub fn restore(
        &self,
        credential: &Credential,
        recipient: &HybridKemKey,
        expected_custody_context: &Digest32,
    ) -> Result<CredentialWitness, DeKyxError> {
        if self.version != 1
            || self.credential_digest != credential.digest()?
            || self.custody_context != *expected_custody_context
            || self.sealed.ciphertext.len() <= 96
        {
            return Err(DeKyxError::InvalidWitness);
        }
        let clear = self
            .sealed
            .open(
                recipient,
                SealingPurpose::CredentialCustody,
                &context(credential, expected_custody_context)?,
                self.sealed.ciphertext.len(),
            )
            .map_err(|_| DeKyxError::InvalidWitness)?;
        let scalar = |bytes: &[u8]| {
            Option::<Scalar>::from(Scalar::from_canonical_bytes(
                bytes.try_into().expect("fixed scalar"),
            ))
            .ok_or(DeKyxError::InvalidWitness)
        };
        let qualifications =
            serde_json::from_slice(&clear[96..]).map_err(|_| DeKyxError::InvalidWitness)?;
        let witness = CredentialWitness::from_scalars_with_holder(
            scalar(&clear[..32])?,
            scalar(&clear[32..64])?,
            qualifications,
            MlDsa65Signer::from_seed(clear[64..96].try_into().expect("fixed seed")),
        )?;
        if witness.subject_commitment() != credential.subject_commitment
            || witness.holder_public_key() != credential.holder_public_key
            || witness.holder_suite() != credential.holder_suite
            || qualification_root(&witness.qualifications)? != credential.qualifications_root
        {
            return Err(DeKyxError::InvalidWitness);
        }
        Ok(witness)
    }
}
