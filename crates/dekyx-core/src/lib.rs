//! Application-neutral identity and qualification verification.
//!
//! DeKYX answers one question: whether an issuer-backed subject satisfies a
//! policy in an exact scope and request context. It deliberately does not
//! decide credit, reserve collateral, clear obligations, or settle assets.

use std::collections::{BTreeMap, BTreeSet};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;
use zkfmi_crypto::{
    backend::{Ed25519Signer, MlDsa65Signer, MlDsa65Verifier},
    hybrid::signature::{HybridSignature, HybridSigner, HybridVerifier},
    key::KeyPurpose,
    suite::{Suite, SuiteId, ML_DSA_65_PK_BYTES, ML_DSA_65_SIG_BYTES},
    traits::{SecretBytes, Signer as _, Verifier as _},
};

pub type Digest32 = [u8; 32];
pub type Identifier = [u8; 32];
pub const ZERO: [u8; 32] = [0; 32];
const CREDENTIAL_DOMAIN: &[u8] = b"DEKYX:CREDENTIAL:v3";
const ISSUANCE_REQUEST_DOMAIN: &[u8] = b"DEKYX:ISSUANCE-REQUEST:v2";
const ISSUANCE_PROOF_DOMAIN: &[u8] = b"DEKYX:ISSUANCE-PROOF:v2";
const STATUS_DOMAIN: &[u8] = b"DEKYX:STATUS-LIST:v2";
const CONTEXT_DOMAIN: &[u8] = b"DEKYX:PRESENTATION-CONTEXT:v1";
const PROOF_DOMAIN: &[u8] = b"DEKYX:ANONYMOUS-PRESENTATION:v1";
const PRESENTATION_DOMAIN: &[u8] = b"DEKYX:PRESENTATION-DIGEST:v2";
const QUALIFICATION_LEAF_DOMAIN: &[u8] = b"DEKYX:QUALIFICATION-LEAF:v1";
const QUALIFICATION_NODE_DOMAIN: &[u8] = b"DEKYX:QUALIFICATION-NODE:v1";
const BLINDING_GENERATOR_DOMAIN: &[u8] = b"DEKYX:SUBJECT-BLINDING-GENERATOR:v1";
const NULLIFIER_GENERATOR_DOMAIN: &[u8] = b"DEKYX:SCOPE-NULLIFIER-GENERATOR:v1";
/// A subject line is the stable identity of one holder inside one issuer, scope,
/// and policy. It deliberately excludes the issuer key epoch and the commitment
/// blinding so that an issuer key rotation or a re-issued credential with the
/// same subject secret continues the same line.
const SUBJECT_LINE_DOMAIN: &[u8] = b"DEKYX:SUBJECT-LINE:v2";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Person,
    LegalEntity,
    Device,
    Service,
    AutonomousAgent,
}

impl SubjectKind {
    fn tag(self) -> u8 {
        match self {
            Self::Person => 1,
            Self::LegalEntity => 2,
            Self::Device => 3,
            Self::Service => 4,
            Self::AutonomousAgent => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuerStatus {
    Active,
    Suspended,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuerDefinition {
    pub issuer_id: Identifier,
    pub key_epoch: u64,
    pub public_key: [u8; 32],
    pub pq_public_key: Vec<u8>,
    pub signature_suite: Suite,
    pub supported_subjects: BTreeSet<SubjectKind>,
    pub namespace_digest: Digest32,
    pub valid_from: u64,
    pub valid_until: u64,
    pub status: IssuerStatus,
}

impl IssuerDefinition {
    pub fn validate(&self) -> Result<(), DeKyxError> {
        if [self.issuer_id, self.public_key, self.namespace_digest].contains(&ZERO)
            || self.key_epoch == 0
            || self.signature_suite != Suite::new(SuiteId::Ed25519MlDsa65)
            || self.pq_public_key.len() != ML_DSA_65_PK_BYTES
            || self.pq_public_key.iter().all(|byte| *byte == 0)
            || self.supported_subjects.is_empty()
            || self.valid_from == 0
            || self.valid_from > self.valid_until
        {
            return Err(DeKyxError::InvalidIssuer);
        }
        VerifyingKey::from_bytes(&self.public_key).map_err(|_| DeKyxError::InvalidIssuerKey)?;
        Ok(())
    }

    fn hybrid_public_key(&self) -> Vec<u8> {
        [self.public_key.as_slice(), self.pq_public_key.as_slice()].concat()
    }

    pub fn active_for(&self, kind: SubjectKind, now: u64) -> bool {
        self.status == IssuerStatus::Active
            && self.valid_from <= now
            && now <= self.valid_until
            && self.supported_subjects.contains(&kind)
    }
}

/// Trust-anchor registry. Direct deserialization is intentionally disabled so
/// persisted input cannot bypass `IssuerDefinition::validate` or replace an
/// already registered issuer/key epoch.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuerRegistry {
    issuers: BTreeMap<String, IssuerDefinition>,
}

impl IssuerRegistry {
    pub fn is_empty(&self) -> bool {
        self.issuers.is_empty()
    }

    pub fn definitions(&self) -> impl Iterator<Item = &IssuerDefinition> {
        self.issuers.values()
    }

    /// Highest key epoch of `issuer_id` that is active for `kind` at `now`.
    pub fn current_epoch(
        &self,
        issuer_id: &Identifier,
        kind: SubjectKind,
        now: u64,
    ) -> Option<u64> {
        self.issuers
            .values()
            .filter(|issuer| &issuer.issuer_id == issuer_id && issuer.active_for(kind, now))
            .map(|issuer| issuer.key_epoch)
            .max()
    }

    fn latest_epoch(&self, issuer_id: &Identifier) -> Option<u64> {
        self.issuers
            .values()
            .filter(|issuer| &issuer.issuer_id == issuer_id)
            .map(|issuer| issuer.key_epoch)
            .max()
    }

    pub fn register(&mut self, issuer: IssuerDefinition) -> Result<(), DeKyxError> {
        issuer.validate()?;
        let key = issuer_key(&issuer.issuer_id, issuer.key_epoch);
        if self.issuers.contains_key(&key) {
            return Err(DeKyxError::DuplicateIssuerEpoch);
        }
        self.issuers.insert(key, issuer);
        Ok(())
    }

    pub fn issuer(
        &self,
        issuer_id: &Identifier,
        key_epoch: u64,
    ) -> Result<&IssuerDefinition, DeKyxError> {
        self.issuers
            .get(&issuer_key(issuer_id, key_epoch))
            .ok_or(DeKyxError::UnknownIssuer)
    }
}

/// Serialized form of [`IssuerDirectory`]. Loading it re-runs every issuer
/// validation, epoch-ordering, and status-list signature check, so a persisted
/// directory cannot smuggle an unvalidated trust anchor or an unsigned list.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuerDirectoryRecord {
    pub issuers: BTreeMap<String, IssuerDefinition>,
    pub status_lists: BTreeMap<String, RevocationStatusList>,
}

/// Application-neutral trust state: every accepted issuer key epoch and the
/// latest signed revocation status list per epoch.
///
/// Key rotation registers a strictly higher epoch with a different key and
/// bounds the earlier epochs. Verification for an epoch without a published
/// status list fails closed, so an issuer must publish at least an empty list
/// before its credentials can be presented.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(into = "IssuerDirectoryRecord", try_from = "IssuerDirectoryRecord")]
pub struct IssuerDirectory {
    registry: IssuerRegistry,
    status_lists: BTreeMap<String, RevocationStatusList>,
}

impl IssuerDirectory {
    pub fn is_empty(&self) -> bool {
        self.registry.is_empty() && self.status_lists.is_empty()
    }

    pub fn registry(&self) -> &IssuerRegistry {
        &self.registry
    }

    pub fn issuer(
        &self,
        issuer_id: &Identifier,
        key_epoch: u64,
    ) -> Result<&IssuerDefinition, DeKyxError> {
        self.registry.issuer(issuer_id, key_epoch)
    }

    pub fn status_list(
        &self,
        issuer_id: &Identifier,
        key_epoch: u64,
    ) -> Option<&RevocationStatusList> {
        self.status_lists.get(&issuer_key(issuer_id, key_epoch))
    }

    /// Highest key epoch of `issuer_id` that is active for `kind` at `now`.
    pub fn current_epoch(
        &self,
        issuer_id: &Identifier,
        kind: SubjectKind,
        now: u64,
    ) -> Option<u64> {
        self.registry.current_epoch(issuer_id, kind, now)
    }

    /// Registers the first key epoch of an issuer. Later epochs must arrive
    /// through [`IssuerDirectory::rotate_key`] so the earlier epochs are bounded.
    pub fn register_issuer(&mut self, issuer: IssuerDefinition) -> Result<(), DeKyxError> {
        issuer.validate()?;
        if self.registry.latest_epoch(&issuer.issuer_id).is_some() {
            return Err(DeKyxError::InvalidKeyRotation);
        }
        self.registry.register(issuer)
    }

    /// Rotates to `next`, whose epoch must exceed every registered epoch of the
    /// same issuer and whose key must differ from the current one. Earlier
    /// epochs stay usable until `previous_valid_until` at the latest; a value
    /// before an epoch's `valid_from` revokes that epoch immediately, which is
    /// the key-compromise path.
    pub fn rotate_key(
        &mut self,
        next: IssuerDefinition,
        previous_valid_until: u64,
    ) -> Result<(), DeKyxError> {
        next.validate()?;
        let latest = self
            .registry
            .latest_epoch(&next.issuer_id)
            .ok_or(DeKyxError::UnknownIssuer)?;
        let current = self.registry.issuer(&next.issuer_id, latest)?;
        if next.key_epoch <= latest
            || next.public_key == current.public_key
            || next.pq_public_key == current.pq_public_key
        {
            return Err(DeKyxError::InvalidKeyRotation);
        }
        let next_id = next.issuer_id;
        let next_epoch = next.key_epoch;
        self.registry.register(next)?;
        for issuer in self.registry.issuers.values_mut() {
            if issuer.issuer_id != next_id || issuer.key_epoch >= next_epoch {
                continue;
            }
            if previous_valid_until < issuer.valid_from {
                issuer.status = IssuerStatus::Revoked;
            } else if previous_valid_until < issuer.valid_until {
                issuer.valid_until = previous_valid_until;
            }
        }
        Ok(())
    }

    pub fn set_status(
        &mut self,
        issuer_id: &Identifier,
        key_epoch: u64,
        status: IssuerStatus,
    ) -> Result<(), DeKyxError> {
        self.registry
            .issuers
            .get_mut(&issuer_key(issuer_id, key_epoch))
            .ok_or(DeKyxError::UnknownIssuer)?
            .status = status;
        Ok(())
    }

    /// Accepts a status list signed by the named issuer key epoch when its
    /// status epoch is newer than the list already held for that epoch.
    pub fn publish_status_list(&mut self, list: RevocationStatusList) -> Result<(), DeKyxError> {
        let issuer = self
            .registry
            .issuer(&list.issuer_id, list.issuer_key_epoch)?;
        list.verify_signature(issuer)?;
        let key = issuer_key(&list.issuer_id, list.issuer_key_epoch);
        if self
            .status_lists
            .get(&key)
            .is_some_and(|existing| existing.status_epoch >= list.status_epoch)
        {
            return Err(DeKyxError::StaleStatusList);
        }
        self.status_lists.insert(key, list);
        Ok(())
    }

    /// Verifier for one exact issuer key epoch. Fails closed when that epoch
    /// has no published status list.
    pub fn verifier(
        &self,
        issuer_id: &Identifier,
        key_epoch: u64,
    ) -> Result<DeKyxVerifier<'_>, DeKyxError> {
        self.registry.issuer(issuer_id, key_epoch)?;
        let status_list = self
            .status_lists
            .get(&issuer_key(issuer_id, key_epoch))
            .ok_or(DeKyxError::MissingStatusList)?;
        Ok(DeKyxVerifier {
            issuers: &self.registry,
            status_list,
        })
    }
}

impl From<IssuerDirectory> for IssuerDirectoryRecord {
    fn from(directory: IssuerDirectory) -> Self {
        Self {
            issuers: directory.registry.issuers,
            status_lists: directory.status_lists,
        }
    }
}

impl TryFrom<IssuerDirectoryRecord> for IssuerDirectory {
    type Error = DeKyxError;

    fn try_from(record: IssuerDirectoryRecord) -> Result<Self, DeKyxError> {
        let mut issuers: Vec<_> = record.issuers.into_iter().collect();
        issuers.sort_by_key(|(_, issuer)| (issuer.issuer_id, issuer.key_epoch));
        let mut directory = Self::default();
        for (key, issuer) in issuers {
            if key != issuer_key(&issuer.issuer_id, issuer.key_epoch) {
                return Err(DeKyxError::InvalidIssuer);
            }
            issuer.validate()?;
            if directory
                .registry
                .latest_epoch(&issuer.issuer_id)
                .is_some_and(|latest| latest >= issuer.key_epoch)
            {
                return Err(DeKyxError::InvalidKeyRotation);
            }
            directory.registry.register(issuer)?;
        }
        for (key, list) in record.status_lists {
            if key != issuer_key(&list.issuer_id, list.issuer_key_epoch) {
                return Err(DeKyxError::InvalidStatusList);
            }
            directory.publish_status_list(list)?;
        }
        Ok(directory)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Qualification {
    /// Human-readable namespace such as `jp.kyb` or `market.qomm`.
    pub namespace: String,
    /// Digest of the exact predicate, schema, and accepted value.
    pub predicate_digest: Digest32,
}

impl Qualification {
    pub fn validate(&self) -> Result<(), DeKyxError> {
        if self.namespace.is_empty()
            || self.namespace.len() > 128
            || self.namespace.chars().any(char::is_control)
            || self.predicate_digest == ZERO
        {
            return Err(DeKyxError::InvalidQualification);
        }
        Ok(())
    }

    pub fn leaf_digest(&self) -> Result<Digest32, DeKyxError> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(QUALIFICATION_LEAF_DOMAIN);
        hash.update((self.namespace.len() as u32).to_be_bytes());
        hash.update(self.namespace.as_bytes());
        hash.update(self.predicate_digest);
        Ok(hash.finalize().into())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationProof {
    pub qualification: Qualification,
    pub index: u32,
    pub total: u32,
    pub siblings: Vec<Digest32>,
}

impl QualificationProof {
    pub fn verify(&self, expected_root: &Digest32) -> Result<(), DeKyxError> {
        if self.total == 0 || self.index >= self.total || self.siblings.len() > 32 {
            return Err(DeKyxError::InvalidQualificationProof);
        }
        let mut node = self.qualification.leaf_digest()?;
        let mut position = self.index as usize;
        let mut width = self.total as usize;
        for sibling in &self.siblings {
            if position == width - 1 && width % 2 == 1 && sibling != &node {
                return Err(DeKyxError::InvalidQualificationProof);
            }
            node = if position % 2 == 0 {
                qualification_node(&node, sibling)
            } else {
                qualification_node(sibling, &node)
            };
            position /= 2;
            width = width.div_ceil(2);
        }
        if width != 1 || node != *expected_root {
            return Err(DeKyxError::InvalidQualificationProof);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignatureBytes {
    pub first: [u8; 32],
    pub second: [u8; 32],
    pub pq: Vec<u8>,
}

impl SignatureBytes {
    fn from_signature(signature: HybridSignature) -> Self {
        Self {
            first: signature.classical[..32]
                .try_into()
                .expect("fixed signature half"),
            second: signature.classical[32..]
                .try_into()
                .expect("fixed signature half"),
            pq: signature.pq,
        }
    }

    fn signature(&self) -> HybridSignature {
        HybridSignature {
            classical: [self.first.as_slice(), self.second.as_slice()].concat(),
            pq: self.pq.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Credential {
    pub credential_id: Identifier,
    pub issuer_id: Identifier,
    pub issuer_key_epoch: u64,
    pub subject_kind: SubjectKind,
    pub subject_commitment: [u8; 32],
    pub holder_public_key: Vec<u8>,
    pub holder_suite: Suite,
    pub scope_digest: Digest32,
    pub policy_digest: Digest32,
    pub qualifications_root: Digest32,
    pub status_epoch: u64,
    pub valid_from: u64,
    pub valid_until: u64,
    pub signature: SignatureBytes,
}

impl Credential {
    pub fn statement_digest(&self) -> Result<Digest32, DeKyxError> {
        if [
            self.credential_id,
            self.issuer_id,
            self.subject_commitment,
            self.scope_digest,
            self.policy_digest,
            self.qualifications_root,
        ]
        .contains(&ZERO)
            || self.issuer_key_epoch == 0
            || self.status_epoch == 0
            || self.valid_from == 0
            || self.valid_from > self.valid_until
        {
            return Err(DeKyxError::InvalidCredential);
        }
        decompress_non_identity(self.subject_commitment)?;
        if self.holder_suite != Suite::new(SuiteId::MlDsa65)
            || self.holder_public_key.len() != ML_DSA_65_PK_BYTES
        {
            return Err(DeKyxError::InvalidCredential);
        }
        let mut hash = Sha256::new();
        hash.update(CREDENTIAL_DOMAIN);
        hash.update(self.credential_id);
        hash.update(self.issuer_id);
        hash.update(self.issuer_key_epoch.to_be_bytes());
        hash.update([self.subject_kind.tag()]);
        hash.update(self.subject_commitment);
        hash.update(self.holder_suite.encode());
        hash.update(&self.holder_public_key);
        hash.update(self.scope_digest);
        hash.update(self.policy_digest);
        hash.update(self.qualifications_root);
        hash.update(self.status_epoch.to_be_bytes());
        hash.update(self.valid_from.to_be_bytes());
        hash.update(self.valid_until.to_be_bytes());
        Ok(hash.finalize().into())
    }

    pub fn digest(&self) -> Result<Digest32, DeKyxError> {
        let mut hash = Sha256::new();
        hash.update(self.statement_digest()?);
        hash.update(
            self.signature
                .signature()
                .encode()
                .map_err(|_| DeKyxError::InvalidCredentialSignature)?,
        );
        Ok(hash.finalize().into())
    }

    fn verify_signature(&self, issuer: &IssuerDefinition) -> Result<(), DeKyxError> {
        issuer.validate()?;
        HybridVerifier
            .verify_hybrid(
                KeyPurpose::Attestation,
                &issuer.hybrid_public_key(),
                &self.statement_digest()?,
                &self.signature.signature(),
            )
            .map_err(|_| DeKyxError::InvalidCredentialSignature)
    }
}

pub struct CredentialWitness {
    subject_secret: Scalar,
    blinding: Scalar,
    qualifications: Vec<Qualification>,
    holder_key: MlDsa65Signer,
}

fn fresh_holder_key<R: RngCore + CryptoRng>(rng: &mut R) -> MlDsa65Signer {
    let mut seed = SecretBytes::new(vec![0; 32]);
    rng.fill_bytes(&mut seed);
    MlDsa65Signer::from_seed(
        seed.as_slice()
            .try_into()
            .expect("fixed holder seed length"),
    )
}

impl CredentialWitness {
    pub fn random<R: RngCore + CryptoRng>(
        qualifications: Vec<Qualification>,
        rng: &mut R,
    ) -> Result<Self, DeKyxError> {
        let mut secret = Scalar::random(&mut *rng);
        while secret == Scalar::ZERO {
            secret = Scalar::random(&mut *rng);
        }
        Self::from_scalars_with_holder(
            secret,
            Scalar::random(&mut *rng),
            qualifications,
            fresh_holder_key(rng),
        )
    }

    /// Create a new witness with an independent fresh PQ holder key.
    /// Restoring an issued credential requires its original holder key through
    /// `from_scalars_with_holder`; the curve scalars cannot reconstruct it.
    pub fn from_scalars(
        subject_secret: Scalar,
        blinding: Scalar,
        qualifications: Vec<Qualification>,
    ) -> Result<Self, DeKyxError> {
        let holder_key = MlDsa65Signer::generate().map_err(|_| DeKyxError::InvalidWitness)?;
        Self::from_scalars_with_holder(subject_secret, blinding, qualifications, holder_key)
    }

    pub fn from_scalars_with_holder(
        subject_secret: Scalar,
        blinding: Scalar,
        qualifications: Vec<Qualification>,
        holder_key: MlDsa65Signer,
    ) -> Result<Self, DeKyxError> {
        if subject_secret == Scalar::ZERO {
            return Err(DeKyxError::InvalidWitness);
        }
        let qualifications = canonical_qualifications(&qualifications)?;
        Ok(Self {
            subject_secret,
            blinding,
            qualifications,
            holder_key,
        })
    }

    /// Keeps the subject secret and qualifications while drawing a fresh
    /// blinding and independent PQ key for a new credential. No holder public
    /// key is reused to link credentials across scopes.
    pub fn rerandomize<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Self {
        Self {
            subject_secret: self.subject_secret,
            blinding: Scalar::random(&mut *rng),
            qualifications: self.qualifications.clone(),
            holder_key: fresh_holder_key(rng),
        }
    }

    pub fn holder_public_key(&self) -> Vec<u8> {
        self.holder_key.public_key()
    }

    pub fn holder_suite(&self) -> Suite {
        self.holder_key.suite()
    }

    pub fn subject_commitment(&self) -> [u8; 32] {
        (RISTRETTO_BASEPOINT_POINT * self.subject_secret + blinding_generator() * self.blinding)
            .compress()
            .to_bytes()
    }

    pub fn scope_nullifier(&self, scope: &Digest32) -> [u8; 32] {
        (nullifier_generator(scope) * self.subject_secret)
            .compress()
            .to_bytes()
    }

    pub fn qualification_proof(
        &self,
        qualification: &Qualification,
    ) -> Result<QualificationProof, DeKyxError> {
        qualification_proof(&self.qualifications, qualification)
    }

    /// Proves possession of the secret opening used in an issuance request.
    /// The issuer sees only the commitment and proof, never either scalar.
    pub fn prove_issuance<R: RngCore + CryptoRng>(
        &self,
        request: &CredentialRequest,
        rng: &mut R,
    ) -> Result<CredentialIssuanceProof, DeKyxError> {
        if request.subject_commitment != self.subject_commitment()
            || request.holder_public_key != self.holder_public_key()
            || request.holder_suite != self.holder_suite()
            || canonical_qualifications(&request.qualifications)? != self.qualifications
        {
            return Err(DeKyxError::MismatchedWitnessOrContext);
        }
        request.statement_digest()?;
        let nonce_subject = Scalar::random(&mut *rng);
        let nonce_blinding = Scalar::random(&mut *rng);
        let announcement_commitment = (RISTRETTO_BASEPOINT_POINT * nonce_subject
            + blinding_generator() * nonce_blinding)
            .compress()
            .to_bytes();
        let challenge = issuance_challenge(request, &announcement_commitment)?;
        let mut proof = CredentialIssuanceProof {
            announcement_commitment,
            response_subject: (nonce_subject + challenge * self.subject_secret).to_bytes(),
            response_blinding: (nonce_blinding + challenge * self.blinding).to_bytes(),
            holder_signature: Vec::new(),
        };
        proof.holder_signature = self
            .holder_key
            .sign(
                KeyPurpose::Attestation,
                &proof.holder_signing_message(request)?,
            )
            .map_err(|_| DeKyxError::InvalidIssuanceProof)?;
        Ok(proof)
    }
}

pub struct CredentialIssuer {
    definition: IssuerDefinition,
    signing_key: HybridSigner,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialRequest {
    pub credential_id: Identifier,
    pub issuer_id: Identifier,
    pub issuer_key_epoch: u64,
    pub subject_kind: SubjectKind,
    pub subject_commitment: [u8; 32],
    pub holder_public_key: Vec<u8>,
    pub holder_suite: Suite,
    pub scope_digest: Digest32,
    pub policy_digest: Digest32,
    pub qualifications: Vec<Qualification>,
    pub status_epoch: u64,
    pub valid_from: u64,
    pub valid_until: u64,
}

impl CredentialRequest {
    pub fn statement_digest(&self) -> Result<Digest32, DeKyxError> {
        if [
            self.credential_id,
            self.issuer_id,
            self.subject_commitment,
            self.scope_digest,
            self.policy_digest,
        ]
        .contains(&ZERO)
            || self.issuer_key_epoch == 0
            || self.status_epoch == 0
            || self.valid_from == 0
            || self.valid_from > self.valid_until
        {
            return Err(DeKyxError::InvalidCredential);
        }
        decompress_non_identity(self.subject_commitment)?;
        if self.holder_suite != Suite::new(SuiteId::MlDsa65)
            || self.holder_public_key.len() != ML_DSA_65_PK_BYTES
        {
            return Err(DeKyxError::InvalidCredential);
        }
        let qualifications_root = qualification_root(&self.qualifications)?;
        Ok(digest_fields(
            ISSUANCE_REQUEST_DOMAIN,
            &[
                &self.credential_id,
                &self.issuer_id,
                &self.issuer_key_epoch.to_be_bytes(),
                &[self.subject_kind.tag()],
                &self.subject_commitment,
                &self.holder_suite.encode(),
                &self.holder_public_key,
                &self.scope_digest,
                &self.policy_digest,
                &qualifications_root,
                &self.status_epoch.to_be_bytes(),
                &self.valid_from.to_be_bytes(),
                &self.valid_until.to_be_bytes(),
            ],
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialIssuanceProof {
    pub announcement_commitment: [u8; 32],
    pub response_subject: [u8; 32],
    pub response_blinding: [u8; 32],
    pub holder_signature: Vec<u8>,
}

impl CredentialIssuanceProof {
    pub fn holder_signing_message(
        &self,
        request: &CredentialRequest,
    ) -> Result<Digest32, DeKyxError> {
        Ok(digest_fields(
            b"DEKYX:HOLDER-ISSUANCE:v2",
            &[
                &request.statement_digest()?,
                &self.announcement_commitment,
                &self.response_subject,
                &self.response_blinding,
            ],
        ))
    }

    fn verify(&self, request: &CredentialRequest) -> Result<(), DeKyxError> {
        MlDsa65Verifier
            .verify(
                KeyPurpose::Attestation,
                &request.holder_public_key,
                &self.holder_signing_message(request)?,
                &self.holder_signature,
            )
            .map_err(|_| DeKyxError::InvalidIssuanceProof)?;
        let commitment = decompress_non_identity(request.subject_commitment)?;
        let announcement = decompress_point(self.announcement_commitment)?;
        let response_subject = canonical_scalar(self.response_subject)?;
        let response_blinding = canonical_scalar(self.response_blinding)?;
        let challenge = issuance_challenge(request, &self.announcement_commitment)?;
        if RISTRETTO_BASEPOINT_POINT * response_subject + blinding_generator() * response_blinding
            != announcement + commitment * challenge
        {
            return Err(DeKyxError::InvalidIssuanceProof);
        }
        Ok(())
    }
}

impl CredentialIssuer {
    pub fn new(
        definition: IssuerDefinition,
        signing_key: SigningKey,
        pq_signing_key: MlDsa65Signer,
    ) -> Result<Self, DeKyxError> {
        definition.validate()?;
        let signing_key = HybridSigner::new(Ed25519Signer::from_key(signing_key), pq_signing_key);
        if definition.hybrid_public_key() != signing_key.public_key() {
            return Err(DeKyxError::InvalidIssuerKey);
        }
        Ok(Self {
            definition,
            signing_key,
        })
    }

    pub fn issue(
        &self,
        request: CredentialRequest,
        holder_proof: CredentialIssuanceProof,
    ) -> Result<Credential, DeKyxError> {
        if request.issuer_id != self.definition.issuer_id
            || request.issuer_key_epoch != self.definition.key_epoch
            || !self
                .definition
                .supported_subjects
                .contains(&request.subject_kind)
            || request.valid_from < self.definition.valid_from
            || request.valid_until > self.definition.valid_until
        {
            return Err(DeKyxError::IssuerNotAuthorized);
        }
        request.statement_digest()?;
        holder_proof.verify(&request)?;
        let mut credential = Credential {
            credential_id: request.credential_id,
            issuer_id: self.definition.issuer_id,
            issuer_key_epoch: self.definition.key_epoch,
            subject_kind: request.subject_kind,
            subject_commitment: request.subject_commitment,
            holder_public_key: request.holder_public_key,
            holder_suite: request.holder_suite,
            scope_digest: request.scope_digest,
            policy_digest: request.policy_digest,
            qualifications_root: qualification_root(&request.qualifications)?,
            status_epoch: request.status_epoch,
            valid_from: request.valid_from,
            valid_until: request.valid_until,
            signature: SignatureBytes {
                first: ZERO,
                second: ZERO,
                pq: Vec::new(),
            },
        };
        credential.signature = SignatureBytes::from_signature(
            self.signing_key
                .sign_hybrid(KeyPurpose::Attestation, &credential.statement_digest()?)
                .map_err(|_| DeKyxError::InvalidCredentialSignature)?,
        );
        Ok(credential)
    }

    pub fn issue_status_list(
        &self,
        status_epoch: u64,
        effective_at: u64,
        valid_until: u64,
        revoked_credentials: Vec<Digest32>,
    ) -> Result<RevocationStatusList, DeKyxError> {
        let mut list = RevocationStatusList {
            issuer_id: self.definition.issuer_id,
            issuer_key_epoch: self.definition.key_epoch,
            status_epoch,
            effective_at,
            valid_until,
            revoked_credentials,
            signature: SignatureBytes {
                first: ZERO,
                second: ZERO,
                pq: Vec::new(),
            },
        };
        list.canonicalize()?;
        list.signature = SignatureBytes::from_signature(
            self.signing_key
                .sign_hybrid(KeyPurpose::Attestation, &list.statement_digest()?)
                .map_err(|_| DeKyxError::InvalidStatusListSignature)?,
        );
        Ok(list)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationStatusList {
    pub issuer_id: Identifier,
    pub issuer_key_epoch: u64,
    pub status_epoch: u64,
    pub effective_at: u64,
    pub valid_until: u64,
    pub revoked_credentials: Vec<Digest32>,
    pub signature: SignatureBytes,
}

impl RevocationStatusList {
    fn canonicalize(&mut self) -> Result<(), DeKyxError> {
        self.revoked_credentials.sort_unstable();
        if self.revoked_credentials.len() > 1_000_000
            || self.revoked_credentials.contains(&ZERO)
            || self
                .revoked_credentials
                .windows(2)
                .any(|pair| pair[0] == pair[1])
        {
            return Err(DeKyxError::InvalidStatusList);
        }
        Ok(())
    }

    pub fn statement_digest(&self) -> Result<Digest32, DeKyxError> {
        if self.issuer_id == ZERO
            || self.issuer_key_epoch == 0
            || self.status_epoch == 0
            || self.effective_at == 0
            || self.effective_at > self.valid_until
            || self.revoked_credentials.len() > 1_000_000
            || self.revoked_credentials.contains(&ZERO)
            || self
                .revoked_credentials
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(DeKyxError::InvalidStatusList);
        }
        let mut hash = Sha256::new();
        hash.update(STATUS_DOMAIN);
        hash.update(self.issuer_id);
        hash.update(self.issuer_key_epoch.to_be_bytes());
        hash.update(self.status_epoch.to_be_bytes());
        hash.update(self.effective_at.to_be_bytes());
        hash.update(self.valid_until.to_be_bytes());
        hash.update((self.revoked_credentials.len() as u32).to_be_bytes());
        for credential in &self.revoked_credentials {
            hash.update(credential);
        }
        Ok(hash.finalize().into())
    }

    fn verify(&self, issuer: &IssuerDefinition, now: u64) -> Result<(), DeKyxError> {
        if now < self.effective_at || now > self.valid_until {
            return Err(DeKyxError::InvalidStatusList);
        }
        self.verify_signature(issuer)
    }

    /// Checks issuer identity and signature without the effective window.
    pub fn verify_signature(&self, issuer: &IssuerDefinition) -> Result<(), DeKyxError> {
        if self.issuer_id != issuer.issuer_id || self.issuer_key_epoch != issuer.key_epoch {
            return Err(DeKyxError::InvalidStatusList);
        }
        issuer.validate()?;
        HybridVerifier
            .verify_hybrid(
                KeyPurpose::Attestation,
                &issuer.hybrid_public_key(),
                &self.statement_digest()?,
                &self.signature.signature(),
            )
            .map_err(|_| DeKyxError::InvalidStatusListSignature)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PresentationContext {
    pub scope_digest: Digest32,
    pub audience_digest: Digest32,
    pub action_digest: Digest32,
    pub request_digest: Digest32,
    pub challenge_nonce: Identifier,
    pub valid_until: u64,
}

impl PresentationContext {
    pub fn digest(&self) -> Result<Digest32, DeKyxError> {
        if [
            self.scope_digest,
            self.audience_digest,
            self.action_digest,
            self.request_digest,
            self.challenge_nonce,
        ]
        .contains(&ZERO)
            || self.valid_until == 0
        {
            return Err(DeKyxError::InvalidPresentationContext);
        }
        let mut hash = Sha256::new();
        hash.update(CONTEXT_DOMAIN);
        hash.update(self.scope_digest);
        hash.update(self.audience_digest);
        hash.update(self.action_digest);
        hash.update(self.request_digest);
        hash.update(self.challenge_nonce);
        hash.update(self.valid_until.to_be_bytes());
        Ok(hash.finalize().into())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnonymousPresentation {
    pub credential: Credential,
    pub context: PresentationContext,
    pub qualifications: Vec<QualificationProof>,
    pub nullifier: [u8; 32],
    pub announcement_commitment: [u8; 32],
    pub announcement_nullifier: [u8; 32],
    pub response_subject: [u8; 32],
    pub response_blinding: [u8; 32],
    pub holder_signature: Vec<u8>,
}

impl AnonymousPresentation {
    pub fn create<R: RngCore + CryptoRng>(
        credential: Credential,
        witness: &CredentialWitness,
        context: PresentationContext,
        required: &[Qualification],
        rng: &mut R,
    ) -> Result<Self, DeKyxError> {
        if credential.subject_commitment != witness.subject_commitment()
            || credential.holder_public_key != witness.holder_public_key()
            || credential.holder_suite != witness.holder_suite()
            || credential.scope_digest != context.scope_digest
            || context.valid_until > credential.valid_until
        {
            return Err(DeKyxError::MismatchedWitnessOrContext);
        }
        let qualifications = required
            .iter()
            .map(|qualification| witness.qualification_proof(qualification))
            .collect::<Result<Vec<_>, _>>()?;
        let nullifier = witness.scope_nullifier(&context.scope_digest);
        let nonce_subject = Scalar::random(&mut *rng);
        let nonce_blinding = Scalar::random(&mut *rng);
        let announcement_commitment = (RISTRETTO_BASEPOINT_POINT * nonce_subject
            + blinding_generator() * nonce_blinding)
            .compress()
            .to_bytes();
        let announcement_nullifier = (nullifier_generator(&context.scope_digest) * nonce_subject)
            .compress()
            .to_bytes();
        let challenge = proof_challenge(
            &credential,
            &context,
            &qualifications,
            &nullifier,
            &announcement_commitment,
            &announcement_nullifier,
        )?;
        let mut presentation = Self {
            credential,
            context,
            qualifications,
            nullifier,
            announcement_commitment,
            announcement_nullifier,
            response_subject: (nonce_subject + challenge * witness.subject_secret).to_bytes(),
            response_blinding: (nonce_blinding + challenge * witness.blinding).to_bytes(),
            holder_signature: Vec::new(),
        };
        presentation.holder_signature = witness
            .holder_key
            .sign(KeyPurpose::Order, &presentation.holder_signing_message()?)
            .map_err(|_| DeKyxError::InvalidAnonymousProof)?;
        Ok(presentation)
    }

    pub fn digest(&self) -> Result<Digest32, DeKyxError> {
        if self.holder_signature.len() != ML_DSA_65_SIG_BYTES {
            return Err(DeKyxError::InvalidAnonymousProof);
        }
        Ok(digest_fields(
            PRESENTATION_DOMAIN,
            &[&self.holder_signing_message()?, &self.holder_signature],
        ))
    }

    pub fn holder_signing_message(&self) -> Result<Digest32, DeKyxError> {
        let mut hash = Sha256::new();
        hash.update(b"DEKYX:HOLDER-PRESENTATION:v2");
        hash.update(self.credential.digest()?);
        hash.update(self.context.digest()?);
        hash.update(self.nullifier);
        hash.update(self.announcement_commitment);
        hash.update(self.announcement_nullifier);
        hash.update(self.response_subject);
        hash.update(self.response_blinding);
        hash.update((self.qualifications.len() as u64).to_be_bytes());
        for proof in &self.qualifications {
            hash.update(proof.qualification.leaf_digest()?);
            hash.update(proof.index.to_be_bytes());
            hash.update(proof.total.to_be_bytes());
            hash.update((proof.siblings.len() as u64).to_be_bytes());
            for sibling in &proof.siblings {
                hash.update(sibling);
            }
        }
        Ok(hash.finalize().into())
    }

    pub fn subject_line_id(&self) -> Result<Digest32, DeKyxError> {
        let mut hash = Sha256::new();
        hash.update(SUBJECT_LINE_DOMAIN);
        hash.update(self.credential.issuer_id);
        hash.update(self.credential.scope_digest);
        hash.update(self.credential.policy_digest);
        hash.update(self.nullifier);
        Ok(hash.finalize().into())
    }

    fn verify_proof(&self) -> Result<(), DeKyxError> {
        MlDsa65Verifier
            .verify(
                KeyPurpose::Order,
                &self.credential.holder_public_key,
                &self.holder_signing_message()?,
                &self.holder_signature,
            )
            .map_err(|_| DeKyxError::InvalidAnonymousProof)?;
        let commitment = decompress_non_identity(self.credential.subject_commitment)?;
        let nullifier = decompress_non_identity(self.nullifier)?;
        let announce_commitment = decompress_point(self.announcement_commitment)?;
        let announce_nullifier = decompress_point(self.announcement_nullifier)?;
        let response_subject = canonical_scalar(self.response_subject)?;
        let response_blinding = canonical_scalar(self.response_blinding)?;
        let challenge = proof_challenge(
            &self.credential,
            &self.context,
            &self.qualifications,
            &self.nullifier,
            &self.announcement_commitment,
            &self.announcement_nullifier,
        )?;
        if RISTRETTO_BASEPOINT_POINT * response_subject + blinding_generator() * response_blinding
            != announce_commitment + commitment * challenge
            || nullifier_generator(&self.context.scope_digest) * response_subject
                != announce_nullifier + nullifier * challenge
        {
            return Err(DeKyxError::InvalidAnonymousProof);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EligibilityRequirement {
    pub issuer_id: Identifier,
    pub issuer_key_epoch: u64,
    pub issuer_namespace_digest: Digest32,
    pub subject_kind: SubjectKind,
    pub scope_digest: Digest32,
    pub policy_digest: Digest32,
    pub required_qualifications: Vec<Qualification>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedEligibility {
    pub issuer_id: Identifier,
    pub issuer_key_epoch: u64,
    pub issuer_namespace_digest: Digest32,
    pub subject_kind: SubjectKind,
    pub subject_commitment: [u8; 32],
    pub subject_nullifier: [u8; 32],
    pub subject_line_id: Digest32,
    pub policy_digest: Digest32,
    pub proof_digest: Digest32,
    pub valid_until: u64,
}

pub trait EligibilityProvider {
    type Evidence;

    fn verify_eligibility(
        &self,
        requirement: &EligibilityRequirement,
        context: &PresentationContext,
        evidence: &Self::Evidence,
        now: u64,
    ) -> Result<VerifiedEligibility, DeKyxError>;
}

pub struct DeKyxVerifier<'a> {
    pub issuers: &'a IssuerRegistry,
    pub status_list: &'a RevocationStatusList,
}

impl EligibilityProvider for DeKyxVerifier<'_> {
    type Evidence = AnonymousPresentation;

    fn verify_eligibility(
        &self,
        requirement: &EligibilityRequirement,
        context: &PresentationContext,
        evidence: &Self::Evidence,
        now: u64,
    ) -> Result<VerifiedEligibility, DeKyxError> {
        if &evidence.context != context
            || context.valid_until < now
            || evidence.credential.issuer_id != requirement.issuer_id
            || evidence.credential.issuer_key_epoch != requirement.issuer_key_epoch
            || requirement.issuer_id == ZERO
            || requirement.issuer_key_epoch == 0
            || requirement.issuer_namespace_digest == ZERO
            || evidence.credential.subject_kind != requirement.subject_kind
            || evidence.credential.scope_digest != requirement.scope_digest
            || context.scope_digest != requirement.scope_digest
            || evidence.credential.policy_digest != requirement.policy_digest
            || evidence.credential.valid_from > now
            || evidence.credential.valid_until < now
            || requirement.required_qualifications.len() > 256
            || evidence.qualifications.len() > 256
        {
            return Err(DeKyxError::RequirementMismatch);
        }
        let issuer = self.issuers.issuer(
            &evidence.credential.issuer_id,
            evidence.credential.issuer_key_epoch,
        )?;
        if !issuer.active_for(requirement.subject_kind, now) {
            return Err(DeKyxError::IssuerNotAuthorized);
        }
        if issuer.namespace_digest != requirement.issuer_namespace_digest {
            return Err(DeKyxError::IssuerNotAuthorized);
        }
        evidence.credential.verify_signature(issuer)?;
        self.status_list.verify(issuer, now)?;
        if self.status_list.status_epoch < evidence.credential.status_epoch {
            return Err(DeKyxError::StaleStatusList);
        }
        let credential_digest = evidence.credential.digest()?;
        if self
            .status_list
            .revoked_credentials
            .binary_search(&credential_digest)
            .is_ok()
        {
            return Err(DeKyxError::RevokedCredential);
        }
        let required: BTreeSet<_> = requirement
            .required_qualifications
            .iter()
            .cloned()
            .collect();
        let supplied: BTreeSet<_> = evidence
            .qualifications
            .iter()
            .map(|proof| proof.qualification.clone())
            .collect();
        if required != supplied || supplied.len() != evidence.qualifications.len() {
            return Err(DeKyxError::RequirementMismatch);
        }
        for proof in &evidence.qualifications {
            proof.verify(&evidence.credential.qualifications_root)?;
        }
        evidence.verify_proof()?;
        Ok(VerifiedEligibility {
            issuer_id: evidence.credential.issuer_id,
            issuer_key_epoch: evidence.credential.issuer_key_epoch,
            issuer_namespace_digest: issuer.namespace_digest,
            subject_kind: evidence.credential.subject_kind,
            subject_commitment: evidence.credential.subject_commitment,
            subject_nullifier: evidence.nullifier,
            subject_line_id: evidence.subject_line_id()?,
            policy_digest: evidence.credential.policy_digest,
            proof_digest: evidence.digest()?,
            valid_until: evidence.credential.valid_until.min(context.valid_until),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PresentationLedger {
    consumed_contexts: BTreeSet<Digest32>,
}

impl PresentationLedger {
    pub fn is_empty(&self) -> bool {
        self.consumed_contexts.is_empty()
    }

    pub fn len(&self) -> usize {
        self.consumed_contexts.len()
    }

    /// Consumes one (scope pseudonym, context) pair. A re-randomized proof of
    /// the same credential for the same context is therefore a replay.
    pub fn consume(
        &mut self,
        subject_nullifier: &[u8; 32],
        context: &PresentationContext,
    ) -> Result<Digest32, DeKyxError> {
        let mut hash = Sha256::new();
        hash.update(b"DEKYX:CONTEXT-USE:v1");
        hash.update(subject_nullifier);
        hash.update(context.digest()?);
        let id: Digest32 = hash.finalize().into();
        if !self.consumed_contexts.insert(id) {
            return Err(DeKyxError::ReplayedContext);
        }
        Ok(id)
    }
}

pub fn qualification_root(qualifications: &[Qualification]) -> Result<Digest32, DeKyxError> {
    let canonical = canonical_qualifications(qualifications)?;
    let mut level = canonical
        .iter()
        .map(Qualification::leaf_digest)
        .collect::<Result<Vec<_>, _>>()?;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            next.push(qualification_node(&pair[0], right));
        }
        level = next;
    }
    Ok(level[0])
}

pub fn qualification_proof(
    qualifications: &[Qualification],
    target: &Qualification,
) -> Result<QualificationProof, DeKyxError> {
    let canonical = canonical_qualifications(qualifications)?;
    let mut position = canonical
        .iter()
        .position(|value| value == target)
        .ok_or(DeKyxError::MissingQualification)?;
    let index = position;
    let total = canonical.len();
    let mut level = canonical
        .iter()
        .map(Qualification::leaf_digest)
        .collect::<Result<Vec<_>, _>>()?;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        let sibling = if position % 2 == 0 {
            *level.get(position + 1).unwrap_or(&level[position])
        } else {
            level[position - 1]
        };
        siblings.push(sibling);
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            next.push(qualification_node(
                &pair[0],
                pair.get(1).unwrap_or(&pair[0]),
            ));
        }
        position /= 2;
        level = next;
    }
    Ok(QualificationProof {
        qualification: target.clone(),
        index: index as u32,
        total: total as u32,
        siblings,
    })
}

fn canonical_qualifications(
    qualifications: &[Qualification],
) -> Result<Vec<Qualification>, DeKyxError> {
    if qualifications.is_empty() || qualifications.len() > 256 {
        return Err(DeKyxError::InvalidQualification);
    }
    let mut canonical = qualifications.to_vec();
    for qualification in &canonical {
        qualification.validate()?;
    }
    canonical.sort();
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(DeKyxError::InvalidQualification);
    }
    Ok(canonical)
}

fn qualification_node(left: &Digest32, right: &Digest32) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(QUALIFICATION_NODE_DOMAIN);
    hash.update(left);
    hash.update(right);
    hash.finalize().into()
}

fn issuance_challenge(
    request: &CredentialRequest,
    announcement_commitment: &[u8; 32],
) -> Result<Scalar, DeKyxError> {
    let mut hash = Sha512::new();
    hash.update(ISSUANCE_PROOF_DOMAIN);
    hash.update(request.statement_digest()?);
    hash.update(announcement_commitment);
    Ok(Scalar::from_hash(hash))
}

fn proof_challenge(
    credential: &Credential,
    context: &PresentationContext,
    qualifications: &[QualificationProof],
    nullifier: &[u8; 32],
    announcement_commitment: &[u8; 32],
    announcement_nullifier: &[u8; 32],
) -> Result<Scalar, DeKyxError> {
    let mut hash = Sha512::new();
    hash.update(PROOF_DOMAIN);
    hash.update(credential.digest()?);
    hash.update(context.digest()?);
    hash.update(nullifier);
    hash.update(announcement_commitment);
    hash.update(announcement_nullifier);
    for proof in qualifications {
        hash.update(proof.qualification.leaf_digest()?);
        hash.update(proof.index.to_be_bytes());
        hash.update(proof.total.to_be_bytes());
        for sibling in &proof.siblings {
            hash.update(sibling);
        }
    }
    Ok(Scalar::from_hash(hash))
}

fn issuer_key(issuer_id: &Identifier, key_epoch: u64) -> String {
    let mut out = String::with_capacity(80);
    for byte in issuer_id {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out.push(':');
    out.push_str(&key_epoch.to_string());
    out
}

fn blinding_generator() -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(BLINDING_GENERATOR_DOMAIN)
}

fn nullifier_generator(scope: &Digest32) -> RistrettoPoint {
    let mut bytes = Vec::with_capacity(NULLIFIER_GENERATOR_DOMAIN.len() + scope.len());
    bytes.extend_from_slice(NULLIFIER_GENERATOR_DOMAIN);
    bytes.extend_from_slice(scope);
    RistrettoPoint::hash_from_bytes::<Sha512>(&bytes)
}

fn decompress_point(bytes: [u8; 32]) -> Result<RistrettoPoint, DeKyxError> {
    CompressedRistretto(bytes)
        .decompress()
        .ok_or(DeKyxError::NonCanonicalPoint)
}

fn decompress_non_identity(bytes: [u8; 32]) -> Result<RistrettoPoint, DeKyxError> {
    let point = decompress_point(bytes)?;
    if point.is_identity() {
        return Err(DeKyxError::NonCanonicalPoint);
    }
    Ok(point)
}

fn canonical_scalar(bytes: [u8; 32]) -> Result<Scalar, DeKyxError> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .ok_or(DeKyxError::NonCanonicalScalar)
}

fn digest_fields(domain: &[u8], fields: &[&[u8]]) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(domain);
    for field in fields {
        hash.update((field.len() as u32).to_be_bytes());
        hash.update(field);
    }
    hash.finalize().into()
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DeKyxError {
    #[error("issuer definition is invalid")]
    InvalidIssuer,
    #[error("issuer key is invalid")]
    InvalidIssuerKey,
    #[error("issuer and epoch are unknown")]
    UnknownIssuer,
    #[error("issuer epoch is already registered")]
    DuplicateIssuerEpoch,
    #[error("issuer key epoch must exceed every registered epoch and change the key")]
    InvalidKeyRotation,
    #[error("no revocation status list was published for this issuer key epoch")]
    MissingStatusList,
    #[error("issuer is not active or authorized for this subject kind")]
    IssuerNotAuthorized,
    #[error("qualification is invalid")]
    InvalidQualification,
    #[error("required qualification is absent")]
    MissingQualification,
    #[error("qualification proof is invalid")]
    InvalidQualificationProof,
    #[error("credential is invalid")]
    InvalidCredential,
    #[error("credential signature is invalid")]
    InvalidCredentialSignature,
    #[error("credential witness is invalid")]
    InvalidWitness,
    #[error("credential issuance proof is invalid")]
    InvalidIssuanceProof,
    #[error("revocation status list is invalid")]
    InvalidStatusList,
    #[error("revocation status signature is invalid")]
    InvalidStatusListSignature,
    #[error("revocation status list is older than the credential")]
    StaleStatusList,
    #[error("credential was revoked")]
    RevokedCredential,
    #[error("presentation context is invalid")]
    InvalidPresentationContext,
    #[error("credential witness or scope context does not match")]
    MismatchedWitnessOrContext,
    #[error("presentation does not meet the requested subject, scope, policy, or attributes")]
    RequirementMismatch,
    #[error("anonymous presentation proof is invalid")]
    InvalidAnonymousProof,
    #[error("context was already consumed for this scope pseudonym")]
    ReplayedContext,
    #[error("Ristretto point is non-canonical or the identity")]
    NonCanonicalPoint,
    #[error("scalar encoding is non-canonical")]
    NonCanonicalScalar,
}
