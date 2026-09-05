use std::collections::BTreeSet;

use dekyx_core::{
    AnonymousPresentation, CredentialIssuer, CredentialRequest, CredentialWitness, DeKyxError,
    DeKyxVerifier, EligibilityProvider, EligibilityRequirement, IssuerDefinition, IssuerDirectory,
    IssuerRegistry, IssuerStatus, PresentationContext, PresentationLedger, Qualification,
    SubjectKind,
};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

fn id(byte: u8) -> [u8; 32] {
    [byte; 32]
}

#[test]
fn selective_qualification_proof_hides_other_attributes_and_consumes_context_once() {
    let signing = SigningKey::generate(&mut OsRng);
    let definition = IssuerDefinition {
        issuer_id: id(1),
        key_epoch: 1,
        public_key: signing.verifying_key().to_bytes(),
        pq_public_key: zkfmi_crypto::traits::Signer::public_key(
            &zkfmi_crypto::test_support::public_fixture_pq_key(
                &(signing.verifying_key().to_bytes()),
            ),
        ),
        signature_suite: zkfmi_crypto::suite::Suite::new(
            zkfmi_crypto::suite::SuiteId::Ed25519MlDsa65,
        ),
        supported_subjects: BTreeSet::from([SubjectKind::LegalEntity]),
        namespace_digest: id(2),
        valid_from: 100,
        valid_until: 1_000,
        status: IssuerStatus::Active,
    };
    let issuer = CredentialIssuer::new(
        definition.clone(),
        (signing).clone(),
        zkfmi_crypto::test_support::public_fixture_pq_key(&(signing).verifying_key().to_bytes()),
    )
    .unwrap();
    let qualifications = vec![
        Qualification {
            namespace: "global.lei".into(),
            predicate_digest: id(3),
        },
        Qualification {
            namespace: "jp.kyb".into(),
            predicate_digest: id(4),
        },
        Qualification {
            namespace: "market.professional".into(),
            predicate_digest: id(5),
        },
    ];
    let required = qualifications[1].clone();
    let witness = CredentialWitness::random(qualifications.clone(), &mut OsRng).unwrap();
    let credential_request = CredentialRequest {
        credential_id: id(6),
        issuer_id: id(1),
        issuer_key_epoch: 1,
        subject_kind: SubjectKind::LegalEntity,
        subject_commitment: witness.subject_commitment(),
        scope_digest: id(7),
        policy_digest: id(8),
        qualifications,
        status_epoch: 2,
        valid_from: 100,
        valid_until: 900,
    };
    let issuance_proof = witness
        .prove_issuance(&credential_request, &mut OsRng)
        .unwrap();
    let credential = issuer.issue(credential_request, issuance_proof).unwrap();
    let status = issuer.issue_status_list(3, 100, 950, vec![]).unwrap();
    let mut registry = IssuerRegistry::default();
    registry.register(definition).unwrap();
    let verifier = DeKyxVerifier {
        issuers: &registry,
        status_list: &status,
    };
    let requirement = EligibilityRequirement {
        issuer_id: id(1),
        issuer_key_epoch: 1,
        issuer_namespace_digest: id(2),
        subject_kind: SubjectKind::LegalEntity,
        scope_digest: id(7),
        policy_digest: id(8),
        required_qualifications: vec![required.clone()],
    };
    let context = PresentationContext {
        scope_digest: id(7),
        audience_digest: id(9),
        action_digest: id(10),
        request_digest: id(11),
        challenge_nonce: id(12),
        valid_until: 800,
    };
    let proof = AnonymousPresentation::create(
        credential.clone(),
        &witness,
        context.clone(),
        std::slice::from_ref(&required),
        &mut OsRng,
    )
    .unwrap();
    assert_eq!(proof.qualifications.len(), 1);
    let verified = verifier
        .verify_eligibility(&requirement, &context, &proof, 200)
        .unwrap();
    for mutation in 0..4 {
        let mut changed = proof.clone();
        match mutation {
            0 => changed.credential.signature.first[0] ^= 1,
            1 => changed.credential.signature.pq[0] ^= 1,
            2 => {
                changed.credential.signature.pq.pop().unwrap();
            }
            3 => changed.credential.signature.pq.clear(),
            _ => unreachable!(),
        }
        assert_eq!(
            verifier.verify_eligibility(&requirement, &context, &changed, 200),
            Err(DeKyxError::InvalidCredentialSignature),
            "accepted credential with only one valid signature component",
        );
    }
    for mutation in 0..3 {
        let mut changed = status.clone();
        match mutation {
            0 => changed.signature.first[0] ^= 1,
            1 => changed.signature.pq[0] ^= 1,
            2 => changed.signature.pq.clear(),
            _ => unreachable!(),
        }
        let changed_verifier = DeKyxVerifier {
            issuers: &registry,
            status_list: &changed,
        };
        assert_eq!(
            changed_verifier.verify_eligibility(&requirement, &context, &proof, 200),
            Err(DeKyxError::InvalidStatusListSignature),
        );
    }
    let mut ledger = PresentationLedger::default();
    ledger
        .consume(&verified.subject_nullifier, &context)
        .unwrap();

    let rerandomized = AnonymousPresentation::create(
        credential,
        &witness,
        context.clone(),
        std::slice::from_ref(&required),
        &mut OsRng,
    )
    .unwrap();
    let rerandomized_verified = verifier
        .verify_eligibility(&requirement, &context, &rerandomized, 200)
        .unwrap();
    assert_ne!(proof.digest().unwrap(), rerandomized.digest().unwrap());
    assert_eq!(
        ledger.consume(&rerandomized_verified.subject_nullifier, &context),
        Err(DeKyxError::ReplayedContext)
    );
}

#[test]
fn duplicate_issuer_epoch_does_not_replace_the_existing_trust_anchor() {
    let first = SigningKey::generate(&mut OsRng);
    let second = SigningKey::generate(&mut OsRng);
    let definition = |key: &SigningKey| IssuerDefinition {
        issuer_id: id(20),
        key_epoch: 5,
        public_key: key.verifying_key().to_bytes(),
        pq_public_key: zkfmi_crypto::traits::Signer::public_key(
            &zkfmi_crypto::test_support::public_fixture_pq_key(&(key.verifying_key().to_bytes())),
        ),
        signature_suite: zkfmi_crypto::suite::Suite::new(
            zkfmi_crypto::suite::SuiteId::Ed25519MlDsa65,
        ),
        supported_subjects: BTreeSet::from([SubjectKind::Person]),
        namespace_digest: id(21),
        valid_from: 1,
        valid_until: 100,
        status: IssuerStatus::Active,
    };
    let mut registry = IssuerRegistry::default();
    registry.register(definition(&first)).unwrap();
    assert_eq!(
        registry.register(definition(&second)),
        Err(DeKyxError::DuplicateIssuerEpoch)
    );
    assert_eq!(
        registry.issuer(&id(20), 5).unwrap().public_key,
        first.verifying_key().to_bytes()
    );
}

#[test]
fn issuance_rejects_a_commitment_not_opened_by_the_holder_proof() {
    let signing = SigningKey::generate(&mut OsRng);
    let definition = IssuerDefinition {
        issuer_id: id(30),
        key_epoch: 1,
        public_key: signing.verifying_key().to_bytes(),
        pq_public_key: zkfmi_crypto::traits::Signer::public_key(
            &zkfmi_crypto::test_support::public_fixture_pq_key(
                &(signing.verifying_key().to_bytes()),
            ),
        ),
        signature_suite: zkfmi_crypto::suite::Suite::new(
            zkfmi_crypto::suite::SuiteId::Ed25519MlDsa65,
        ),
        supported_subjects: BTreeSet::from([SubjectKind::LegalEntity]),
        namespace_digest: id(31),
        valid_from: 1,
        valid_until: 1_000,
        status: IssuerStatus::Active,
    };
    let issuer = CredentialIssuer::new(
        definition,
        (signing).clone(),
        zkfmi_crypto::test_support::public_fixture_pq_key(&(signing).verifying_key().to_bytes()),
    )
    .unwrap();
    let qualification = Qualification {
        namespace: "global.lei".into(),
        predicate_digest: id(32),
    };
    let holder = CredentialWitness::random(vec![qualification.clone()], &mut OsRng).unwrap();
    let substitute = CredentialWitness::random(vec![qualification.clone()], &mut OsRng).unwrap();
    let request = CredentialRequest {
        credential_id: id(33),
        issuer_id: id(30),
        issuer_key_epoch: 1,
        subject_kind: SubjectKind::LegalEntity,
        subject_commitment: holder.subject_commitment(),
        scope_digest: id(34),
        policy_digest: id(35),
        qualifications: vec![qualification],
        status_epoch: 1,
        valid_from: 1,
        valid_until: 900,
    };
    let proof = holder.prove_issuance(&request, &mut OsRng).unwrap();
    let mut substituted_request = request;
    substituted_request.subject_commitment = substitute.subject_commitment();
    assert_eq!(
        issuer.issue(substituted_request, proof),
        Err(DeKyxError::InvalidIssuanceProof)
    );
}

fn issuer_definition(
    key: &SigningKey,
    issuer: u8,
    epoch: u64,
    namespace: u8,
    valid_until: u64,
) -> IssuerDefinition {
    IssuerDefinition {
        issuer_id: id(issuer),
        key_epoch: epoch,
        public_key: key.verifying_key().to_bytes(),
        pq_public_key: zkfmi_crypto::traits::Signer::public_key(
            &zkfmi_crypto::test_support::public_fixture_pq_key(&(key.verifying_key().to_bytes())),
        ),
        signature_suite: zkfmi_crypto::suite::Suite::new(
            zkfmi_crypto::suite::SuiteId::Ed25519MlDsa65,
        ),
        supported_subjects: BTreeSet::from([SubjectKind::LegalEntity]),
        namespace_digest: id(namespace),
        valid_from: 1,
        valid_until,
        status: IssuerStatus::Active,
    }
}

fn issue_for(
    issuer: &CredentialIssuer,
    definition: &IssuerDefinition,
    witness: &CredentialWitness,
    qualification: &Qualification,
    credential_id: u8,
    scope: u8,
    policy: u8,
) -> dekyx_core::Credential {
    let request = CredentialRequest {
        credential_id: id(credential_id),
        issuer_id: definition.issuer_id,
        issuer_key_epoch: definition.key_epoch,
        subject_kind: SubjectKind::LegalEntity,
        subject_commitment: witness.subject_commitment(),
        scope_digest: id(scope),
        policy_digest: id(policy),
        qualifications: vec![qualification.clone()],
        status_epoch: 1,
        valid_from: 1,
        valid_until: 900,
    };
    let proof = witness.prove_issuance(&request, &mut OsRng).unwrap();
    issuer.issue(request, proof).unwrap()
}

fn requirement_for(
    definition: &IssuerDefinition,
    scope: u8,
    policy: u8,
    qualification: &Qualification,
) -> EligibilityRequirement {
    EligibilityRequirement {
        issuer_id: definition.issuer_id,
        issuer_key_epoch: definition.key_epoch,
        issuer_namespace_digest: definition.namespace_digest,
        subject_kind: SubjectKind::LegalEntity,
        scope_digest: id(scope),
        policy_digest: id(policy),
        required_qualifications: vec![qualification.clone()],
    }
}

fn context_for(scope: u8, nonce: u8) -> PresentationContext {
    PresentationContext {
        scope_digest: id(scope),
        audience_digest: id(200),
        action_digest: id(201),
        request_digest: id(202),
        challenge_nonce: id(nonce),
        valid_until: 800,
    }
}

#[test]
fn key_rotation_bounds_the_old_epoch_and_keeps_the_subject_line() {
    let first_key = SigningKey::generate(&mut OsRng);
    let second_key = SigningKey::generate(&mut OsRng);
    let first = issuer_definition(&first_key, 40, 1, 41, 1_000);
    let second = issuer_definition(&second_key, 40, 2, 41, 1_000);
    let first_issuer = CredentialIssuer::new(
        first.clone(),
        (first_key.clone()).clone(),
        zkfmi_crypto::test_support::public_fixture_pq_key(
            &(first_key.clone()).verifying_key().to_bytes(),
        ),
    )
    .unwrap();
    let second_issuer = CredentialIssuer::new(
        second.clone(),
        (second_key).clone(),
        zkfmi_crypto::test_support::public_fixture_pq_key(&(second_key).verifying_key().to_bytes()),
    )
    .unwrap();
    let qualification = Qualification {
        namespace: "jp.kyb".into(),
        predicate_digest: id(42),
    };
    let witness = CredentialWitness::random(vec![qualification.clone()], &mut OsRng).unwrap();
    let old_credential = issue_for(&first_issuer, &first, &witness, &qualification, 43, 44, 45);

    let mut directory = IssuerDirectory::default();
    directory.register_issuer(first.clone()).unwrap();
    // A later epoch cannot be registered without bounding the earlier one.
    assert_eq!(
        directory.register_issuer(second.clone()),
        Err(DeKyxError::InvalidKeyRotation)
    );
    // Fail closed until the issuer publishes a status list for the epoch.
    assert_eq!(
        directory.verifier(&id(40), 1).map(|_| ()),
        Err(DeKyxError::MissingStatusList)
    );
    directory
        .publish_status_list(first_issuer.issue_status_list(1, 1, 950, vec![]).unwrap())
        .unwrap();
    let requirement = requirement_for(&first, 44, 45, &qualification);
    let context = context_for(44, 46);
    let old_presentation = AnonymousPresentation::create(
        old_credential.clone(),
        &witness,
        context.clone(),
        std::slice::from_ref(&qualification),
        &mut OsRng,
    )
    .unwrap();
    let before_rotation = directory
        .verifier(&id(40), 1)
        .unwrap()
        .verify_eligibility(&requirement, &context, &old_presentation, 200)
        .unwrap();

    // Rotation with the same key or a non-increasing epoch is refused.
    let same_key = issuer_definition(&first_key, 40, 2, 41, 1_000);
    assert_eq!(
        directory.rotate_key(same_key, 300),
        Err(DeKyxError::InvalidKeyRotation)
    );
    directory.rotate_key(second.clone(), 300).unwrap();
    assert_eq!(
        directory.current_epoch(&id(40), SubjectKind::LegalEntity, 250),
        Some(2)
    );
    assert_eq!(directory.issuer(&id(40), 1).unwrap().valid_until, 300);

    // Within the grace window the old epoch still verifies.
    directory
        .verifier(&id(40), 1)
        .unwrap()
        .verify_eligibility(&requirement, &context, &old_presentation, 250)
        .unwrap();
    // After the grace window it does not.
    assert_eq!(
        directory.verifier(&id(40), 1).unwrap().verify_eligibility(
            &requirement,
            &context,
            &old_presentation,
            400
        ),
        Err(DeKyxError::IssuerNotAuthorized)
    );

    // The same subject re-issued under the new epoch continues the same line.
    directory
        .publish_status_list(second_issuer.issue_status_list(1, 1, 950, vec![]).unwrap())
        .unwrap();
    let new_credential = issue_for(
        &second_issuer,
        &second,
        &witness,
        &qualification,
        47,
        44,
        45,
    );
    let new_presentation = AnonymousPresentation::create(
        new_credential,
        &witness,
        context.clone(),
        std::slice::from_ref(&qualification),
        &mut OsRng,
    )
    .unwrap();
    let after_rotation = directory
        .verifier(&id(40), 2)
        .unwrap()
        .verify_eligibility(
            &requirement_for(&second, 44, 45, &qualification),
            &context,
            &new_presentation,
            400,
        )
        .unwrap();
    assert_eq!(
        after_rotation.subject_nullifier,
        before_rotation.subject_nullifier
    );
    assert_eq!(
        after_rotation.subject_line_id,
        before_rotation.subject_line_id
    );
    assert_ne!(
        after_rotation.issuer_key_epoch,
        before_rotation.issuer_key_epoch
    );

    // Immediate retirement is the compromise path: the old epoch is revoked.
    let third = issuer_definition(&SigningKey::generate(&mut OsRng), 40, 3, 41, 1_000);
    directory.rotate_key(third, 0).unwrap();
    assert_eq!(
        directory.issuer(&id(40), 2).unwrap().status,
        IssuerStatus::Revoked
    );
    assert_eq!(
        directory.verifier(&id(40), 2).unwrap().verify_eligibility(
            &requirement_for(&second, 44, 45, &qualification),
            &context,
            &new_presentation,
            400,
        ),
        Err(DeKyxError::IssuerNotAuthorized)
    );
}

#[test]
fn different_scopes_are_not_publicly_linkable() {
    let key = SigningKey::generate(&mut OsRng);
    let definition = issuer_definition(&key, 50, 1, 51, 1_000);
    let issuer = CredentialIssuer::new(
        definition.clone(),
        (key).clone(),
        zkfmi_crypto::test_support::public_fixture_pq_key(&(key).verifying_key().to_bytes()),
    )
    .unwrap();
    let qualification = Qualification {
        namespace: "jp.kyb".into(),
        predicate_digest: id(52),
    };
    let witness_a = CredentialWitness::random(vec![qualification.clone()], &mut OsRng).unwrap();
    let witness_b = witness_a.rerandomize(&mut OsRng);
    let credential_a = issue_for(&issuer, &definition, &witness_a, &qualification, 53, 54, 55);
    let credential_b = issue_for(&issuer, &definition, &witness_b, &qualification, 56, 57, 55);
    assert_ne!(
        credential_a.subject_commitment,
        credential_b.subject_commitment
    );

    let mut directory = IssuerDirectory::default();
    directory.register_issuer(definition.clone()).unwrap();
    directory
        .publish_status_list(issuer.issue_status_list(1, 1, 950, vec![]).unwrap())
        .unwrap();
    let verifier = directory.verifier(&id(50), 1).unwrap();
    let context_a = context_for(54, 58);
    let context_b = context_for(57, 59);
    let presentation_a = AnonymousPresentation::create(
        credential_a.clone(),
        &witness_a,
        context_a.clone(),
        std::slice::from_ref(&qualification),
        &mut OsRng,
    )
    .unwrap();
    let presentation_b = AnonymousPresentation::create(
        credential_b,
        &witness_b,
        context_b.clone(),
        std::slice::from_ref(&qualification),
        &mut OsRng,
    )
    .unwrap();
    let verified_a = verifier
        .verify_eligibility(
            &requirement_for(&definition, 54, 55, &qualification),
            &context_a,
            &presentation_a,
            200,
        )
        .unwrap();
    let verified_b = verifier
        .verify_eligibility(
            &requirement_for(&definition, 57, 55, &qualification),
            &context_b,
            &presentation_b,
            200,
        )
        .unwrap();
    // Nothing that reaches a verifier ties the two scopes together.
    assert_ne!(verified_a.subject_commitment, verified_b.subject_commitment);
    assert_ne!(verified_a.subject_nullifier, verified_b.subject_nullifier);
    assert_ne!(verified_a.subject_line_id, verified_b.subject_line_id);
    assert_ne!(verified_a.proof_digest, verified_b.proof_digest);

    // A credential for one scope cannot satisfy the other scope's requirement,
    // and a witness cannot present a credential whose commitment it does not open.
    assert_eq!(
        verifier.verify_eligibility(
            &requirement_for(&definition, 57, 55, &qualification),
            &context_b,
            &presentation_a,
            200,
        ),
        Err(DeKyxError::RequirementMismatch)
    );
    assert_eq!(
        AnonymousPresentation::create(
            credential_a,
            &witness_b,
            context_a,
            std::slice::from_ref(&qualification),
            &mut OsRng,
        )
        .map(|_| ()),
        Err(DeKyxError::MismatchedWitnessOrContext)
    );
}

#[test]
fn directory_rejects_stale_status_lists_and_reloads_only_validated_state() {
    let key = SigningKey::generate(&mut OsRng);
    let definition = issuer_definition(&key, 60, 1, 61, 1_000);
    let issuer = CredentialIssuer::new(
        definition.clone(),
        (key).clone(),
        zkfmi_crypto::test_support::public_fixture_pq_key(&(key).verifying_key().to_bytes()),
    )
    .unwrap();
    let mut directory = IssuerDirectory::default();
    directory.register_issuer(definition.clone()).unwrap();
    let newer = issuer.issue_status_list(3, 1, 950, vec![id(62)]).unwrap();
    let older = issuer.issue_status_list(2, 1, 950, vec![]).unwrap();
    directory.publish_status_list(newer.clone()).unwrap();
    // An older list cannot un-revoke by replacing the newer one.
    assert_eq!(
        directory.publish_status_list(older),
        Err(DeKyxError::StaleStatusList)
    );
    assert_eq!(
        directory.publish_status_list(newer.clone()),
        Err(DeKyxError::StaleStatusList)
    );
    // A list signed by an unregistered epoch is refused.
    let stranger = CredentialIssuer::new(
        issuer_definition(&SigningKey::generate(&mut OsRng), 60, 2, 61, 1_000),
        (SigningKey::generate(&mut OsRng)).clone(),
        zkfmi_crypto::test_support::public_fixture_pq_key(
            &(SigningKey::generate(&mut OsRng))
                .verifying_key()
                .to_bytes(),
        ),
    );
    assert!(stranger.is_err());

    let encoded = serde_json::to_string(&directory).unwrap();
    let reloaded: IssuerDirectory = serde_json::from_str(&encoded).unwrap();
    assert_eq!(reloaded, directory);
    assert_eq!(reloaded.status_list(&id(60), 1), Some(&newer));

    // Tampering with a persisted status list breaks its signature on reload.
    let tampered = encoded.replace(
        &format!("\"statusEpoch\":{}", newer.status_epoch),
        "\"statusEpoch\":9",
    );
    assert!(serde_json::from_str::<IssuerDirectory>(&tampered).is_err());
    // A persisted issuer whose key does not match its map key is refused.
    let mut record: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    let issuers = record["issuers"].as_object_mut().unwrap();
    let (key_name, value) = issuers
        .iter()
        .next()
        .map(|(k, v)| (k.clone(), v.clone()))
        .unwrap();
    issuers.remove(&key_name);
    issuers.insert("00:1".into(), value);
    assert!(serde_json::from_value::<IssuerDirectory>(record).is_err());
}

#[test]
fn issuer_rotation_requires_new_pq_material_and_legacy_records_fail_closed() {
    let first = issuer_definition(&SigningKey::generate(&mut OsRng), 87, 1, 88, 1_000);
    let mut next = issuer_definition(&SigningKey::generate(&mut OsRng), 87, 2, 88, 2_000);
    let mut directory = IssuerDirectory::default();
    directory.register_issuer(first.clone()).unwrap();
    let before = serde_json::to_vec(&directory).unwrap();
    next.pq_public_key = first.pq_public_key.clone();
    assert_eq!(
        directory.rotate_key(next, 500),
        Err(DeKyxError::InvalidKeyRotation)
    );
    assert_eq!(serde_json::to_vec(&directory).unwrap(), before);

    let mut legacy = serde_json::to_value(&first).unwrap();
    legacy.as_object_mut().unwrap().remove("pqPublicKey");
    assert!(serde_json::from_value::<IssuerDefinition>(legacy).is_err());
    let mut unsupported = first;
    unsupported.signature_suite =
        zkfmi_crypto::suite::Suite::new(zkfmi_crypto::suite::SuiteId::Ed25519);
    assert_eq!(unsupported.validate(), Err(DeKyxError::InvalidIssuer));
}
