use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

macro_rules! wire_enum {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
        pub enum $name { $(#[serde(rename = $wire)] $variant),+ }
    };
}
wire_enum!(KnowledgeKind { Question => "question", Hypothesis => "hypothesis", Definition => "definition", Observation => "observation", Inference => "inference", Procedure => "procedure", Resource => "resource", NegativeResult => "negative_result", Synthesis => "synthesis", Collection => "collection" });
wire_enum!(KnowledgeRelationKind { DerivedFrom => "derived_from", Addresses => "addresses", Tests => "tests", Extends => "extends", Supports => "supports", Contradicts => "contradicts", Supersedes => "supersedes", Contains => "contains" });
wire_enum!(KnowledgeVerdict { Supports => "supports", Challenges => "challenges", Reproduced => "reproduced", NotReproduced => "not_reproduced", Applied => "applied", Inconclusive => "inconclusive" });
wire_enum!(EvidenceRole { Source => "source", Input => "input", Output => "output", Environment => "environment", Validation => "validation" });
wire_enum!(EvidenceStatus { Unchecked => "unchecked", Matched => "matched", Mismatched => "mismatched", Unavailable => "unavailable" });
wire_enum!(SearchMode { Lexical => "lexical", Semantic => "semantic", Hybrid => "hybrid" });
wire_enum!(PublicVisibility { Public => "public" });

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeContext {
    pub scope: String,
    pub conditions: Vec<String>,
    pub limitations: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeReproduction {
    pub environment: String,
    pub steps: Vec<String>,
    pub expected: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeEvidence {
    pub url: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<EvidenceRole>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeRelation {
    pub relation: KnowledgeRelationKind,
    pub target: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeProfileReference {
    pub url: String,
    pub digest: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeProfileBinding {
    pub profile: KnowledgeProfileReference,
    pub data: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgePublishPayload {
    pub visibility: PublicVisibility,
    pub license: String,
    pub kind: KnowledgeKind,
    pub title: String,
    pub statement: String,
    pub language: String,
    pub context: KnowledgeContext,
    pub basis: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Vec<KnowledgeEvidence>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reproduction: Option<KnowledgeReproduction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relations: Option<Vec<KnowledgeRelation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profiles: Option<Vec<KnowledgeProfileBinding>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub learned_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<BTreeMap<String, Value>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeAssessPayload {
    pub visibility: PublicVisibility,
    pub license: String,
    pub target: String,
    pub verdict: KnowledgeVerdict,
    pub summary: String,
    pub context: KnowledgeContext,
    pub basis: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Vec<KnowledgeEvidence>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reproduction: Option<KnowledgeReproduction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profiles: Option<Vec<KnowledgeProfileBinding>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<BTreeMap<String, Value>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeRetractPayload {
    pub visibility: PublicVisibility,
    pub license: String,
    pub target: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<BTreeMap<String, Value>>,
}

/// Extensible service receipt. Envelope stays raw until boundary validation,
/// preventing serde from silently dropping unknown envelope members.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct KnowledgeAcceptanceRecord {
    pub envelope: Value,
    pub seq: u64,
    pub accepted_at: i64,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Profile validation is separate from core binding validity. A caller must
/// supply its discipline's validator and verify all normative dependencies.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProfileStatus {
    Unavailable,
    Unchecked,
    Conformant,
    Nonconformant,
}

/// Run an explicitly supplied profile validator only after artifact integrity
/// and normative dependency integrity are established. No network or execution.
pub fn validate_knowledge_profile<F>(
    binding: &KnowledgeProfileBinding,
    artifact: Option<&[u8]>,
    dependencies_verified: bool,
    validator: Option<F>,
) -> crate::Result<ProfileStatus>
where
    F: FnOnce(&[u8], &BTreeMap<String, Value>) -> crate::Result<bool>,
{
    super::validate_knowledge_schema(&serde_json::to_value(binding)?, "profileBinding")?;
    super::https_url(&binding.profile.url)?;
    super::validate_knowledge_digest(&binding.profile.digest)?;
    let Some(validator) = validator else {
        return Ok(ProfileStatus::Unchecked);
    };
    let Some(artifact) = artifact else {
        return Ok(ProfileStatus::Unavailable);
    };
    if super::verify_knowledge_evidence(Some(&binding.profile.digest), Some(artifact), true, true)
        != EvidenceStatus::Matched
        || !dependencies_verified
    {
        return Ok(ProfileStatus::Unavailable);
    }
    Ok(if validator(artifact, &binding.data)? {
        ProfileStatus::Conformant
    } else {
        ProfileStatus::Nonconformant
    })
}

/// Local validation metadata bound to one signed event and exact profile.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnowledgeProfileResult {
    pub event_id: String,
    pub profile_digest: String,
    pub status: ProfileStatus,
}

pub fn validate_knowledge_event_profile<F>(
    envelope: &Value,
    digest: &str,
    artifact: Option<&[u8]>,
    dependencies_verified: bool,
    validator: Option<F>,
) -> crate::Result<KnowledgeProfileResult>
where
    F: FnOnce(&[u8], &BTreeMap<String, Value>) -> crate::Result<bool>,
{
    super::validate_knowledge_envelope(envelope)?;
    let binding = super::arr(&envelope["event"]["payload"]["profiles"])
        .iter()
        .find(|b| b["profile"]["digest"] == digest)
        .ok_or_else(|| super::fail("invalid_request", "event does not declare this profile"))?;
    let binding: KnowledgeProfileBinding = serde_json::from_value(binding.clone())?;
    Ok(KnowledgeProfileResult {
        event_id: super::string(&envelope["hash"]).to_owned(),
        profile_digest: digest.to_owned(),
        status: validate_knowledge_profile(&binding, artifact, dependencies_verified, validator)?,
    })
}
