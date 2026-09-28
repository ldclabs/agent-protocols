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
    pub extra: Option<BTreeMap<String, Value>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeAssessPayload {
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
    pub license: String,
    pub target: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<BTreeMap<String, Value>>,
}

/// Caller-ranked candidates for one ranked-search page. Candidates must be
/// visible and satisfy the request's exact filters; no ranking model is implied.
/// `explanations` are optional per-hit texts keyed by event ID.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct KnowledgeSearchSelection {
    pub candidates: Vec<String>,
    pub ranking: Value,
    pub coverage: Value,
    pub explanations: BTreeMap<String, String>,
}
