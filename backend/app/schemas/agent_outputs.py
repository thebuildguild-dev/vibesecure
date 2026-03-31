"""
Pydantic output models for every agent.

All models use ``extra="forbid"`` so unexpected keys from the LLM
are caught immediately instead of silently passing through.
"""

from pydantic import BaseModel, ConfigDict, Field

# ── Shared / reusable fragments ─────────────────────────────────


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = ""
    severity: str = "info"
    fix: str = ""


class PlatformConfigs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vercel: str = ""
    netlify: str = ""
    nginx: str = ""
    apache: str = ""


# ── Deepfake service ────────────────────────────────────────────


class TriageResult(BaseModel):
    """Output of :class:`DeepfakeTriageAgent`."""

    model_config = ConfigDict(extra="forbid")

    triage_verdict: str = "inconclusive"
    confidence: int = Field(0, ge=0, le=100)
    quick_observations: list[str] = []
    needs_forensic: bool = True
    risk_indicators: list[str] = []
    triage_reasoning: str = ""


class FrameAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    frame_index: int = 0
    facial_consistency_score: int = Field(50, ge=0, le=100)
    lighting_score: int = Field(50, ge=0, le=100)
    edge_quality_score: int = Field(50, ge=0, le=100)
    background_score: int = Field(50, ge=0, le=100)
    texture_score: int = Field(50, ge=0, le=100)
    anomalies_detected: list[str] = []
    artifact_type: str = "none"


class ForensicBatchResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    frame_analyses: list[FrameAnalysis] = []
    batch_summary: str = ""


class AudioAnalysisResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    audio_risk_level: str = "low"
    audio_observations: list[str] = []
    lip_sync_risk: str = "low"
    voice_clone_indicators: list[str] = []


class DatasetMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dataset: str = ""
    similarity: int = Field(0, ge=0, le=100)
    technique: str = ""
    notes: str = ""


class EnsembleRAGResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dataset_matches: list[DatasetMatch] = []
    plain_english_explanation: str = ""
    heatmap_regions: list[str] = []
    generation_technique_guess: str = "Unknown"


# ── Threat intelligence service ──────────────────────────────────


class ThreatFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    technique_id: str = ""
    technique_name: str = ""
    severity: str = "low"
    description: str = ""
    evidence: str = ""
    mitigations: list[str] = []


class ThreatPatternResult(BaseModel):
    """Output of :class:`ThreatPatternAgent` content analysis."""

    model_config = ConfigDict(extra="forbid")

    threats_found: list[ThreatFinding] = []
    overall_threat_level: str = "none"
    confidence: int = Field(0, ge=0, le=100)
    analysis_summary: str = ""


class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="forbid")
    category: str = ""
    technique_id: str = ""
    severity: str = "low"
    description: str = ""
    evidence: str = ""
    fix: str = ""


class AISystemTestResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vulnerabilities: list[Vulnerability] = []
    risk_score: int = Field(0, ge=0, le=100)
    guardrail_assessment: str = ""
    recommended_fixes: list[str] = []


class PredictedAttack(BaseModel):
    model_config = ConfigDict(extra="forbid")
    attack_type: str = ""
    probability: str = "low"
    impact: str = "low"
    timeframe: str = "long_term"
    description: str = ""
    prevention: str = ""


class AttackSurface(BaseModel):
    model_config = ConfigDict(extra="forbid")
    component: str = ""
    exposure_level: str = "low"
    vulnerabilities: list[str] = []


class ThreatActorProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    likely_type: str = "automated_bot"
    motivation: str = "disruption"
    capability_required: str = "low"


class PriorityMitigation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = ""
    impact: str = "medium"
    effort: str = "medium"
    reduces_risk_by: int = Field(0, ge=0, le=100)


class PredictiveRiskResult(BaseModel):
    """Output of :class:`PredictiveRiskAgent`."""

    model_config = ConfigDict(extra="forbid")

    predicted_attacks: list[PredictedAttack] = []
    risk_score: int = Field(0, ge=0, le=100)
    risk_level: str = "medium"
    risk_trajectory: str = "stable"
    attack_surface: list[AttackSurface] = []
    threat_actor_profile: ThreatActorProfile = ThreatActorProfile()
    priority_mitigations: list[PriorityMitigation] = []
    executive_summary: str = ""


# ── Responsible AI service ───────────────────────────────────────


class DimensionScore(BaseModel):
    model_config = ConfigDict(extra="forbid")
    score: int = Field(0, ge=0, le=100)
    findings: str = ""
    recommendations: list[str] = []


class NISTRating(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rating: str = "not_addressed"
    notes: str = ""


class SAIFAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    principle: str = ""
    compliance: str = "non_compliant"
    notes: str = ""


class AuditorResult(BaseModel):
    """Output of :class:`ResponsibleAIAuditorAgent`."""

    model_config = ConfigDict(extra="forbid")

    scorecard: dict[str, DimensionScore] = {}
    nist_assessment: dict[str, NISTRating] = {}
    saif_assessment: list[SAIFAssessment] = []
    overall_score: int = Field(0, ge=0, le=100)
    overall_grade: str = "N/A"
    plain_english_summary: str = ""
    top_recommendations: list[str] = []
    reasoning_trace: str = ""


class BiasAssessmentItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dimension: str = ""
    detected: bool = False
    severity: str = "none"
    evidence: str = ""
    affected_groups: list[str] = []
    mitigation: str = ""


class BiasFairnessResult(BaseModel):
    """Output of :class:`BiasFairnessAgent`."""

    model_config = ConfigDict(extra="forbid")

    bias_assessment: list[BiasAssessmentItem] = []
    representation_score: int = Field(0, ge=0, le=100)
    stereotype_risk: str = "none"
    accessibility_score: int = Field(0, ge=0, le=100)
    disparate_impact_risk: str = "none"
    overall_bias_score: int = Field(0, ge=0, le=100)
    overall_fairness_grade: str = "N/A"
    key_concerns: list[str] = []
    recommendations: list[str] = []
    plain_english_summary: str = ""


# ── Privacy service ──────────────────────────────────────────────


class PIIFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = ""
    severity: str = "low"
    location: str = ""
    recommendation: str = ""


class ConsentAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    grade: str = "N/A"
    is_compliant: bool = False
    issues: list[str] = []
    recommendations: list[str] = []


class PrivacyPolicyAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    exists: bool = False
    grade: str = "N/A"
    missing_sections: list[str] = []
    recommendations: list[str] = []


class DataCollectionForms(BaseModel):
    model_config = ConfigDict(extra="forbid")
    count: int = 0
    fields: list[str] = []


class PrivacyScanResult(BaseModel):
    """Output of :class:`PrivacyScannerAgent` AI analysis."""

    model_config = ConfigDict(extra="forbid")

    pii_findings: list[PIIFinding] = []
    consent_assessment: ConsentAssessment = ConsentAssessment()
    privacy_policy_assessment: PrivacyPolicyAssessment = PrivacyPolicyAssessment()
    tracking_scripts: list[str] = []
    data_collection_forms: DataCollectionForms = DataCollectionForms()
    overall_privacy_score: int = Field(0, ge=0, le=100)
    summary: str = ""


class PrivacyContentResult(BaseModel):
    """Output of :class:`PrivacyScannerAgent` content-only analysis."""

    model_config = ConfigDict(extra="forbid")

    pii_findings: list[PIIFinding] = []
    privacy_concerns: list[str] = []
    overall_privacy_score: int = Field(0, ge=0, le=100)
    summary: str = ""


class RegulatoryViolation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    article: str = ""
    section: str = ""
    title: str = ""
    status: str = "non_compliant"
    finding: str = ""
    required_action: str = ""
    priority: str = "medium"


class RegulationMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")
    applicable: bool = False
    compliance_score: int = Field(0, ge=0, le=100)
    violations: list[RegulatoryViolation] = []
    recommendations: list[str] = []


class AIActObligation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    obligation: str = ""
    status: str = "not_met"
    required_action: str = ""


class EUAIActMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")
    applicable: bool = False
    risk_category: str = "minimal"
    compliance_score: int = Field(0, ge=0, le=100)
    obligations: list[AIActObligation] = []
    recommendations: list[str] = []


class ReportMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assessment_date: str = ""
    regulations_checked: list[str] = []
    confidence_level: str = "medium"


class RegulatoryMappingResult(BaseModel):
    """Output of :class:`RegulatoryMapperAgent`."""

    model_config = ConfigDict(extra="forbid")

    gdpr_mapping: RegulationMapping = RegulationMapping()
    ccpa_mapping: RegulationMapping = RegulationMapping()
    dpdp_mapping: RegulationMapping = RegulationMapping()
    eu_ai_act_mapping: EUAIActMapping = EUAIActMapping()
    overall_compliance_score: int = Field(0, ge=0, le=100)
    overall_compliance_grade: str = "N/A"
    critical_non_compliance: list[str] = []
    executive_summary: str = ""
    report_metadata: ReportMetadata = ReportMetadata()


# ── Digital asset service ────────────────────────────────────────


class DigitalAssetAIAnalysis(BaseModel):
    """Output of the AI sub-analysis inside DigitalAssetGovernanceAgent."""

    model_config = ConfigDict(extra="forbid")

    executive_summary: str = ""
    critical_issues: list[Finding] = []
    platform_configs: PlatformConfigs = PlatformConfigs()
    overall_assessment: str = ""


# ── Supervisor ───────────────────────────────────────────────────


class SupervisorSynthesis(BaseModel):
    """Output of :meth:`SupervisorAgent.synthesize_bundle`."""

    model_config = ConfigDict(extra="forbid")

    executive_summary: str = ""
    overall_risk_level: str = "medium"
    confidence_score: int = Field(0, ge=0, le=100)
    key_findings: list[str] = []
    recommended_actions: list[str] = []
    service_summaries: dict[str, str] = {}
