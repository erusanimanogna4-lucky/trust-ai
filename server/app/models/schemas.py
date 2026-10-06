from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime


class ScanRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="Raw user prompt or payload to intercept and analyze")
    session_id: Optional[str] = Field(default=None, description="Optional session or conversation ID")
    user_id: Optional[str] = Field(default=None, description="Optional user identifier")
    policy_level: Optional[str] = Field(default="STRICT", description="Policy enforcement level: PERMISSIVE, STANDARD, STRICT")


class DetectedEntity(BaseModel):
    entity_type: str = Field(..., description="Type of PII/PHI (EMAIL, PHONE, SSN, CREDIT_CARD, etc.)")
    raw_value: str = Field(..., description="Original raw sensitive string")
    token: str = Field(..., description="Synthetic replacement token, e.g. [EMAIL_1]")
    start: int = Field(..., description="Character start index in raw prompt")
    end: int = Field(..., description="Character end index in raw prompt")
    confidence: float = Field(default=0.95, description="Detection confidence 0.0 - 1.0")
    category: str = Field(default="PII", description="PII, PHI, CREDENTIAL, or NETWORK")


class ThreatTrigger(BaseModel):
    category: str = Field(..., description="Threat category: PROMPT_INJECTION, JAILBREAK, SYSTEM_LEAK, etc.")
    pattern_name: str = Field(..., description="Name of rule or trigger pattern that fired")
    severity: str = Field(..., description="Severity level: LOW, MEDIUM, HIGH, CRITICAL")
    matched_snippet: str = Field(..., description="Snippet of text that matched the threat rule")
    explanation: str = Field(..., description="Human-readable reason for threat trigger")


class ThreatAnalysis(BaseModel):
    risk_score: float = Field(..., description="Adversarial risk score between 0.0 (safe) and 1.0 (dangerous)")
    threat_level: str = Field(..., description="NONE, LOW, MEDIUM, HIGH, CRITICAL")
    triggers: List[ThreatTrigger] = Field(default_factory=list, description="List of matched threat triggers")
    injection_detected: bool = Field(default=False)
    leakage_detected: bool = Field(default=False)
    jailbreak_detected: bool = Field(default=False)
    malicious_code_detected: bool = Field(default=False)


class TrustScoreBreakdown(BaseModel):
    baseline_score: int = Field(default=100)
    injection_penalty: int = Field(default=0, description="Deductions due to prompt injection / jailbreak risk (-40 max)")
    pii_penalty: int = Field(default=0, description="Deductions due to PII/PHI presence (-30 max)")
    heuristic_penalty: int = Field(default=0, description="Deductions due to toxicity/malicious syntax (-30 max)")
    final_score: int = Field(..., description="Consolidated Trust Index (0 - 100)")
    trust_tier: str = Field(..., description="EXCELLENT, GOOD, MODERATE, CRITICAL_RISK")


class ScanResponse(BaseModel):
    scan_id: str
    timestamp: str
    decision: str = Field(..., description="ALLOW, SANITIZE_AND_FORWARD, or QUARANTINE_BLOCKED")
    trust_score: int = Field(..., description="Consolidated Trust Index (0 - 100)")
    breakdown: TrustScoreBreakdown
    original_prompt: str
    tokenized_prompt: str
    entities_detected: List[DetectedEntity] = Field(default_factory=list)
    threat_analysis: ThreatAnalysis
    token_map_id: str
    latency_ms: float
    policy_compliance: Dict[str, bool] = Field(default_factory=dict)


class DetokenizeRequest(BaseModel):
    tokenized_text: str = Field(..., description="Text containing synthetic tokens like [EMAIL_1]")
    token_map_id: Optional[str] = Field(default=None, description="Session token map ID stored in gateway")
    custom_token_map: Optional[Dict[str, str]] = Field(default=None, description="Optional explicit token-to-raw map")


class DetokenizeResponse(BaseModel):
    restored_text: str
    restored_count: int
    success: bool
    message: str = "Detokenization successful"


class AuditLogEntry(BaseModel):
    audit_id: str
    timestamp: str
    client_ip_hash: str
    prompt_preview: str
    decision: str
    trust_score: int
    threat_level: str
    pii_count: int
    triggers_summary: List[str]
    latency_ms: float
    full_prompt_length: int = 0


class MetricsResponse(BaseModel):
    total_scans: int
    total_allowed: int
    total_sanitized: int
    total_blocked: int
    pii_entities_redacted: int
    avg_trust_score: float
    threat_distribution: Dict[str, int]
    pii_distribution: Dict[str, int]


class PresetAttack(BaseModel):
    id: str
    title: str
    category: str
    description: str
    prompt: str
