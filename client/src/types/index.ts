export interface DetectedEntity {
  entity_type: string;
  raw_value: string;
  token: string;
  start: number;
  end: number;
  confidence: number;
  category: 'PII' | 'PHI' | 'CREDENTIAL' | 'NETWORK' | string;
}

export interface ThreatTrigger {
  category: string;
  pattern_name: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  matched_snippet: string;
  explanation: string;
}

export interface ThreatAnalysis {
  risk_score: number;
  threat_level: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  triggers: ThreatTrigger[];
  injection_detected: boolean;
  leakage_detected: boolean;
  jailbreak_detected: boolean;
  malicious_code_detected: boolean;
}

export interface TrustScoreBreakdown {
  baseline_score: number;
  injection_penalty: number;
  pii_penalty: number;
  heuristic_penalty: number;
  final_score: number;
  trust_tier: 'EXCELLENT' | 'GOOD' | 'MODERATE' | 'CRITICAL_RISK';
}

export interface ScanResponse {
  scan_id: string;
  timestamp: string;
  decision: 'ALLOW' | 'SANITIZE_AND_FORWARD' | 'QUARANTINE_BLOCKED';
  trust_score: number;
  breakdown: TrustScoreBreakdown;
  original_prompt: string;
  tokenized_prompt: string;
  entities_detected: DetectedEntity[];
  threat_analysis: ThreatAnalysis;
  token_map_id: string;
  latency_ms: number;
  policy_compliance: {
    injection_shield_passed: boolean;
    jailbreak_defense_passed: boolean;
    prompt_leakage_shield_passed: boolean;
    remote_code_shield_passed: boolean;
    pii_vault_shielded: boolean;
    zero_trust_transit_approved: boolean;
    [key: string]: boolean;
  };
}

export interface DetokenizeRequest {
  tokenized_text: string;
  token_map_id?: string;
  custom_token_map?: Record<string, string>;
}

export interface DetokenizeResponse {
  restored_text: string;
  restored_count: number;
  success: boolean;
  message: string;
}

export interface AuditLogEntry {
  audit_id: string;
  timestamp: string;
  client_ip_hash: string;
  prompt_preview: string;
  decision: 'ALLOW' | 'SANITIZE_AND_FORWARD' | 'QUARANTINE_BLOCKED';
  trust_score: number;
  threat_level: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  pii_count: number;
  triggers_summary: string[];
  latency_ms: number;
  full_prompt_length?: number;
}

export interface MetricsResponse {
  total_scans: number;
  total_allowed: number;
  total_sanitized: number;
  total_blocked: number;
  pii_entities_redacted: number;
  avg_trust_score: number;
  threat_distribution: Record<string, number>;
  pii_distribution: Record<string, number>;
}

export interface PresetAttack {
  id: string;
  title: string;
  category: string;
  description: string;
  prompt: string;
}
