import re
from typing import List, Tuple, Dict, Any
from app.models.schemas import ThreatTrigger, ThreatAnalysis, TrustScoreBreakdown, DetectedEntity


class SecurityEngine:
    """
    Real-time Threat & Adversarial Injection Detector with Explainable Trust & Safety Index.
    """

    def __init__(self):
        # Threat pattern definitions: (regex, category, pattern_name, severity, base_risk, explanation)
        self.threat_rules = [
            # 1. Direct Prompt Injection & Override
            (
                re.compile(r"\b(?:ignore|disregard|forget|bypass|override)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts|rules|commands|constraints|directives)\b", re.IGNORECASE),
                "PROMPT_INJECTION",
                "INSTRUCTION_OVERRIDE",
                "CRITICAL",
                0.85,
                "Explicit attempt to instruct the LLM to discard system governance directives."
            ),
            (
                re.compile(r"\b(?:from\s+now\s+on\s+you\s+(?:will|must|are)|new\s+instruction(?:s)?\s*[:=]|system\s+override\s*[:=])\b", re.IGNORECASE),
                "PROMPT_INJECTION",
                "ROLE_OVERRIDE_DIRECTIVE",
                "HIGH",
                0.70,
                "Attempt to forcefully redefine assistant baseline persona or operation mode."
            ),
            (
                re.compile(r"\bdo\s+not\s+follow\s+(?:the\s+)?(?:safety|guidelines|rules|policies|filters)\b", re.IGNORECASE),
                "PROMPT_INJECTION",
                "SAFETY_FILTER_BYPASS",
                "CRITICAL",
                0.80,
                "Direct command targeting AI safety guardrails."
            ),
            (
                re.compile(r"\b(?:reset|wipe|erase)\s+your\s+(?:parameters|memory|instructions|rules)\b", re.IGNORECASE),
                "PROMPT_INJECTION",
                "SYSTEM_RESET_ATTEMPT",
                "HIGH",
                0.65,
                "Attempt to trigger simulated memory wipe or context reset."
            ),

            # 2. Jailbreaks & Known Exploits
            (
                re.compile(r"\b(?:DAN|Do\s+Anything\s+Now|STAN|AIM|DUDE|Maximum\s+Mode|Anti-GPT)\b", re.IGNORECASE),
                "JAILBREAK",
                "ARCHETYPAL_JAILBREAK",
                "CRITICAL",
                0.90,
                "Signature matches known adversarial jailbreak archetypes (DAN/AIM/STAN)."
            ),
            (
                re.compile(r"\b(?:jailbreak|jailbroken|unfiltered\s+mode|unrestricted\s+mode|developer\s+mode\s+enabled)\b", re.IGNORECASE),
                "JAILBREAK",
                "UNFILTERED_MODE_SWITCH",
                "CRITICAL",
                0.85,
                "Adversarial assertion that AI developer/unrestricted mode is active."
            ),
            (
                re.compile(r"\b(?:pretend|act\s+as\s+if)\s+you\s+(?:have\s+no\s+(?:rules|filters|morals|limits|restrictions)|are\s+(?:evil|unfiltered|malicious|a\s+hacker))\b", re.IGNORECASE),
                "JAILBREAK",
                "FICTIONAL_ROLEPLAY_BYPASS",
                "HIGH",
                0.75,
                "Adversarial roleplay designed to elicit harmful unconstrained behavior."
            ),
            (
                re.compile(r"\bhypothetically,\s+(?:if\s+there\s+were\s+no\s+(?:laws|restrictions|guardrails|safety\s+checks))\b", re.IGNORECASE),
                "JAILBREAK",
                "HYPOTHETICAL_GUARDRAIL_BYPASS",
                "MEDIUM",
                0.50,
                "Hypothetical reframing used to bypass policy checks."
            ),

            # 3. System Prompt & Secret Leakage
            (
                re.compile(r"\b(?:repeat|print|output|display|show|reveal|leak|exfiltrate)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|hidden\s+prompt|developer\s+instructions|base\s+prompt)\b", re.IGNORECASE),
                "SYSTEM_LEAK",
                "PROMPT_EXTRACTION_ATTEMPT",
                "HIGH",
                0.75,
                "Attempt to extract hidden system instructions, intellectual property, or confidential meta-prompts."
            ),
            (
                re.compile(r"\bwhat\s+(?:are|were)\s+the\s+(?:exact\s+)?(?:words|instructions)\s+(?:given\s+to\s+you\s+at\s+the\s+beginning|above)\b", re.IGNORECASE),
                "SYSTEM_LEAK",
                "SYSTEM_PROMPT_PROBING",
                "HIGH",
                0.65,
                "Probing questions designed to reconstruct system context."
            ),
            (
                re.compile(r"\b(?:output|dump|print)\s+all\s+(?:environment\s+variables|env\s+vars|API\s+keys|secrets)\b", re.IGNORECASE),
                "SYSTEM_LEAK",
                "ENVIRONMENT_SECRET_EXFILTRATION",
                "CRITICAL",
                0.90,
                "Direct attempt to dump host/runtime credentials and environment variables."
            ),

            # 4. Malicious Shell / Remote Code Payloads
            (
                re.compile(r"\b(?:sudo\s+su|chmod\s+777|rm\s+-rf\s+(?:/|\*)|curl\s+[^\s]+\s*\|\s*(?:bash|sh)|wget\s+[^\s]+\s*\|\s*(?:bash|sh))\b", re.IGNORECASE),
                "MALICIOUS_CODE",
                "DESTRUCTIVE_SHELL_COMMAND",
                "CRITICAL",
                0.95,
                "Destructive or remote code execution shell payload detected."
            ),
            (
                re.compile(r"\b(?:powershell\s+-(?:enc|encodedcommand)|cmd\.exe\s+/c|netcat\s+-e|nc\s+-e)\b", re.IGNORECASE),
                "MALICIOUS_CODE",
                "REVERSE_SHELL_INVOCATION",
                "CRITICAL",
                0.90,
                "Reverse shell or obfuscated command execution string."
            ),
            (
                re.compile(r"\b(?:union\s+select\s+.*?from|'\s*or\s*['\"]?1['\"]?\s*=\s*['\"]?1|drop\s+table\s+[a-z_]+)\b", re.IGNORECASE),
                "MALICIOUS_CODE",
                "SQL_INJECTION_PATTERN",
                "HIGH",
                0.80,
                "Classic SQL injection signature detected."
            ),
            (
                re.compile(r"\b(?:eval\s*\(base64_decode|base64\.b64decode|__import__\s*\(\s*['\"]os['\"]\s*\))\b", re.IGNORECASE),
                "MALICIOUS_CODE",
                "DYNAMIC_CODE_EVALUATION",
                "CRITICAL",
                0.95,
                "Dynamic code evaluation or dangerous language runtime reflection."
            ),

            # 5. Obfuscation & Steganography
            (
                re.compile(r"[\u200B-\u200D\uFEFF]"),
                "OBFUSCATION",
                "ZERO_WIDTH_CHARACTER_INJECTION",
                "MEDIUM",
                0.55,
                "Hidden zero-width unicode characters detected (steganographic injection)."
            ),
        ]

    def analyze_threats(self, prompt: str) -> ThreatAnalysis:
        """
        Runs threat rules against input text and computes risk score and trigger list.
        """
        triggers: List[ThreatTrigger] = []
        max_risk = 0.0
        risk_accumulator = 0.0

        for pattern, category, pattern_name, severity, base_risk, explanation in self.threat_rules:
            matches = list(pattern.finditer(prompt))
            if matches:
                # Capture first matched snippet
                matched_snippet = matches[0].group(0)
                if len(matched_snippet) > 60:
                    matched_snippet = matched_snippet[:57] + "..."
                
                triggers.append(
                    ThreatTrigger(
                        category=category,
                        pattern_name=pattern_name,
                        severity=severity,
                        matched_snippet=matched_snippet,
                        explanation=explanation,
                    )
                )

                max_risk = max(max_risk, base_risk)
                risk_accumulator += base_risk * 0.35

        # Consolidated risk score capped at 1.0
        calculated_risk = min(1.0, max_risk + min(0.3, risk_accumulator))
        risk_score = round(calculated_risk, 2)

        # Categorize threat level
        if risk_score == 0:
            threat_level = "NONE"
        elif risk_score < 0.35:
            threat_level = "LOW"
        elif risk_score < 0.65:
            threat_level = "MEDIUM"
        elif risk_score < 0.85:
            threat_level = "HIGH"
        else:
            threat_level = "CRITICAL"

        injection_detected = any(t.category == "PROMPT_INJECTION" for t in triggers)
        jailbreak_detected = any(t.category == "JAILBREAK" for t in triggers)
        leakage_detected = any(t.category == "SYSTEM_LEAK" for t in triggers)
        malicious_code_detected = any(t.category == "MALICIOUS_CODE" for t in triggers)

        return ThreatAnalysis(
            risk_score=risk_score,
            threat_level=threat_level,
            triggers=triggers,
            injection_detected=injection_detected,
            leakage_detected=leakage_detected,
            jailbreak_detected=jailbreak_detected,
            malicious_code_detected=malicious_code_detected,
        )

    def compute_trust_score(
        self, threat_analysis: ThreatAnalysis, entities: List[DetectedEntity]
    ) -> Tuple[int, TrustScoreBreakdown, str]:
        """
        Computes consolidated Explainable Trust & Safety Index (0 - 100)
        and outputs the governance decision: ALLOW, SANITIZE_AND_FORWARD, or QUARANTINE_BLOCKED.
        """
        # 1. Injection Risk penalty (-40 max)
        injection_penalty = min(40, int(threat_analysis.risk_score * 40))

        # 2. PII / PHI density penalty (-30 max)
        pii_penalty = 0
        for ent in entities:
            if ent.category in ("CREDENTIAL", "PHI") or ent.entity_type in ("SSN", "API_KEY", "CREDIT_CARD"):
                pii_penalty += 12
            else:
                pii_penalty += 5
        pii_penalty = min(30, pii_penalty)

        # 3. Heuristic / malicious anomaly penalty (-30 max)
        heuristic_penalty = 0
        if threat_analysis.leakage_detected:
            heuristic_penalty += 15
        if threat_analysis.malicious_code_detected:
            heuristic_penalty += 20
        if any(t.category == "OBFUSCATION" for t in threat_analysis.triggers):
            heuristic_penalty += 10
        heuristic_penalty = min(30, heuristic_penalty)

        # Consolidated Trust Index (0 - 100)
        final_score = max(0, 100 - injection_penalty - pii_penalty - heuristic_penalty)

        # Determine Trust Tier
        if final_score >= 85:
            trust_tier = "EXCELLENT"
        elif final_score >= 70:
            trust_tier = "GOOD"
        elif final_score >= 50:
            trust_tier = "MODERATE"
        else:
            trust_tier = "CRITICAL_RISK"

        breakdown = TrustScoreBreakdown(
            baseline_score=100,
            injection_penalty=injection_penalty,
            pii_penalty=pii_penalty,
            heuristic_penalty=heuristic_penalty,
            final_score=final_score,
            trust_tier=trust_tier,
        )

        # Decision Logic:
        # Zero-trust quarantine if threat risk is severe or malicious payloads detected
        is_quarantine = (
            threat_analysis.risk_score >= 0.45
            or threat_analysis.injection_detected
            or threat_analysis.jailbreak_detected
            or threat_analysis.malicious_code_detected
            or final_score < 50
        )

        if is_quarantine:
            decision = "QUARANTINE_BLOCKED"
        elif len(entities) > 0 or pii_penalty > 0 or final_score < 85:
            decision = "SANITIZE_AND_FORWARD"
        else:
            decision = "ALLOW"

        return final_score, breakdown, decision


# Global singleton instance
security_engine = SecurityEngine()
