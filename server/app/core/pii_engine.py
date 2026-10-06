import re
import uuid
import time
from typing import List, Dict, Tuple, Optional
from app.models.schemas import DetectedEntity


class PIIEngine:
    """
    High-performance PII/PHI detection & reversible synthetic tokenization engine.
    Detects sensitive entities and replaces them with identifiable synthetic tokens
    e.g. [EMAIL_1], [PHONE_1], [SSN_1], [API_KEY_1].
    """

    def __init__(self, max_token_maps: int = 5000):
        # In-memory session token store: token_map_id -> { token: raw_value }
        self._token_store: Dict[str, Dict[str, str]] = {}
        self._store_timestamps: Dict[str, float] = {}
        self.max_token_maps = max_token_maps

        # Compile high-performance regex patterns
        self.patterns = {
            "API_KEY": [
                (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "CREDENTIAL", 0.99),
                (re.compile(r"\bgh[pousr]_[a-zA-Z0-9]{36}\b"), "CREDENTIAL", 0.99),
                (re.compile(r"\bsk-(?:proj-)?[a-zA-Z0-9_\-]{20,}\b"), "CREDENTIAL", 0.99),
                (re.compile(r"\b(?:api[_-]?key|secret|access_token|private_key)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?", re.IGNORECASE), "CREDENTIAL", 0.95),
                (re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"), "CREDENTIAL", 1.0)
            ],
            "SSN": [
                (re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), "PII", 0.98),
                (re.compile(r"\bSSN\s*[:#]?\s*\d{9}\b", re.IGNORECASE), "PII", 0.95),
            ],
            "CREDIT_CARD": [
                # Visa, Mastercard, Amex, Discover
                (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"), "CREDENTIAL", 0.95),
                (re.compile(r"\b(?:\d{4}[- ]){3}\d{4}\b"), "CREDENTIAL", 0.90),
            ],
            "EMAIL": [
                (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"), "PII", 0.99),
            ],
            "PHONE": [
                (re.compile(r"\b(?:\+?1[-. ]?)?\(?[0-9]{3}\)?[-. ]?[0-9]{3}[-. ]?[0-9]{4}\b"), "PII", 0.92),
                (re.compile(r"\b\+?[1-9]\d{1,14}\b(?=.*(?:phone|cell|mobile|call|fax))", re.IGNORECASE), "PII", 0.85),
            ],
            "IP_ADDRESS": [
                (re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"), "NETWORK", 0.95),
            ],
            "MEDICAL_ID": [
                (re.compile(r"\b(?:MRN|MED|PATIENT)[-:#]?\s*[A-Z0-9]{6,12}\b", re.IGNORECASE), "PHI", 0.96),
                (re.compile(r"\bRecord\s*ID\s*[:#]?\s*[A-Z0-9]{6,12}\b", re.IGNORECASE), "PHI", 0.92),
            ],
            "NAME": [
                (re.compile(r"\b(?:Patient|Dr\.|Doctor|Mr\.|Ms\.|Mrs\.|Client|Employee|Name:)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b"), "PII", 0.88),
            ],
        }

    def _cleanup_old_maps(self):
        """Evicts oldest stored token maps if capacity is exceeded"""
        if len(self._token_store) > self.max_token_maps:
            sorted_keys = sorted(self._store_timestamps.items(), key=lambda x: x[1])
            for k, _ in sorted_keys[: len(self._token_store) - self.max_token_maps + 500]:
                self._token_store.pop(k, None)
                self._store_timestamps.pop(k, None)

    def scan_and_tokenize(self, text: str) -> Tuple[str, List[DetectedEntity], str]:
        """
        Scans input string for all sensitive entities, replaces them with reversible tokens,
        and saves the session mapping.
        Returns: (tokenized_text, list of detected entities, token_map_id)
        """
        raw_matches: List[Tuple[int, int, str, str, str, float]] = [] # (start, end, entity_type, raw_val, category, confidence)

        for entity_type, patterns in self.patterns.items():
            for pattern, category, confidence in patterns:
                for match in pattern.finditer(text):
                    # Handle capture groups if present
                    if match.groups() and match.group(1):
                        start, end = match.start(1), match.end(1)
                        val = match.group(1)
                    else:
                        start, end = match.start(), match.end()
                        val = match.group(0)
                    
                    # Ignore extremely short strings
                    if len(val.strip()) < 3:
                        continue
                    
                    raw_matches.append((start, end, entity_type, val, category, confidence))

        # Sort matches by start position
        raw_matches.sort(key=lambda x: x[0])

        # Remove overlapping matches (keep earliest or longest)
        filtered_matches = []
        last_end = -1
        for start, end, entity_type, val, category, confidence in raw_matches:
            if start >= last_end:
                filtered_matches.append((start, end, entity_type, val, category, confidence))
                last_end = end

        # Generate tokens and build tokenized string
        token_counter: Dict[str, int] = {}
        token_to_raw: Dict[str, str] = {}
        detected_entities: List[DetectedEntity] = []

        # We construct tokenized text by replacing from right to left or segment by segment
        tokenized_text_parts = []
        curr_idx = 0

        for start, end, entity_type, val, category, confidence in filtered_matches:
            # Append plain text leading up to match
            tokenized_text_parts.append(text[curr_idx:start])

            # Increment count for this entity type
            count = token_counter.get(entity_type, 0) + 1
            token_counter[entity_type] = count
            token = f"[{entity_type}_{count}]"

            token_to_raw[token] = val
            tokenized_text_parts.append(token)

            detected_entities.append(
                DetectedEntity(
                    entity_type=entity_type,
                    raw_value=val,
                    token=token,
                    start=start,
                    end=end,
                    confidence=confidence,
                    category=category,
                )
            )
            curr_idx = end

        tokenized_text_parts.append(text[curr_idx:])
        tokenized_text = "".join(tokenized_text_parts)

        # Store in session map
        token_map_id = f"tkn_{uuid.uuid4().hex[:12]}"
        self._token_store[token_map_id] = token_to_raw
        self._store_timestamps[token_map_id] = time.time()
        self._cleanup_old_maps()

        return tokenized_text, detected_entities, token_map_id

    def detokenize(
        self,
        tokenized_text: str,
        token_map_id: Optional[str] = None,
        custom_token_map: Optional[Dict[str, str]] = None,
    ) -> Tuple[str, int, bool]:
        """
        Reverses synthetic tokenization by swapping tokens with original values.
        """
        token_map: Dict[str, str] = {}
        if custom_token_map:
            token_map.update(custom_token_map)
        
        if token_map_id and token_map_id in self._token_store:
            token_map.update(self._token_store[token_map_id])

        if not token_map:
            return tokenized_text, 0, False

        restored_text = tokenized_text
        restored_count = 0

        # Replace each token
        for token, raw_val in token_map.items():
            if token in restored_text:
                restored_text = restored_text.replace(token, raw_val)
                restored_count += 1

        return restored_text, restored_count, True


# Global singleton instance
pii_engine = PIIEngine()
