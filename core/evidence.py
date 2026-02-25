from dataclasses import dataclass, field
from typing import List, Optional, Dict
from enum import Enum
import hashlib

class EvidenceLevel(Enum):
    HEURISTIC = "heuristic"
    PROBABLE = "probable"
    CONFIRMED = "confirmed"

@dataclass
class StackContext:
    server_header: Optional[str] = None
    x_powered_by: Optional[str] = None
    cms_guess: Optional[str] = None
    tls_port: Optional[int] = None

@dataclass
class EvidenceProof:
    status_before: Optional[int] = None
    status_after: Optional[int] = None
    body_hash_before: Optional[str] = None
    body_hash_after: Optional[str] = None
    markers: List[str] = field(default_factory=list)
    matched_regexes: List[str] = field(default_factory=list)

@dataclass
class EvidenceModel:
    level: EvidenceLevel = EvidenceLevel.HEURISTIC
    proof: EvidenceProof = field(default_factory=EvidenceProof)
    stack_context: StackContext = field(default_factory=StackContext)
    verification_required: bool = False

    def to_dict(self) -> Dict:
        return {
            "evidence_level": self.level.value,
            "verification_required": self.verification_required,
            "proof": {
                "status_before": self.proof.status_before,
                "status_after": self.proof.status_after,
                "body_hash_before": self.proof.body_hash_before,
                "body_hash_after": self.proof.body_hash_after,
                "markers": self.proof.markers,
                "matched_regexes": self.proof.matched_regexes
            },
            "stack_context": {
                "server_header": self.stack_context.server_header,
                "x_powered_by": self.stack_context.x_powered_by,
                "cms_guess": self.stack_context.cms_guess,
                "tls_port": self.stack_context.tls_port
            }
        }

def compute_body_hash(body_text: str) -> str:
    """Computes a stable hash of a normalized HTTP body."""
    if not body_text:
        return ""
    # Strip whitespace to avoid trivial differences
    normalized = "".join(body_text.split())
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()
