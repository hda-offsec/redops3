from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class RouteModel:
    path: str
    variables: List[str] = field(default_factory=list)
    constraints: Dict[str, str] = field(default_factory=dict)
    methods: List[str] = field(default_factory=list)
    source: str = "seed"
    risk_tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return {
            "path": self.path,
            "variables": self.variables,
            "constraints": self.constraints,
            "methods": self.methods,
            "source": self.source,
            "risk_tags": self.risk_tags,
            "metadata": self.metadata
        }
