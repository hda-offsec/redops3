import logging
from scan_engine.helpers.finding_schema import deep_merge_metadata

logger = logging.getLogger(__name__)

class SignalSynthesisEngine:
    """
    Synthesizes signals and findings into logical attack chains.
    Focuses on linking infrastructure, enumeration, and exploitation facts.
    """
    def __init__(self, options=None):
        self.options = options or {}

    def synthesize(self, findings):
        """
        Groups findings by common patterns and produces chain metadata.
        """
        if not findings:
            return []

        # 1. Group by endpoint/host
        by_host = {}
        for f in findings:
            target = f.get("endpoint") or f.get("target") or "global"
            host = target.split("/")[2] if "://" in target else target.split("/")[0]
            by_host.setdefault(host, []).append(f)

        chains = []
        
        for host, host_findings in by_host.items():
            # Ensure chain_metadata is initialized for all findings
            for f in host_findings:
                if not isinstance(f.get("chain_metadata"), dict):
                    f["chain_metadata"] = {}
                if "related_findings" not in f["chain_metadata"]:
                    f["chain_metadata"]["related_findings"] = []

            # Logical grouping
            secrets = [f for f in host_findings if f.get("category") == "sensitive_endpoint" or "secret" in (f.get("category") or "").lower()]
            vulns = [f for f in host_findings if (f.get("severity") or "").lower() in ["critical", "high"]]
            assets = [f for f in host_findings if f.get("category") in ["asset_discovery", "api_surface"]]

            # Correlation logic: Secrets + Assets
            if secrets and assets:
                for s in secrets:
                    s["chain_metadata"]["is_chain_root"] = True
                    s["chain_metadata"]["related_findings"] = list(set(s["chain_metadata"]["related_findings"] + [a.get("id_stable") for a in assets if a.get("id_stable")]))
                    s["chain_metadata"]["attack_path_summary"] = f"Sensitive data exposed on active surface: {host}"
                    
            # Correlation logic: Vulns + API
            for v in vulns:
                v_ep = v.get("endpoint")
                if not v_ep: continue
                related_api = [a for a in assets if a.get("endpoint") == v_ep]
                if related_api:
                    v["chain_metadata"]["related_findings"] = list(set(v["chain_metadata"]["related_findings"] + [a.get("id_stable") for a in related_api if a.get("id_stable")]))
                    v["chain_metadata"]["attack_path_summary"] = "Critical vulnerability identified on verified API surface."
                    v["chain_metadata"]["previous_findings"] = [a.get("id_stable") for a in related_api if a.get("id_stable")]

        return findings

    def get_tactical_summary(self, findings):
        """
        Produces a high-level summary for the 'Tactical Board'.
        """
        critical_chains = [f for f in findings if f.get("chain_metadata", {}).get("is_chain_root") and f.get("severity") == "critical"]
        
        return {
            "active_chains_count": len(critical_chains),
            "top_threats": [f.get("title") for f in critical_chains[:3]],
            "tactical_recommendation": "Prioritize verification of exposed sensitive endpoints to prevent credential leakage." if critical_chains else "Continue exploration of discovered attack surfaces."
        }
