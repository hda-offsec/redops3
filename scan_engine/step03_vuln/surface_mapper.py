import json
from scan_engine.surface.architecture_detector import ArchitectureDetector
from scan_engine.surface.risk_classifier import RiskClassifier
from scan_engine.surface.passive_backend_validator import PassiveBackendValidator
from scan_engine.surface.attack_surface_builder import AttackSurfaceBuilder
from scan_engine.surface.surface_visualizer import SurfaceVisualizer

class SurfaceMapperScanner:
    """
    Orchestrates the Backend Surface Exposure discovery.
    Integrated as a scanner module.
    """
    
    def __init__(self, target, options=None):
        self.options = options
        self.target = target
        self.detector = ArchitectureDetector()
        self.classifier = RiskClassifier()
        self.validator = PassiveBackendValidator(target)
        self.builder = AttackSurfaceBuilder(0) # Port will be set during audit
        
    def audit(self, port, protocol='http', logger=None, scan_results=None):
        """
        Main entry point for surface mapping.
        Analyzes existing scan results (JS files, HTML) for architecture leaks.
        """
        findings = []
        all_discovered_routes = []
        
        if not scan_results:
            return []

        if logger: logger(f"[Surface] Starting backend architecture mapping on port {port}...", "INFO")
        
        # 1. Collect all potential sources of leaks (already discovered in ENUM phase)
        # We look at Katana results for JS files and the initial crawl.
        enum_data = scan_results.get("phases", {}).get("enum", {})
        katana_results = enum_data.get("katana", {}).get(str(port), [])
        
        sources = [f"{protocol}://{self.target}:{port}/"] # Main page
        sources.extend([u for u in katana_results if u.endswith('.js') or u.endswith('.json')])
        
        # Deduplicate
        sources = list(set(sources))
        
        for source_url in sources:
            try:
                # We need to fetch the content if it's not already cached.
                # In a real integration, we might use a shared cache, but for now we fetch.
                import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
                resp = http_client.get(source_url, options=getattr(self, "options", None), timeout=10, headers={"User-Agent": "RedOps3-SurfaceMapper/1.0"})
                if resp.status_code == 200:
                    content = resp.text
                    ctype = resp.headers.get("Content-Type", "")
                    
                    # Detect Leaks
                    discovered = self.detector.detect_in_response(source_url, content, ctype)
                    if discovered:
                        if logger: logger(f"[Surface] Architecture leak detected in {source_url} ({len(discovered)} routes found)", "SUCCESS")
                        all_discovered_routes.extend(discovered)
            except Exception as e:
                continue

        if not all_discovered_routes:
            if logger: logger(f"[Surface] No architecture leaks found for port {port}.", "DEBUG")
            return []

        # 2. Classify and Validate
        self.classifier.batch_classify(all_discovered_routes)
        
        confirmed_count = 0
        for route in all_discovered_routes:
            # Passive validation
            if self.validator.validate_route(route, port, protocol):
                confirmed_count += 1
                if logger: logger(f"[Surface] Passive backend lookup confirmed for {route.path}", "SUCCESS")

        # 3. Build Graph Data
        self.builder.port = port
        graph_patch = self.builder.build_nodes(all_discovered_routes)
        
        # 4. Format for UI
        ui_data = SurfaceVisualizer.format_for_ui(all_discovered_routes)
        
        # 5. Return as specialized result
        # We also create a finding for visibility in the log
        findings.append({
            "title": "Architecture Mapping: Backend Surface Exposed",
            "description": f"Successfully mapped the backend attack surface from client-side leaks.\nEndpoints: {len(all_discovered_routes)}\nConfirmed: {confirmed_count}\nHigh Risk: {ui_data['summary']['high_risk_points']}",
            "severity": "info",
            "tool_source": "surface_mapper",
            "surface_data": ui_data,
            "graph_patch": graph_patch
        })
        
        if logger: logger(f"[Surface] Mapping complete. {len(all_discovered_routes)} routes categorized.", "SUCCESS")
        
        return findings
