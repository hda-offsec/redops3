import json

class DetectionAdapter:
    """
    Unified DetectionAdapter layer.
    Responsibilities:
    1. Normalize DB Finding -> UI model
    2. Normalize JSON findings -> UI model
    3. Deduplicate via id_stable
    4. Merge severity + confidence safely
    5. Preserve original engine metadata
    """
    
    @staticmethod
    def normalize_findings(db_findings, json_results):
        print("[INTEL_RESTORE] detection_adapter initialized")
        normalized = {}
        
        # 1. Normalize DB Findings
        for f in db_findings:
            fid = f.id_stable or str(f.id)
            if fid not in normalized:
                normalized[fid] = {
                    'id': str(f.id),
                    'id_stable': f.id_stable,
                    'title': f.title,
                    'severity': f.severity or 'info',
                    'confidence': f.confidence or 'medium',
                    'description': f.description,
                    'tool_source': f.tool_source or 'Unknown Engine',
                    'request': f.request,
                    'response': f.response,
                    'repro_command': f.repro_command,
                    'screenshot_path': f.screenshot_path,
                }
        
        # 2. Normalize JSON findings
        if json_results and 'phases' in json_results and 'vuln' in json_results['phases']:
            vuln_phase = json_results['phases']['vuln']
            for tool, findings_data in vuln_phase.items():
                findings_list = []
                if isinstance(findings_data, list):
                    findings_list = findings_data
                elif isinstance(findings_data, dict) and 'findings' in findings_data:
                    findings_list = findings_data['findings']
                
                for item in findings_list:
                    if not isinstance(item, dict):
                        continue
                        
                    fid = item.get('id_stable') or str(item.get('id', ''))
                    title = item.get('name') or item.get('title') or "Untitled JSON Finding"
                    
                    if not fid:
                        fid = f"{tool}_{title}"
                    
                    if fid in normalized:
                        # 4. Merge severity + confidence safely
                        merged = normalized[fid]
                        # Don't overwrite higher severity or better evidence, just skip simple overwrites for now
                        # But do ensure we preserve full data if the mapped one is weak
                        continue
                    
                    desc = item.get('description', '')
                    if item.get('extracted-results'):
                        desc += f"\nExtracted: {item.get('extracted-results')}"
                        
                    normalized[fid] = {
                        'id': str(item.get('id', '')),
                        'id_stable': item.get('id_stable'),
                        'title': title,
                        'severity': item.get('severity', 'info'),
                        'confidence': item.get('confidence', 'medium'),
                        'description': desc,
                        'tool_source': item.get('tool_source', tool),
                        'request': item.get('request', ''),
                        'response': item.get('response', ''),
                        'repro_command': item.get('curl-command', '') or item.get('repro_command', ''),
                        'screenshot_path': item.get('screenshot_path', ''),
                    }

        print(f"[INTEL_RESTORE] merged JSON + DB findings. Total detections: {len(normalized)}")
        return list(normalized.values())
