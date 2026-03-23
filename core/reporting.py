try:
    from fpdf import FPDF
except Exception:  # pragma: no cover - import guard for environments without fpdf
    class FPDF:  # type: ignore
        def __init__(self, *args, **kwargs):
            raise RuntimeError("fpdf_not_installed")
import os
import json
from datetime import datetime
from markdown import markdown
from core.results_store import load_results
from core.findings_ui_contract import attach_finding_ui_contract, build_finding_detail_contract

REPORTS_DIR = "data/reports"


def severity_color_for_pdf(severity):
    """Return (bg_color, text_color) where red is reserved strictly for HIGH severity."""
    sev = str(severity or "info").lower()
    if sev == "high":
        return (180, 0, 0), (255, 255, 255)
    if sev == "critical":
        return (120, 60, 140), (255, 255, 255)
    if sev == "medium":
        return (90, 90, 95), (255, 255, 255)
    if sev == "low":
        return (230, 230, 235), (50, 50, 50)
    return (245, 245, 250), (100, 100, 100)


class RedOpsReport(FPDF):
    def __init__(self, target_name):
        super().__init__()
        self.target_name = target_name

    def header(self):
        if self.page_no() == 1:
            return # Cover page header handled separately

        # Minimal header for internal pages
        self.set_fill_color(20, 20, 25)
        self.rect(0, 0, 210, 25, 'F')
        
        self.set_y(5)
        self.set_x(10)
        self.set_font('helvetica', 'B', 12)
        self.set_text_color(36, 92, 160)
        self.cell(0, 10, 'REDOPS3 - OFFENSIVE INTELLIGENCE REPORT', ln=True, align='L')
        
        self.set_y(12)
        self.set_font('helvetica', '', 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 5, f'TARGET: {self.target_name} | CLASSIFIED', ln=True, align='L')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_x(10)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, f'Page {self.page_no()} - RedOps3 Framework - Proprietary Offensive Data', align='C')

    def cover_page(self, scan_obj, findings_count):
        self.add_page()
        # Background
        self.set_fill_color(10, 10, 12)
        self.rect(0, 0, 210, 297, 'F')
        
        # Logo placeholder / Title
        self.set_y(60)
        self.set_font('helvetica', 'B', 36)
        self.set_text_color(36, 92, 160)
        self.cell(0, 20, 'REDOPS3', ln=True, align='C')
        
        self.set_font('helvetica', 'B', 20)
        self.set_text_color(255, 255, 255)
        self.cell(0, 15, 'OFFENSIVE SECURITY REPORT', ln=True, align='C')
        
        self.ln(40)
        self.set_font('helvetica', '', 14)
        self.set_text_color(200, 200, 200)
        self.cell(0, 10, f'TARGET: {self.target_name}', ln=True, align='C')
        self.cell(0, 10, f'DATE: {datetime.now().strftime("%Y-%m-%d %H:%M")}', ln=True, align='C')
        self.cell(0, 10, f'SCAN ID: #{scan_obj.id}', ln=True, align='C')
        
        self.ln(50)
        self.set_font('helvetica', 'B', 16)
        if findings_count > 0:
            self.set_text_color(196, 100, 20)
            self.cell(0, 10, f'ALERT: {findings_count} REPORTABLE ITEMS IDENTIFIED', ln=True, align='C')
        else:
            self.set_text_color(0, 255, 100)
            self.cell(0, 10, 'CLEAN BILL OF HEALTH - NO CRITICAL VECTORS FOUND', ln=True, align='C')

    def safe_text(self, text):
        """Sanitizes text to be compatible with latin-1 encoding used by core fonts."""
        if not text: return ""
        # Map common problematic chars
        replacements = {
            "•": "-", "✅": "[YES]", "❌": "[NO]", "⚠️": "[WARN]", "🔥": "[CRIT]",
            "✓": "[OK]", "—": "-", "’": "'", "“": "\"", "”": "\"",
            "…": "...", "►": ">", "→": "->", "«": "\"", "»": "\""
        }
        # Coerce non-string types (dict, list, int, etc.) to string
        if not isinstance(text, str):
            text = str(text)
        for k, v in replacements.items():
            text = text.replace(k, v)
        
        # Fallback: encode/decode to strip unhandled chars
        try:
            return text.encode('latin-1', 'replace').decode('latin-1')
        except Exception:
            return text

    def chapter_title(self, title, color=(36, 92, 160)):
        self.ln(10)
        self.set_font('helvetica', 'B', 16)
        self.set_text_color(*color)
        self.cell(0, 10, self.safe_text(title), ln=True)
        self.set_draw_color(*color)
        self.line(self.get_x(), self.get_y(), self.get_x() + 190, self.get_y())
        self.ln(5)


def _truncate_report_block(value, limit=1600):
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[:limit] + "... [TRUNCATED FOR PDF EXPORT]"


def prepare_report_findings(findings):
    prepared = []
    for finding in findings or []:
        record = attach_finding_ui_contract(finding if isinstance(finding, dict) else {})
        record["_detail"] = build_finding_detail_contract(record)
        prepared.append(record)
    return prepared

def generate_scan_report(scan_id, scan_obj, findings):
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR, exist_ok=True)
        
    results = load_results(scan_id)
    findings = prepare_report_findings(findings)
    pdf = RedOpsReport(scan_obj.target.identifier)
    
    # 1. Cover Page
    pdf.cover_page(scan_obj, len(findings))
    
    # 2. Executive Summary
    pdf.add_page()
    pdf.set_text_color(0, 0, 0)
    pdf.chapter_title("1. Executive Summary")
    
    pdf.set_font("helvetica", "", 10)
    summary = (
        f"This tactical intelligence report summarizes the findings for the target {scan_obj.target.identifier}. "
        f"The operation was initiated on {scan_obj.start_time.strftime('%Y-%m-%d %H:%M:%S')} using the {scan_obj.scan_type} profile. "
        f"A total of {len(findings)} unique findings were recorded across multiple attack surfaces."
    )
    pdf.multi_cell(0, 6, pdf.safe_text(summary))
    
    # Severity breakdown
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = (f.get('severity', 'info') if isinstance(f, dict) else getattr(f, 'severity', 'info')).lower()
        if s in sev_counts: sev_counts[s] += 1
        
    pdf.ln(5)
    pdf.set_font("helvetica", "B", 10)
    pdf.cell(40, 7, "Risk Distribution:")
    pdf.ln(5)
    pdf.set_font("helvetica", "", 10)
    for s, c in sev_counts.items():
        if c > 0:
            pdf.cell(40, 6, f"- {s.upper()}: {c}")
            pdf.ln()

    # Timeline highlights
    timeline_events = []
    if isinstance(results, dict):
        if isinstance(results.get("timeline"), list):
            timeline_events = list(results.get("timeline") or [])
        elif isinstance(results.get("events"), list):
            timeline_events = list(results.get("events") or [])

    if timeline_events:
        pdf.ln(5)
        pdf.set_font("helvetica", "B", 10)
        pdf.cell(0, 7, "Mission Chronology (Key Events):")
        pdf.ln(5)
        pdf.set_font("helvetica", "", 8)
        # Deterministic sort + cap
        important_events = sorted(
            [e for e in timeline_events if isinstance(e, dict) and e.get("type") != "LOG"],
            key=lambda item: (str(item.get("ts") or ""), str(item.get("type") or ""), str(item.get("module") or "")),
        )[:15]
        for e in important_events:
            ts = e.get('ts', '').split('T')[-1].split('.')[0] if 'T' in e.get('ts', '') else ''
            module = str(e.get('module', 'engine'))
            etype = str(e.get('type', 'EVENT'))
            data = e.get('data', {})
            msg = data.get('title') or data.get('message') or str(data)
            
            pdf.set_x(10) # Force reset to left margin
            pdf.set_font("helvetica", "", 8)
            pdf.cell(20, 5, pdf.safe_text(ts))
            pdf.set_font("helvetica", "B", 8)
            pdf.cell(30, 5, pdf.safe_text(f"[{module}]"))
            pdf.set_font("helvetica", "", 8)
            # Use safe width: 210 - 10 - 10 - 20 - 30 = 140
            pdf.multi_cell(140, 5, pdf.safe_text(f"{etype}: {msg}"))
    
    # 3. Recon Matrix
    pdf.chapter_title("2. Technical Reconnaissance Matrix")
    if results and 'phases' in results and 'recon' in results['phases']:
        ports = results['phases']['recon'].get('open_ports', [])
        
        pdf.set_fill_color(230, 230, 235)
        pdf.set_font("helvetica", "B", 9)
        pdf.cell(20, 8, "Port", border=1, fill=True)
        pdf.cell(40, 8, "Service", border=1, fill=True)
        pdf.cell(100, 8, "Version / Banner", border=1, fill=True)
        pdf.cell(20, 8, "Risk", border=1, fill=True, ln=True)
        
        pdf.set_font("helvetica", "", 8)
        for p in sorted(ports, key=lambda x: x.get('priority_score', 0), reverse=True):
            score = p.get('priority_score', 0)
            if score >= 80: pdf.set_text_color(196, 100, 20)
            else: pdf.set_text_color(0, 0, 0)
            
            pdf.cell(20, 7, f"{p['port']}/tcp", border=1)
            pdf.cell(40, 7, pdf.safe_text(p['service_name']), border=1)
            ver = pdf.safe_text(str(p.get('version', 'Not Fingerprinted')))
            pdf.cell(100, 7, ver[:100], border=1)
            pdf.cell(20, 7, str(score), border=1, ln=True)
    pdf.set_text_color(0, 0, 0)

    # 4. OSINT Intelligence
    pdf.chapter_title("3. Infrastructure Intelligence (OSINT)")
    
    # Cloud Assets
    if results and 'phases' in results and 'osint' in results['phases']:
        osint = results['phases']['osint']
        
        # Subdomains
        if 'phases' in results and 'dns' in results['phases']:
            subs = results['phases']['dns'].get('subdomains', [])
            if subs:
                # Robustness: Ensure subs is a list of strings
                if isinstance(subs, tuple):
                     # Handle legacy bug where run_command tuple was stored
                     if len(subs) > 1 and isinstance(subs[1], str):
                         subs = subs[1].splitlines()
                     else:
                         subs = []
                elif not isinstance(subs, list):
                     subs = []
                
                # Filter non-string items and empty strings
                subs = [s for s in subs if isinstance(s, str) and s.strip()]

                if subs:
                    unique_subs = sorted(list(set(subs)))
                    pdf.set_font("helvetica", "B", 10)
                    pdf.cell(0, 7, f"Discovered Subdomains ({len(unique_subs)}):", ln=True)
                    pdf.set_font("helvetica", "", 8)
                    pdf.multi_cell(0, 5, pdf.safe_text(", ".join(unique_subs)))
                    pdf.ln(3)

        # Cloud
        if osint.get('cloud'):
            pdf.set_font("helvetica", "B", 10)
            pdf.cell(0, 7, f"Cloud Assets Found ({len(osint['cloud'])}):", ln=True)
            pdf.set_font("helvetica", "", 8)
            for c in osint['cloud']:
                pdf.cell(0, 5, pdf.safe_text(f"- [{c['provider']}] {c.get('bucket', c.get('account'))} ({c['status']})"), ln=True)
            pdf.ln(3)

        # GitHub
        if osint.get('github'):
            pdf.set_font("helvetica", "B", 10)
            pdf.cell(0, 7, f"GitHub Leaks ({len(osint['github'])}):", ln=True)
            pdf.set_font("helvetica", "", 8)
            for g in osint['github']:
                pdf.cell(0, 5, pdf.safe_text(f"- {g['repository']}: {g['path']}"), ln=True)
            pdf.ln(3)

        # Emails
        if osint.get('emails'):
            unique_emails = sorted(list(set(osint['emails'])))
            pdf.set_font("helvetica", "B", 10)
            pdf.cell(0, 7, f"Email Addresses ({len(unique_emails)}):", ln=True)
            pdf.set_font("helvetica", "", 8)
            pdf.multi_cell(0, 5, pdf.safe_text(", ".join(unique_emails)))
            pdf.ln(3)

    # 4.5 Strategic Intelligence (Cortex)
    if results and 'phases' in results and 'enum' in results['phases'] and 'derived' in results['phases']['enum']:
        derived = results['phases']['enum']['derived']
        pdf.chapter_title("4. Strategic Intelligence (Cortex)")
        
        # Recommendations
        recs = derived.get('cortex_recommendations', [])
        if recs:
            pdf.set_font("helvetica", "B", 11)
            pdf.set_text_color(0, 100, 200)
            pdf.cell(0, 7, "Strategic Recommendations:", ln=True)
            pdf.set_font("helvetica", "", 9)
            pdf.set_text_color(50, 50, 50)
            seen_recs = set()
            for r in recs:
                title = r.get('title', 'Recommendation')
                if title in seen_recs: continue
                seen_recs.add(title)
                
                reason = r.get('reason', '')
                conf = r.get('confidence', 0)
                pdf.set_font("helvetica", "B", 9)
                pdf.cell(0, 5, pdf.safe_text(f"- {title} (Signal strength: {conf}%)"), ln=True)
                pdf.set_font("helvetica", "I", 8)
                pdf.multi_cell(0, 4, pdf.safe_text(f"  Audit recommendation: {reason}"))
                pdf.ln(2)
        
        # Surface Expansion
        expansion = derived.get('surface_expansion', {})
        if expansion:
            pdf.ln(2)
            pdf.set_font("helvetica", "B", 11)
            pdf.set_text_color(200, 100, 0)
            pdf.cell(0, 7, "Derived Surface Expansion (Heuristics):", ln=True)
            pdf.set_font("helvetica", "", 9)
            pdf.set_text_color(50, 50, 50)
            
            global_eps = expansion.get('global', {}).get('derived_endpoints', [])
            if global_eps:
                unique_eps = sorted(list(set(global_eps)))
                pdf.set_font("helvetica", "B", 9)
                pdf.cell(0, 5, "Heuristic Search Nodes:", ln=True)
                pdf.set_font("helvetica", "I", 8)
                pdf.multi_cell(0, 5, pdf.safe_text(", ".join(unique_eps)))
                pdf.ln(2)

        # Service Intel
        intel = derived.get('service_intelligence', [])
        if intel:
            pdf.ln(2)
            pdf.set_font("helvetica", "B", 11)
            pdf.set_text_color(50, 50, 50)
            pdf.cell(0, 7, "Service Intelligence Tags:", ln=True)
            pdf.set_font("helvetica", "", 9)
            tags_found = set()
            for item in intel:
                for t in item.get('tags', []):
                    tags_found.add(f"{t} (Port {item.get('port')})")
            pdf.multi_cell(0, 5, pdf.safe_text(", ".join(sorted(tags_found))))
            pdf.ln(5)

    # 5. Technology Intelligence
    if results and 'phases' in results and 'enum' in results['phases'] and 'tech' in results['phases']['enum']:
        tech = results['phases']['enum']['tech']
        pdf.chapter_title("5. Technology Stack Intelligence")
        
        pdf.set_font("helvetica", "B", 10)
        pdf.cell(50, 7, "Modernization Level:", border=1)
        pdf.set_font("helvetica", "", 10)
        
        modernization = "Unknown"
        if isinstance(tech, dict):
            modernization = tech.get('modernization_level', 'Unknown')
        pdf.cell(0, 7, pdf.safe_text(modernization), border=1, ln=True)
        
        pdf.set_font("helvetica", "B", 10)
        pdf.cell(50, 7, "Technology Score:", border=1)
        pdf.set_font("helvetica", "", 10)
        
        score = 0
        if isinstance(tech, dict):
            score = tech.get('technology_score', 0)
        pdf.cell(0, 7, f"{score}/100", border=1, ln=True)
        
        pdf.ln(3)
        pdf.set_font("helvetica", "B", 10)
        pdf.cell(0, 7, "Detected Frameworks & Libraries:", ln=True)
        pdf.set_font("helvetica", "", 9)
        
        # Combine WhatWeb and Tech Detector
        all_techs = []
        is_wp_detected = False
        
        # Check vuln phase for explicit WP detection
        if results.get('phases', {}).get('vuln', {}).get('wordpress'):
            all_techs.append("WordPress (Confirmed)")
            is_wp_detected = True

        if 'whatweb' in results['phases']['enum']:
            ww_data = results['phases']['enum']['whatweb']
            # Check for parsed technologies first (new format)
            if 'technologies' in ww_data:
                for port, port_techs in ww_data['technologies'].items():
                     if isinstance(port_techs, list):
                         for t in port_techs:
                             if t not in all_techs: all_techs.append(t)
                             if "WordPress" in t: is_wp_detected = True
            
            # Fallback to summary parsing (legacy / backward compatibility)
            elif 'summary' in ww_data:
                 # Try to extract from summary if not parsed
                 for port, summ in ww_data['summary'].items():
                     if "WordPress" in summ: is_wp_detected = True

        if all_techs:
             pdf.multi_cell(0, 5, pdf.safe_text(", ".join(all_techs)))
        else:
             pdf.cell(0, 5, "No specific frameworks identified.", ln=True)
        pdf.ln(3)

    # 5.5 CMS Intelligence (WordPress Deep Dive)
    if results and 'phases' in results and 'vuln' in results['phases'] and 'wordpress' in results['phases']['vuln']:
        wp_data_all = results['phases']['vuln']['wordpress']
        pdf.chapter_title("5.5 CMS Intelligence (WordPress Analysis)")
        
        for port, wp in wp_data_all.items():
            pdf.set_font("helvetica", "B", 10)
            pdf.cell(0, 7, f"WordPress Analysis on Port {port}:", ln=True)
            
            pdf.set_font("helvetica", "", 9)
            pdf.cell(50, 6, "WordPress Version:", border=1)
            pdf.cell(0, 6, pdf.safe_text(wp.get('version', 'Unknown')), border=1, ln=True)
            
            pdf.cell(50, 6, "Theme:", border=1)
            pdf.cell(0, 6, pdf.safe_text(wp.get('theme', 'Unknown')), border=1, ln=True)
            
            if wp.get('wordfence_detected'):
                pdf.set_text_color(200, 50, 0)
                pdf.cell(50, 6, "WAF Detected:", border=1)
                pdf.cell(0, 6, "Wordfence (Evasion Mode Active)", border=1, ln=True)
                pdf.set_text_color(0, 0, 0)

            # Vulnerable Plugins
            vulns = wp.get('vulns', [])
            if vulns:
                pdf.ln(2)
                pdf.set_font("helvetica", "B", 10)
                pdf.set_text_color(120, 60, 140)
                pdf.cell(0, 7, f"Direct Vulnerabilities Found ({len(vulns)}):", ln=True)
                pdf.set_font("helvetica", "", 8)
                pdf.set_text_color(0, 0, 0)
                for v in vulns:
                    pdf.set_x(15) # Indent slightly and ensure space
                    # Width: 180 (10 margin + 180 = 190, leaves 10 margin at right)
                    pdf.multi_cell(180, 5, pdf.safe_text(f"• [{v.get('component', 'Core')}] {v.get('title') or v.get('raw_title')}"))
            
            # Enumerated Plugins
            plugins = wp.get('plugins', [])
            if plugins:
                pdf.ln(2)
                pdf.set_font("helvetica", "B", 10)
                pdf.cell(0, 7, f"Detected Plugins ({len(plugins)}):", ln=True)
                pdf.set_font("helvetica", "", 8)
                for p in plugins:
                    p_info = f"- {p['slug']} v{p['version']}"
                    if p.get('vulns'): p_info += f" [! {len(p['vulns'])} VULNS]"
                    pdf.cell(0, 5, pdf.safe_text(p_info), ln=True)
            
            # Users
            users = wp.get('users', [])
            if users:
                pdf.ln(2)
                pdf.set_font("helvetica", "B", 10)
                pdf.cell(0, 7, f"Enumerated Users ({len(users)}):", ln=True)
                pdf.set_font("helvetica", "", 8)
                user_names = []
                for u in users:
                    if isinstance(u, dict): user_names.append(u.get('name', 'Unknown'))
                    else: user_names.append(str(u))
                pdf.multi_cell(0, 5, pdf.safe_text(", ".join(user_names)))
            
            pdf.ln(5)


    # 4.6 Security Headers
    if results and 'phases' in results and 'enum' in results['phases'] and 'headers' in results['phases']['enum']:
        headers_data = results['phases']['enum']['headers']
        if headers_data:
            pdf.chapter_title("6. Security Headers Analysis")
            
            for port, headers in headers_data.items():
                pdf.set_font("helvetica", "B", 10)
                pdf.cell(0, 6, f"Port {port}:", ln=True)
                pdf.set_font("helvetica", "", 8)
                
                # Interesting headers to highlight
                highlights = ['Server', 'X-Powered-By', 'Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options']
                
                highlight_keys = [h.lower() for h in highlights]
                for k, v in headers.items():
                    if k.lower() in highlight_keys:
                        pdf.set_x(15)
                        pdf.set_font("helvetica", "B", 8)
                        pdf.cell(50, 5, pdf.safe_text(k), border=1)
                        pdf.set_font("helvetica", "", 8)
                        # More conservative width: 120 (Total 15+50+120=185)
                        pdf.multi_cell(120, 5, pdf.safe_text(v), border=1)
                    else:
                        pass
                pdf.ln(2)

    # 5. API & Web Endpoints
    if results and 'phases' in results and 'enum' in results['phases'] and 'api' in results['phases']['enum']:
        api = results['phases']['enum']['api']
        if api.get('endpoints'):
            pdf.add_page()
            pdf.chapter_title("7. API & Web Endpoints Analysis")
            
            pdf.set_font("helvetica", "B", 10)
            pdf.cell(0, 7, f"Discovered API Endpoints ({len(api['endpoints'])}):", ln=True)
            
            pdf.set_font("helvetica", "", 8)
            pdf.set_fill_color(240, 240, 245)
            
            # Table header
            pdf.cell(20, 6, "Method", border=1, fill=True)
            pdf.cell(15, 6, "Status", border=1, fill=True) 
            pdf.cell(155, 6, "URL / Path", border=1, fill=True, ln=True)
            
            for ep in api['endpoints'][:100]: # Limit to 100 to avoid 500 pages
                url_value = ""
                status_value = "Unverified"
                if isinstance(ep, dict):
                    url_value = str(ep.get('url') or ep.get('endpoint') or ep.get('path') or '')
                    if ep.get('status') not in (None, ""):
                        status_value = str(ep.get('status'))
                else:
                    url_value = str(ep)
                pdf.cell(20, 6, "GET", border=1) # Katana usually GET
                pdf.cell(15, 6, pdf.safe_text(status_value), border=1)
                pdf.cell(155, 6, pdf.safe_text(url_value[:180]), border=1, ln=True)
                
            if len(api['endpoints']) > 100:
                pdf.cell(0, 6, f"... and {len(api['endpoints']) - 100} more endpoints.", border=1, ln=True)
            pdf.ln(5)

    # 5.5. Directory Busting (Recursive)
    if results and 'phases' in results and 'dirbusting' in results['phases']:
        dirs = []
        if 'ffuf' in results['phases']['dirbusting'] and 'endpoints' in results['phases']['dirbusting']['ffuf']:
            dirs = results['phases']['dirbusting']['ffuf']['endpoints']
            
        if dirs:
            pdf.add_page()
            pdf.chapter_title("8. Recursive Directory Analysis")
            
            pdf.set_font("helvetica", "B", 10)
            pdf.cell(0, 7, f"Discovered Paths ({len(dirs)}):", ln=True)
            
            pdf.set_font("helvetica", "", 8)
            pdf.set_fill_color(240, 240, 245)
            
            # Simple list mechanism or table
            for d in dirs[:100]:
                url = d.get('url', str(d)) if isinstance(d, dict) else str(d)
                pdf.cell(0, 5, pdf.safe_text(url), border=1, ln=True)
                
            if len(dirs) > 100:
                pdf.cell(0, 5, f"... and {len(dirs) - 100} more paths.", border=1, ln=True)
            pdf.ln(5)

    # 9. FINDINGS
    pdf.chapter_title("9. Detailed Findings & Validation Context")
    
    sev_map = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    
    def get_sev(f):
        return (f.get('severity', 'info') if isinstance(f, dict) else getattr(f, 'severity', 'info')).lower()
        
    sorted_findings = sorted(findings, key=lambda x: sev_map.get(get_sev(x), 4))
    
    import re
    # Grouping repetitive INFO findings to keep report size manageable
    info_groups = {
        "Subdomain Inferred": [],
        "Parameter Surface Discovered": [],
        "Discovered Asset": []
    }
    other_findings = []
    
    for f in sorted_findings:
        sev = get_sev(f)
        title = f.get('title', 'Unknown') if isinstance(f, dict) else getattr(f, 'title', 'Unknown')
        
        grouped = False
        if sev == "info":
            for prefix in info_groups.keys():
                if title.startswith(f"{prefix}:"):
                    val = title.replace(f"{prefix}:", "").strip()
                    info_groups[prefix].append(val)
                    grouped = True
                    break
        
        if not grouped:
            other_findings.append(f)

    # Print Detailed Findings
    for f in other_findings:
        if pdf.get_y() > 250: pdf.add_page()
        
        sev = get_sev(f)
        # Severity palette rule: red is reserved strictly for HIGH severity findings.
        bg_color, text_color = severity_color_for_pdf(sev)
        
        title = f.get('title', 'Unknown') if isinstance(f, dict) else getattr(f, 'title', 'Unknown')
        tool_source = f.get('tool_source', 'Unknown') if isinstance(f, dict) else getattr(f, 'tool_source', 'Unknown')
        detail = f.get('_detail', {}) if isinstance(f, dict) else {}
        ui = f.get('_ui', {}) if isinstance(f, dict) else {}
        description = detail.get('summary') or (f.get('description', '') if isinstance(f, dict) else getattr(f, 'description', ''))
        confidence = (detail.get('confidence') or (f.get('confidence', '') if isinstance(f, dict) else getattr(f, 'confidence', '')) or 'medium').upper()
        visible_truth = str(ui.get("visibleTruthLabel") or "observation").upper()
        validation_status = str(ui.get("validationStatus") or "not_run").upper()
        result_state = str(ui.get("resultState") or "observation").replace("_", " ").upper()
        target = detail.get('target', '')
        versions = detail.get('observedVersions', []) if isinstance(detail.get('observedVersions'), list) else []
        command_blocks = detail.get('commandBlocks', []) if isinstance(detail.get('commandBlocks'), list) else []
        evidence_blocks = detail.get('evidenceBlocks', []) if isinstance(detail.get('evidenceBlocks'), list) else []
        technical_context = detail.get('technicalContext', []) if isinstance(detail.get('technicalContext'), list) else []
        interpretation = detail.get('interpretation', '')
        remediation = detail.get('remediation', '')
        references = detail.get('references', []) if isinstance(detail.get('references'), list) else []
        artifacts = detail.get('artifacts', []) if isinstance(detail.get('artifacts'), list) else []
        validation_guidance = detail.get('validationGuidance', '')
        
        # Draw finding header
        pdf.set_fill_color(*bg_color)
        pdf.set_text_color(*text_color)
        pdf.set_font("helvetica", "B", 11)
        # Clean title from prefix if it already exists
        title_cleaned = title.replace(f"{sev.upper()}:", "").strip()
        pdf.cell(0, 8, pdf.safe_text(f" {sev.upper()}: {title_cleaned}"), fill=True, ln=True)
        
        # Finding Details Section
        pdf.set_text_color(50, 50, 50)
        pdf.set_font("helvetica", "B", 8)
        pdf.cell(0, 5, pdf.safe_text(f" Vector Source: {tool_source} | Confidence: {confidence} | Visible Class: {visible_truth}"), ln=True)
        pdf.cell(0, 5, pdf.safe_text(f" Validation: {validation_status} | Result State: {result_state}"), ln=True)
        
        pdf.set_font("helvetica", "", 9)
        pdf.set_text_color(60, 60, 65)
        pdf.set_x(10)
        
        # Truncate description for Info findings if they are still very long
        if sev == "info" and len(description) > 500:
            description = description[:500] + "... [TRUNCATED]"
            
        pdf.multi_cell(190, 5, pdf.safe_text(description))

        if target:
            pdf.set_font("helvetica", "B", 7)
            pdf.cell(0, 5, " Target:", ln=True)
            pdf.set_font("courier", "", 7)
            pdf.multi_cell(190, 3.5, pdf.safe_text(target), border=1)

        if versions:
            pdf.set_font("helvetica", "B", 7)
            pdf.cell(0, 5, " Observed Versions:", ln=True)
            pdf.set_font("helvetica", "", 7)
            pdf.multi_cell(190, 4, pdf.safe_text(", ".join(versions)), border=1)

        if technical_context:
            pdf.ln(1)
            pdf.set_fill_color(240, 240, 240)
            pdf.set_text_color(100, 100, 100)
            pdf.set_font("helvetica", "B", 8)
            pdf.cell(0, 6, " TECHNICAL CONTEXT", fill=True, ln=True)
            for row in technical_context:
                if not isinstance(row, dict):
                    continue
                label = row.get("label", "")
                value = row.get("value", "")
                if not label or not value:
                    continue
                pdf.set_font("helvetica", "B", 7)
                pdf.set_text_color(60, 60, 65)
                pdf.cell(0, 5, pdf.safe_text(f" {label}:"), ln=True)
                pdf.set_font("helvetica", "", 7)
                pdf.multi_cell(190, 3.5, pdf.safe_text(_truncate_report_block(value, 500)), border=1)

        if command_blocks or validation_guidance:
            pdf.ln(1)
            pdf.set_fill_color(240, 240, 240)
            pdf.set_text_color(100, 100, 100)
            pdf.set_font("helvetica", "B", 8)
            pdf.cell(0, 6, " HOW TO VALIDATE SAFELY", fill=True, ln=True)

            for block in command_blocks:
                if not isinstance(block, dict):
                    continue
                pdf.set_font("helvetica", "B", 7)
                pdf.set_text_color(60, 60, 65)
                pdf.cell(0, 5, pdf.safe_text(f" {block.get('label', 'Command')}:"), ln=True)
                pdf.set_font("courier", "", 7)
                pdf.multi_cell(190, 3.5, pdf.safe_text(_truncate_report_block(block.get("value"), 1200)), border=1)

            if validation_guidance:
                pdf.set_font("helvetica", "B", 7)
                pdf.set_text_color(60, 60, 65)
                pdf.cell(0, 5, " Validation Guidance:", ln=True)
                pdf.set_font("helvetica", "", 7)
                pdf.multi_cell(190, 4, pdf.safe_text(_truncate_report_block(validation_guidance, 900)), border=1)

        if evidence_blocks:
            pdf.ln(1)
            pdf.set_fill_color(240, 240, 240)
            pdf.set_text_color(100, 100, 100)
            pdf.set_font("helvetica", "B", 8)
            pdf.cell(0, 6, " RECORDED EVIDENCE / WHAT REMAINS UNVERIFIED", fill=True, ln=True)

            for block in evidence_blocks:
                if not isinstance(block, dict):
                    continue
                pdf.set_font("helvetica", "B", 7)
                pdf.set_text_color(60, 60, 65)
                pdf.cell(0, 5, pdf.safe_text(f" {block.get('label', 'Evidence')}:"), ln=True)
                pdf.set_font("courier", "", 7)
                pdf.multi_cell(190, 3.5, pdf.safe_text(_truncate_report_block(block.get("value"), 1400)), border=1)

        if interpretation:
            pdf.set_font("helvetica", "B", 7)
            pdf.set_text_color(60, 60, 65)
            pdf.cell(0, 5, " Interpretation:", ln=True)
            pdf.set_font("helvetica", "", 7)
            pdf.multi_cell(190, 4, pdf.safe_text(_truncate_report_block(interpretation, 900)), border=1)

        if remediation:
            pdf.set_font("helvetica", "B", 7)
            pdf.set_text_color(60, 60, 65)
            pdf.cell(0, 5, " Remediation:", ln=True)
            pdf.set_font("helvetica", "", 7)
            pdf.multi_cell(190, 4, pdf.safe_text(_truncate_report_block(remediation, 900)), border=1)

        if references:
            pdf.set_font("helvetica", "B", 7)
            pdf.set_text_color(60, 60, 65)
            pdf.cell(0, 5, " References:", ln=True)
            pdf.set_font("helvetica", "", 7)
            pdf.multi_cell(190, 4, pdf.safe_text("\n".join(f"- {ref}" for ref in references)), border=1)

        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            if artifact.get("kind") == "image":
                full_img_path = os.path.join("ui/web/static", str(artifact.get("value", "")))
                if os.path.exists(full_img_path):
                    try:
                        pdf.ln(2)
                        pdf.image(full_img_path, w=150)
                        pdf.ln(5)
                    except Exception:
                        pass
                continue
            pdf.set_font("helvetica", "B", 7)
            pdf.set_text_color(60, 60, 65)
            pdf.cell(0, 5, pdf.safe_text(f" {artifact.get('label', 'Artifact')}:"), ln=True)
            pdf.set_font("courier", "", 7)
            pdf.multi_cell(190, 3.5, pdf.safe_text(_truncate_report_block(artifact.get("value"), 1200)), border=1)

        pdf.ln(6)

    # Print Grouped Info Findings
    for prefix, values in info_groups.items():
        if not values: continue
        if pdf.get_y() > 240: pdf.add_page()
        
        pdf.set_fill_color(245, 245, 250)
        pdf.set_text_color(100, 100, 100)
        pdf.set_font("helvetica", "B", 10)
        pdf.cell(0, 8, pdf.safe_text(f" INFO SUMMARY: {prefix} ({len(values)})"), fill=True, ln=True)
        
        pdf.set_font("helvetica", "", 8)
        pdf.set_text_color(80, 80, 85)
        # Deduplicate and sort values for clean summary
        unique_vals = sorted(list(set(values)))
        summary_text = ", ".join(unique_vals)
        if len(summary_text) > 5000:
             summary_text = summary_text[:5000] + "... [TRUNCATED DUE TO VOLUME]"
             
        pdf.multi_cell(190, 4, pdf.safe_text(summary_text))
        pdf.ln(5)

    # 6. LOOT VAULT
    from core.models import Loot
    loots = Loot.query.filter_by(scan_id=scan_id).all()
    if loots:
        pdf.add_page()
        pdf.chapter_title("10. Loot Vault (Classified Assets)", color=(0, 150, 50))
        pdf.set_font("helvetica", "B", 10)
        pdf.cell(40, 8, "Type", border=1, fill=True)
        pdf.cell(100, 8, "Content (Masked)", border=1, fill=True)
        pdf.cell(50, 8, "Context", border=1, fill=True, ln=True)
        
        pdf.set_font("helvetica", "", 8)
        for l in loots:
            masked_content = l.content[:80] + "..." if len(l.content) > 85 else l.content
            pdf.cell(40, 7, pdf.safe_text(l.type), border=1)
            pdf.cell(100, 7, pdf.safe_text(masked_content), border=1)
            pdf.cell(50, 7, pdf.safe_text(str(l.context)[:100]), border=1, ln=True)

    # 7. Notes
    if scan_obj.notes:
        pdf.add_page()
        pdf.chapter_title("11. Operational Mission Notes", color=(100, 100, 100))
        pdf.set_font("helvetica", "", 10)
        pdf.set_text_color(50, 50, 50)
        pdf.multi_cell(0, 6, pdf.safe_text(scan_obj.notes))

    filename = f"redops_report_{scan_id}_{datetime.now().strftime('%Y%m%d%H%M')}.pdf"
    path = os.path.join(REPORTS_DIR, filename)
    pdf.output(path)
    return filename

def generate_html_report(scan_id, scan_obj, findings, suggestions):
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR, exist_ok=True)
        
    results = load_results(scan_id)
    
    # Calculate duration
    duration = "N/A"
    if scan_obj.end_time and scan_obj.start_time:
        delta = scan_obj.end_time - scan_obj.start_time
        duration = str(delta).split('.')[0]
        
    # We need to render the template. 
    # Since this might be called from background task or context where render_template works:
    from flask import render_template
    
    html_content = render_template(
        "reports/standard_report.html",
        scan=scan_obj,
        results=results,
        findings=prepare_report_findings(findings),
        suggestions=suggestions,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        duration=duration
    )
    
    filename = f"redops_report_{scan_id}_{datetime.now().strftime('%Y%m%d%H%M')}.html"
    path = os.path.join(REPORTS_DIR, filename)
    
    with open(path, "w", encoding='utf-8') as f:
        f.write(html_content)
        
    return filename
