from fpdf import FPDF
import os
import json
from datetime import datetime
from markdown import markdown
from core.results_store import load_results

REPORTS_DIR = "data/reports"

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
        self.set_font('helvetica', 'B', 12)
        self.set_text_color(255, 42, 42)
        self.cell(0, 10, 'REDOPS3 - OFFENSIVE INTELLIGENCE REPORT', ln=True, align='L')
        
        self.set_y(12)
        self.set_font('helvetica', '', 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 5, f'TARGET: {self.target_name} | CLASSIFIED', ln=True, align='L')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
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
        self.set_text_color(255, 42, 42)
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
            self.set_text_color(255, 42, 42)
            self.cell(0, 10, f'ALERT: {findings_count} VULNERABILITIES IDENTIFIED', ln=True, align='C')
        else:
            self.set_text_color(0, 255, 100)
            self.cell(0, 10, 'CLEAN BILL OF HEALTH - NO CRITICAL VECTORS FOUND', ln=True, align='C')

    def safe_text(self, text):
        """Sanitizes text to be compatible with latin-1 encoding used by core fonts."""
        if not text: return ""
        # Map common problematic chars
        replacements = {
            "✅": "[YES]", "❌": "[NO]", "⚠️": "[WARN]", "🔥": "[CRIT]",
            "✓": "[OK]", "—": "-", "’": "'", "“": "\"", "”": "\"",
            "…": "..."
        }
        for k, v in replacements.items():
            text = text.replace(k, v)
        
        # Fallback: encode/decode to strip unhandled chars
        try:
            return text.encode('latin-1', 'replace').decode('latin-1')
        except:
            return text

    def chapter_title(self, title, color=(255, 42, 42)):
        self.ln(10)
        self.set_font('helvetica', 'B', 16)
        self.set_text_color(*color)
        self.cell(0, 10, self.safe_text(title), ln=True)
        self.set_draw_color(*color)
        self.line(self.get_x(), self.get_y(), self.get_x() + 190, self.get_y())
        self.ln(5)

def generate_scan_report(scan_id, scan_obj, findings):
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR, exist_ok=True)
        
    results = load_results(scan_id)
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
        s = f.severity.lower()
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
            if score >= 80: pdf.set_text_color(255, 42, 42)
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
                pdf.set_font("helvetica", "B", 10)
                pdf.cell(0, 7, f"Discovered Subdomains ({len(subs)}):", ln=True)
                pdf.set_font("helvetica", "", 8)
                pdf.multi_cell(0, 5, pdf.safe_text(", ".join(subs)))
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
            pdf.set_font("helvetica", "B", 10)
            pdf.cell(0, 7, f"Email Addresses ({len(osint['emails'])}):", ln=True)
            pdf.set_font("helvetica", "", 8)
            pdf.multi_cell(0, 5, pdf.safe_text(", ".join(osint['emails'])))
            pdf.ln(3)

    # 4.5 Technology Intelligence
    if results and 'phases' in results and 'enum' in results['phases'] and 'tech' in results['phases']['enum']:
        tech = results['phases']['enum']['tech']
        pdf.chapter_title("4. Technology Stack Intelligence")
        
        pdf.set_font("helvetica", "B", 10)
        pdf.cell(50, 7, "Modernization Level:", border=1)
        pdf.set_font("helvetica", "", 10)
        pdf.cell(0, 7, pdf.safe_text(tech.get('modernization_level', 'Unknown')), border=1, ln=True)
        
        pdf.set_font("helvetica", "B", 10)
        pdf.cell(50, 7, "Technology Score:", border=1)
        pdf.set_font("helvetica", "", 10)
        score = tech.get('technology_score', 0)
        pdf.cell(0, 7, f"{score}/100", border=1, ln=True)
        
        pdf.ln(3)
        pdf.set_font("helvetica", "B", 10)
        pdf.cell(0, 7, "Detected Frameworks & Libraries:", ln=True)
        pdf.set_font("helvetica", "", 9)
        
        # Combine WhatWeb and Tech Detector
        all_techs = []
        if 'whatweb' in results['phases']['enum']:
            for port, techs in results['phases']['enum']['whatweb'].items():
                all_techs.extend([t for t in techs if t not in all_techs])
                
        if all_techs:
             pdf.multi_cell(0, 5, pdf.safe_text(", ".join(all_techs)))
        else:
             pdf.cell(0, 5, "No specific frameworks identified.", ln=True)
        pdf.ln(3)

    # 4.6 API & Web Endpoints
    if results and 'phases' in results and 'enum' in results['phases'] and 'api' in results['phases']['enum']:
        api = results['phases']['enum']['api']
        if api.get('endpoints'):
            pdf.add_page()
            pdf.chapter_title("5. API & Web Entpoints Analysis")
            
            pdf.set_font("helvetica", "B", 10)
            pdf.cell(0, 7, f"Discovered API Endpoints ({len(api['endpoints'])}):", ln=True)
            
            pdf.set_font("helvetica", "", 8)
            pdf.set_fill_color(240, 240, 245)
            
            # Table header
            pdf.cell(20, 6, "Method", border=1, fill=True)
            pdf.cell(15, 6, "Status", border=1, fill=True) 
            pdf.cell(155, 6, "URL / Path", border=1, fill=True, ln=True)
            
            for ep in api['endpoints'][:100]: # Limit to 100 to avoid 500 pages
                pdf.cell(20, 6, "GET", border=1) # Katana usually GET
                pdf.cell(15, 6, str(ep.get('status', '200')), border=1)
                pdf.cell(155, 6, pdf.safe_text(ep.get('url', '')[:180]), border=1, ln=True)
                
            if len(api['endpoints']) > 100:
                pdf.cell(0, 6, f"... and {len(api['endpoints']) - 100} more endpoints.", border=1, ln=True)
            pdf.ln(5)

    # 5. FINDINGS
    pdf.chapter_title("6. Detailed Vulnerabilities & Vectors")
    
    sev_map = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda x: sev_map.get(x.severity.lower(), 4))
    
    for f in sorted_findings:
        if pdf.get_y() > 250: pdf.add_page()
        
        sev = f.severity.lower()
        if sev == 'critical': color = (200, 0, 0)
        elif sev == 'high': color = (255, 42, 42)
        elif sev == 'medium': color = (255, 120, 0)
        else: color = (0, 100, 200)
        
        pdf.set_fill_color(*color)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("helvetica", "B", 11)
        title_cleaned = f.title.replace(f"{f.severity.upper()}:", "").strip()
        pdf.cell(0, 8, pdf.safe_text(f" {f.severity.upper()}: {title_cleaned}"), fill=True, ln=True)
        
        pdf.set_text_color(50, 50, 50)
        pdf.set_font("helvetica", "B", 9)
        pdf.cell(0, 6, pdf.safe_text(f" Source: {f.tool_source}"), ln=True)
        
        pdf.set_font("helvetica", "", 9)
        pdf.set_text_color(80, 80, 80)
        pdf.multi_cell(0, 5, pdf.safe_text(f.description))
        
        if f.screenshot_path:
            full_img_path = os.path.join("ui/web/static", f.screenshot_path)
            if os.path.exists(full_img_path):
                try:
                    pdf.ln(2)
                    pdf.image(full_img_path, w=150)
                    pdf.ln(5)
                except: pass
        pdf.ln(4)

    # 6. LOOT VAULT
    from core.models import Loot
    loots = Loot.query.filter_by(scan_id=scan_id).all()
    if loots:
        pdf.add_page()
        pdf.chapter_title("5. Loot Vault (Classified Assets)", color=(0, 150, 50))
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
        pdf.chapter_title("6. Operational Mission Notes", color=(100, 100, 100))
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
        findings=findings,
        suggestions=suggestions,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        duration=duration
    )
    
    filename = f"redops_report_{scan_id}_{datetime.now().strftime('%Y%m%d%H%M')}.html"
    path = os.path.join(REPORTS_DIR, filename)
    
    with open(path, "w", encoding='utf-8') as f:
        f.write(html_content)
        
    return filename
