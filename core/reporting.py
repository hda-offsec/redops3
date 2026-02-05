from fpdf import FPDF
import os
import json
from datetime import datetime
from markdown import markdown
from core.results_store import load_results

REPORTS_DIR = "data/reports"

class RedOpsReport(FPDF):
    def header(self):
        self.set_fill_color(30, 30, 30)
        self.rect(0, 0, 210, 40, 'F')
        self.set_font('helvetica', 'B', 24)
        self.set_text_color(255, 42, 42)
        self.cell(0, 20, 'REDOPS3 - OFFENSIVE REPORT', ln=True, align='C')
        self.set_font('helvetica', 'I', 10)
        self.set_text_color(200, 200, 200)
        self.cell(0, 10, f'Mission Control Data Export - {datetime.now().strftime("%Y-%m-%d %H:%M")}', ln=True, align='C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f'Page {self.page_no()} - Internal Use Only - RedOps3 Framework', align='C')

def generate_scan_report(scan_id, scan_obj, findings):
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR, exist_ok=True)
        
    results = load_results(scan_id)
    pdf = RedOpsReport()
    pdf.add_page()
    
    # --- EXECUTIVE SUMMARY ---
    pdf.set_font("helvetica", "B", 16)
    pdf.set_text_color(50, 50, 50)
    pdf.cell(0, 10, "1. Executive Summary", ln=True)
    pdf.ln(5)
    
    pdf.set_font("helvetica", "", 11)
    summary = f"Security assessment for target {scan_obj.target.identifier}. "
    summary += f"Status: {scan_obj.status.upper()}. Total findings: {len(findings)}."
    pdf.multi_cell(0, 7, summary)
    pdf.ln(10)
    
    # --- RECON MATRIX ---
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(0, 10, "2. Technical Reconnaissance Matrix", ln=True)
    pdf.ln(5)
    
    if results and 'phases' in results and 'recon' in results['phases']:
        ports = results['phases']['recon'].get('open_ports', [])
        
        # Table Header
        pdf.set_fill_color(240, 240, 240)
        pdf.set_font("helvetica", "B", 10)
        pdf.cell(30, 10, "Port", border=1, fill=True)
        pdf.cell(50, 10, "Service", border=1, fill=True)
        pdf.cell(80, 10, "Version", border=1, fill=True)
        pdf.cell(30, 10, "Score", border=1, fill=True, ln=True)
        
        pdf.set_font("helvetica", "", 10)
        for p in sorted(ports, key=lambda x: x.get('priority_score', 0), reverse=True):
            pdf.cell(30, 8, f"{p['port']}/tcp", border=1)
            pdf.cell(50, 8, p['service_name'], border=1)
            pdf.cell(80, 8, str(p.get('version', '')), border=1)
            pdf.cell(30, 8, str(p.get('priority_score', 0)), border=1, ln=True)
    else:
        pdf.cell(0, 10, "No recon data available.", ln=True)
        
    pdf.ln(10)
    
    # --- FINDINGS ---
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(0, 10, "3. Identified Vulnerabilities & Vectors", ln=True)
    pdf.ln(5)
    
    for f in findings:
        # Severity Badge
        sev = f.severity.lower()
        if sev == 'critical': color = (200, 0, 0)
        elif sev == 'high': color = (255, 42, 42)
        elif sev == 'medium': color = (255, 165, 0)
        else: color = (0, 100, 200)
        
        pdf.set_text_color(*color)
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, f"[{f.severity.upper()}] {f.title}", ln=True)
        
        pdf.set_text_color(70, 70, 70)
        pdf.set_font("helvetica", "", 10)
        pdf.multi_cell(0, 6, f.description)
        
        if f.screenshot_path:
            full_img_path = os.path.join("ui/web/static", f.screenshot_path)
            if os.path.exists(full_img_path):
                pdf.image(full_img_path, w=100)
                pdf.ln(5)
        pdf.ln(5)

    # --- OPERATOR NOTES ---
    if scan_obj.notes:
        pdf.add_page()
        pdf.set_font("helvetica", "B", 16)
        pdf.set_text_color(50, 50, 50)
        pdf.cell(0, 10, "4. Operator Mission Notes", ln=True)
        pdf.ln(5)
        pdf.set_font("helvetica", "", 10)
        pdf.multi_cell(0, 6, scan_obj.notes)

    filename = f"report_scan_{scan_id}.pdf"
    path = os.path.join(REPORTS_DIR, filename)
    pdf.output(path)
    return filename
