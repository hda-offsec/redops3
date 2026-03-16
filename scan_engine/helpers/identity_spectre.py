from typing import Any, Dict, List
import re

class IdentitySpectre:
    """
    Synthesizes a high-density "Spectre" of the target from across all scan phases.
    This consolidates CMS, WAF, Cloud, OS, and Tech Stack into a single identity.
    """

    @staticmethod
    def synthesize(results: Dict[str, Any]) -> Dict[str, Any]:
        phases = results.get("phases", {})
        recon = phases.get("recon", {})
        enum = phases.get("enum", {})
        vuln = phases.get("vuln", {})

        spectre = {
            "os": {"name": "Unknown", "confidence": 0, "icon": "fa-microchip"},
            "waf": {"name": "None", "detected": False, "icon": "fa-shield-halved"},
            "cms": {"name": "None", "confidence": 0, "icon": "fa-puzzle-piece"},
            "cloud": {"name": "On-Prem / Unknown", "provider": "unknown", "icon": "fa-cloud"},
            "whois": {
                "registrar": "Unknown",
                "creation_date": "N/A",
                "expiration_date": "N/A",
                "nameservers": [],
                "status": [],
                "icon": "fa-globe-americas"
            },
            "stack": [], # List of detected technologies with versions
            "environment": "Unknown" # Production, Development, etc.
        }

        # 1. OS Analysis
        os_details = recon.get("enriched", {}).get("os_details", {})
        if os_details.get("os") and os_details.get("os") != "Unknown":
            spectre["os"]["name"] = os_details["os"]
            spectre["os"]["confidence"] = os_details.get("accuracy", 50)
            
        # 2. WAF Analysis
        waf_data = enum.get("waf", {})
        for port, data in waf_data.items():
            if data.get("has_waf"):
                spectre["waf"]["name"] = data.get("waf_name", "Detected")
                spectre["waf"]["detected"] = True
                break

        # 3. CMS Analysis
        # Check WhatWeb
        whatweb = enum.get("whatweb", {})
        techs = whatweb.get("technologies", {})
        cms_candidates = [
            "WordPress", "Drupal", "Joomla", "Magento", "Ghost", "Strapi", 
            "Shopify", "PrestaShop", "Wix", "Squarespace", "Bitrix"
        ]
        framework_candidates = [
            "React", "Vue", "Angular", "Next.js", "Nuxt", "Laravel", "Django", "Flask",
            "Express", "Spring", "ASP.NET", "Symfony", "Ruby on Rails"
        ]
        
        all_detected_techs = []
        for port_techs in techs.values():
            all_detected_techs.extend(port_techs)

        for tech in all_detected_techs:
            t_name = tech.get("name", "") if isinstance(tech, dict) else str(tech)
            for cms in cms_candidates:
                if cms.lower() in t_name.lower():
                    spectre["cms"]["name"] = cms
                    spectre["cms"]["confidence"] = 90
                    break
            
            for fw in framework_candidates:
                if fw.lower() in t_name.lower():
                    # We can track frameworks in stack, but CMS is a top-level field
                    pass 
            
            # Populate Stack
            v = tech.get("version") if isinstance(tech, dict) else None
            stack_item = {"name": t_name, "version": v}
            if stack_item not in spectre["stack"]:
                spectre["stack"].append(stack_item)

        # 4. Cloud Analysis
        cloud_assets = phases.get("osint", {}).get("cloud", [])
        if cloud_assets:
            # Simple heuristic: first detected provider
            for asset in cloud_assets:
                p = asset.get("provider")
                if p and p != "unknown":
                    spectre["cloud"]["name"] = p.upper()
                    spectre["cloud"]["provider"] = p
                    break
        
        # 5. WHOIS Analysis
        whois_data = phases.get("osint", {}).get("whois")
        if whois_data:
            spectre["whois"]["registrar"] = whois_data.get("registrar", "Unknown")
            spectre["whois"]["creation_date"] = whois_data.get("creation_date", "N/A")
            spectre["whois"]["expiration_date"] = whois_data.get("expiration_date", "N/A")
            spectre["whois"]["nameservers"] = whois_data.get("nameservers", [])
            spectre["whois"]["status"] = whois_data.get("status", [])

        # 6. Environment Heuristic
        # If any debug hints or dev subdomains
        passive_findings = [] # We'd need to fetch these or check the results
        # For now, look at targets
        all_targets = str(enum.get("targets", {}))
        if any(h in all_targets.lower() for h in ["dev", "staging", "test", "lab"]):
            spectre["environment"] = "Non-Production"
        elif any(h in all_targets.lower() for h in ["www", "api", "prod"]):
            spectre["environment"] = "Production"

        return spectre
