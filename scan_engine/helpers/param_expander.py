import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class ParamExpander:
    """
    Expands the attack surface by guessing potential parameters 
    commonly used in LFI, RCE, and SSRF attacks.
    """
    
    COMMON_LFI_PARAMS = [
        "file", "filename", "path", "document", "folder", "root", 
        "pg", "page", "template", "style", "view", "include", "inc", 
        "layout", "mod", "conf", "config", "src", "source", "url",
        "uri", "dest", "destination", "site", "html", "data", "id",
        "action", "name", "dir", "path_info", "redirect", "to", "goto"
    ]
    
    COMMON_RCE_PARAMS = [
        "cmd", "exec", "command", "execute", "ping", "query", "jump", 
        "code", "reg", "do", "func", "arg", "option", "load", "process"
    ]
    
    COMMON_SSRF_PARAMS = [
        "url", "uri", "link", "src", "source", "target", "u", 
        "dest", "destination", "proxy", "request", "site", "html"
    ]

    @staticmethod
    def expand(url, attack_type="generic"):
        """
        Returns a list of URLs with injected parameters based on the attack type.
        Always keeps the original URL parameters if they exist.
        """
        expanded_urls = []
        parsed = urlparse(url)
        current_params = parse_qs(parsed.query)
        
        target_params = []
        if attack_type == "lfi":
            target_params = ParamExpander.COMMON_LFI_PARAMS
        elif attack_type == "rce":
            target_params = ParamExpander.COMMON_RCE_PARAMS
        elif attack_type == "ssrf":
            target_params = ParamExpander.COMMON_SSRF_PARAMS
        else:
            target_params = list(set(ParamExpander.COMMON_LFI_PARAMS + ParamExpander.COMMON_RCE_PARAMS))

        # 1. If URL has no params, populate it with common params
        if not current_params:
            for param in target_params:
                # Create a URL with this single param
                new_query = urlencode({param: "FUZZ"})
                new_url = urlunparse(parsed._replace(query=new_query))
                expanded_urls.append(new_url)
        
        # 2. If URL has params, also add a strategy where we append a common param
        # (Some WAFs/Apps ignore unknown params, but some might process them)
        if current_params:
            for param in target_params:
                if param not in current_params:
                    qs = current_params.copy()
                    qs[param] = "FUZZ"
                    new_query = urlencode(qs, doseq=True)
                    new_url = urlunparse(parsed._replace(query=new_query))
                    expanded_urls.append(new_url)

        return expanded_urls

    @staticmethod
    def get_injection_points(url):
        """
        Returns a list of (url, param_name) tuples for existing parameters.
        """
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        points = []
        for param in qs:
            points.append((url, param))
        return points
