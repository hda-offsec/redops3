import requests
import re
import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class CustomWordlistScanner:
    """
    Advanced Module: Context-Aware Wordlist Generator ("Spider & Learn")
    Spiders the target website to create a custom wordlist for fuzzing.
    """

    def __init__(self, target):
        self.target = target
        self.output_dir = "data/wordlists/custom"
        os.makedirs(self.output_dir, exist_ok=True)
        self.words = set()

    def generate(self, start_url=None, depth=2, logger=None):
        if not start_url:
            # Default to https
            start_url = f"https://{self.target}"

        filename = os.path.join(self.output_dir, f"{self.target}_cewl.txt")
        if logger: logger(f"CustomWordlist: Spidering {start_url} to generate {filename}...", "INFO")

        visited = set()
        queue = [(start_url, 0)]

        # Regex for words (min 5 chars, alphanumeric)
        word_regex = re.compile(r'\b[a-zA-Z0-9\-]{5,}\b')

        try:
            while queue:
                url, current_depth = queue.pop(0)
                if url in visited or current_depth > depth:
                    continue
                
                visited.add(url)
                
                try:
                    r = requests.get(url, timeout=5, verify=False)
                    soup = BeautifulSoup(r.text, 'html.parser')
                    
                    # 1. Extract Words
                    text = soup.get_text()
                    found = word_regex.findall(text)
                    for w in found:
                        self.words.add(w.lower())
                        
                    # 2. Extract Links for next depth
                    if current_depth < depth:
                        for a in soup.find_all('a', href=True):
                            href = a['href']
                            full_url = urljoin(url, href)
                            # Only internal links
                            if self.target in urlparse(full_url).netloc:
                                queue.append((full_url, current_depth + 1))
                                
                except Exception as e:
                    # logger(f"Spider error on {url}: {e}", "DEBUG")
                    pass

            # 3. Add Permutations (Years, Seasons, Common envs)
            extra_words = set()
            for w in self.words:
                extra_words.add(f"{w}2024")
                extra_words.add(f"{w}2025")
                extra_words.add(f"{w}-dev")
                extra_words.add(f"{w}-api")
            
            self.words.update(extra_words)

            # Save
            with open(filename, "w") as f:
                for w in sorted(self.words):
                    f.write(w + "\n")
                    
            if logger: logger(f"CustomWordlist: Generated {len(self.words)} unique words.", "SUCCESS")
            return filename

        except Exception as e:
            if logger: logger(f"CustomWordlist Generation Failed: {e}", "ERROR")
            return None
