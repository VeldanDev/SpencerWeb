"""
Spencer v2.0 — Web Spider / Deep Crawler
Melakukan crawling mendalam ke seluruh website:
- Follow semua link internal
- Kumpulkan semua form (action, method, inputs)
- Kumpulkan semua URL parameter
- Stay within target domain (tidak crawl ke external sites)

Semua kode original. Menggunakan BFS (Breadth-First Search) dengan
depth limit dan max pages untuk mencegah crawler berjalan tak terhingga.
"""

import requests
from urllib.parse import urlparse, urljoin, parse_qs
from collections import deque
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor


HEADERS = {"User-Agent": "Spencer/2.0 (Security Audit Spider)"}


class WebSpider:
    """
    Deep web crawler dengan kontrol depth dan rate limiting.
    
    Args:
        base_url: URL awal untuk crawling
        max_depth: Maksimum kedalaman crawl (default 2)
        max_pages: Maksimum jumlah halaman yang di-crawl (default 50)
        timeout: Timeout per request
    """
    
    def __init__(self, base_url: str, max_depth: int = 2, max_pages: int = 50, timeout: int = 10):
        if not base_url.startswith(("http://", "https://")):
            base_url = "https://" + base_url
        
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        
        # State
        self.visited = set()
        self.forms = []  # List of {action, method, inputs, source_url}
        self.urls_with_params = []  # List of {url, params, source_url}
        self.all_urls = []  # All discovered URLs
        self.failed_urls = []
        
    def crawl(self, progress_callback=None) -> dict:
        """
        Mulai crawling dari base_url.
        
        Returns:
            dict dengan statistik crawl dan data yang ditemukan
        """
        # Queue: (url, depth)
        queue = deque([(self.base_url, 0)])
        self.visited.add(self._normalize_url(self.base_url))
        
        while queue and len(self.visited) < self.max_pages:
            current_url, depth = queue.popleft()
            
            if depth > self.max_depth:
                continue
            
            if progress_callback:
                progress_callback(len(self.visited), current_url)
            
            # Fetch halaman
            try:
                resp = requests.get(
                    current_url, 
                    timeout=self.timeout, 
                    headers=HEADERS, 
                    allow_redirects=True,
                    verify=False  # Untuk handle self-signed certs
                )
                
                content_type = resp.headers.get("Content-Type", "")
                if "text/html" not in content_type.lower():
                    continue
                    
                soup = BeautifulSoup(resp.text, "html.parser")
                self.all_urls.append(current_url)
                
            except Exception as e:
                self.failed_urls.append({"url": current_url, "error": str(e)})
                continue
            
            # Extract forms dari halaman ini
            self._extract_forms(current_url, soup)
            
            # Extract links dengan parameters
            self._extract_params(current_url, soup)
            
            # Discover new links untuk di-crawl
            if depth < self.max_depth:
                new_links = self._extract_internal_links(current_url, soup)
                for link in new_links:
                    normalized = self._normalize_url(link)
                    if normalized not in self.visited and len(self.visited) < self.max_pages:
                        self.visited.add(normalized)
                        queue.append((link, depth + 1))
        
        return {
            "base_url": self.base_url,
            "pages_crawled": len(self.all_urls),
            "pages_failed": len(self.failed_urls),
            "forms_found": len(self.forms),
            "urls_with_params": len(self.urls_with_params),
            "all_urls": self.all_urls,
            "forms": self.forms,
            "param_links": self.urls_with_params,
            "failed_urls": self.failed_urls,
        }
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL untuk de-duplication."""
        parsed = urlparse(url)
        # Hapus fragment, normalize trailing slash
        path = parsed.path.rstrip("/") or "/"
        return f"{parsed.scheme}://{parsed.netloc}{path}?{parsed.query}"
    
    def _is_same_domain(self, url: str) -> bool:
        """Cek apakah URL masih di domain yang sama."""
        try:
            return urlparse(url).netloc == self.base_domain or urlparse(url).netloc == ""
        except Exception:
            return False
    
    def _extract_internal_links(self, source_url: str, soup: BeautifulSoup) -> list:
        """Ekstrak semua link internal dari halaman."""
        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            
            # Skip non-HTTP links
            if href.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
                continue
            
            full_url = urljoin(source_url, href)
            
            # Hanya internal links
            if self._is_same_domain(full_url):
                # Skip file extensions yang tidak perlu di-crawl
                skip_ext = (".pdf", ".jpg", ".jpeg", ".png", ".gif", ".css", ".js",
                          ".zip", ".tar", ".gz", ".mp4", ".mp3", ".doc", ".docx",
                          ".xls", ".xlsx", ".ppt", ".pptx", ".svg", ".ico", ".woff", ".woff2")
                if not full_url.lower().split("?")[0].endswith(skip_ext):
                    links.append(full_url)
        
        return links
    
    def _extract_forms(self, source_url: str, soup: BeautifulSoup):
        """Ekstrak semua form dari halaman."""
        for form in soup.find_all("form"):
            action = form.get("action", "")
            action = urljoin(source_url, action) if action else source_url
            method = form.get("method", "GET").upper()
            
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                inputs.append({
                    "name": name,
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", "")
                })
            
            if inputs:
                # De-dup: jangan tambah form yang persis sama
                form_signature = f"{method}|{action}|{'|'.join(sorted(i['name'] for i in inputs))}"
                if not any(self._form_signature(f) == form_signature for f in self.forms):
                    self.forms.append({
                        "action": action,
                        "method": method,
                        "inputs": inputs,
                        "source_url": source_url
                    })
    
    def _form_signature(self, form: dict) -> str:
        return f"{form['method']}|{form['action']}|{'|'.join(sorted(i['name'] for i in form['inputs']))}"
    
    def _extract_params(self, source_url: str, soup: BeautifulSoup):
        """Ekstrak link yang punya URL parameters."""
        seen_param_keys = {(p["url"], frozenset(p["params"].keys())) for p in self.urls_with_params}
        
        for a in soup.find_all("a", href=True):
            href = urljoin(source_url, a["href"])
            parsed = urlparse(href)
            
            if parsed.netloc != self.base_domain or not parsed.query:
                continue
            
            params = parse_qs(parsed.query, keep_blank_values=True)
            flat_params = {k: v[0] if v else "" for k, v in params.items()}
            
            url_clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            key = (url_clean, frozenset(flat_params.keys()))
            
            if key not in seen_param_keys:
                seen_param_keys.add(key)
                self.urls_with_params.append({
                    "url": url_clean,
                    "params": flat_params,
                    "source_url": source_url
                })


def deep_crawl(url: str, max_depth: int = 2, max_pages: int = 50, timeout: int = 10) -> dict:
    """Helper function untuk crawling."""
    spider = WebSpider(url, max_depth=max_depth, max_pages=max_pages, timeout=timeout)
    return spider.crawl()
