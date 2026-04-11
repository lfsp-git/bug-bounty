"""
Tech Stack Detector for Smart Nuclei Tag Selection

Detects web technologies (servers, frameworks, CMSes) from:
1. HTTP headers (Server, X-Powered-By, etc)
2. HTML fingerprints (meta, comments, specific tech indicators)
3. Katana crawl output (endpoint patterns, framework signatures)

Maps detected tech → Nuclei tag priorities for accurate vulnerability scanning.
"""

import re
from typing import Dict, Set, List, Tuple
from enum import Enum

class TechCategory(Enum):
    """Technology categories for vulnerability prioritization"""
    WEB_SERVER = "web_server"        # Apache, Nginx, IIS, etc
    LANGUAGE = "language"             # PHP, Java, Python, ASP.NET, etc
    FRAMEWORK = "framework"            # Django, Spring, Rails, Laravel, etc
    CMS = "cms"                        # WordPress, Drupal, Joomla, etc
    DATABASE = "database"              # MySQL, MSSQL, PostgreSQL, MongoDB, etc
    API = "api"                        # REST, GraphQL, SOAP, etc
    AUTH = "auth"                      # OAuth, JWT, Session-based, etc
    CACHING = "caching"                # Redis, Memcached, etc

class TechDetector:
    """Detects web technologies and returns prioritized Nuclei tags"""

    # Web Server fingerprints
    WEB_SERVERS = {
        'apache': {
            'patterns': [r'Apache/[\d.]+', r'Apache'],
            'tags': ['apache', 'cve', 'misconfig', 'info-disclosure'],
            'priority': 1,
        },
        'nginx': {
            'patterns': [r'nginx/[\d.]+', r'nginx'],
            'tags': ['nginx', 'cve', 'misconfig', 'path-traversal'],
            'priority': 1,
        },
        'iis': {
            'patterns': [r'Microsoft-IIS/[\d.]+', r'IIS/[\d.]+', r'Microsoft-IIS'],
            'tags': ['iis', 'asp', 'aspx', 'webdav', 'cve', 'misconfig'],
            'priority': 1,
        },
        'lighttpd': {
            'patterns': [r'lighttpd/[\d.]+', r'lighttpd'],
            'tags': ['cve', 'misconfig'],
            'priority': 2,
        },
        'caddy': {
            'patterns': [r'Caddy', r'caddy'],
            'tags': ['cve', 'misconfig'],
            'priority': 2,
        },
    }

    # Language/Framework fingerprints
    FRAMEWORKS = {
        'wordpress': {
            'patterns': [r'wp-content', r'wp-includes', r'wordpress', r'/wp-admin', r'wp-json'],
            'tags': ['wordpress', 'cve', 'plugin', 'theme', 'misconfig', 'wpscan'],
            'priority': 1,
        },
        'drupal': {
            'patterns': [r'/sites/default', r'/modules/', r'/themes/', r'Drupal'],
            'tags': ['drupal', 'cve', 'misconfig', 'module'],
            'priority': 1,
        },
        'joomla': {
            'patterns': [r'/components/', r'/modules/', r'Joomla', r'joomla'],
            'tags': ['joomla', 'cve', 'misconfig', 'component'],
            'priority': 1,
        },
        'php': {
            'patterns': [r'PHP/[\d.]+', r'\.php', r'X-Powered-By.*PHP'],
            'tags': ['php', 'sqli', 'rfi', 'lfi', 'xss', 'cve'],
            'priority': 1,
        },
        'laravel': {
            'patterns': [r'laravel', r'Laravel', r'X-Powered-By.*Laravel', r'/nova/', r'artisan'],
            'tags': ['laravel', 'cve', 'misconfig', 'sqli', 'auth-bypass'],
            'priority': 2,
        },
        'django': {
            'patterns': [r'django', r'Django', r'X-Powered-By.*Django', r'/admin/', r'/static/'],
            'tags': ['django', 'cve', 'misconfig', 'sqli', 'ssti'],
            'priority': 2,
        },
        'rails': {
            'patterns': [r'Rails', r'rails', r'X-Powered-By.*Rails'],
            'tags': ['rails', 'cve', 'misconfig', 'sqli', 'rce'],
            'priority': 2,
        },
        'spring': {
            'patterns': [r'Spring', r'X-Powered-By.*Spring', r'/actuator', r'servlet'],
            'tags': ['spring', 'java', 'cve', 'sqli', 'rce', 'actuator'],
            'priority': 1,
        },
        'aspnet': {
            'patterns': [r'ASP\.NET', r'ASP.Net', r'\.aspx', r'X-AspNet-Version', r'X-Powered-By.*ASP'],
            'tags': ['asp', 'aspx', 'cve', 'misconfig', 'sqli', 'path-traversal'],
            'priority': 1,
        },
        'node': {
            'patterns': [r'Node\.js', r'node\.js', r'X-Powered-By.*Express'],
            'tags': ['nodejs', 'javascript', 'cve', 'sqli', 'rce', 'xxe'],
            'priority': 2,
        },
    }

    # Database fingerprints
    DATABASES = {
        'mysql': {
            'patterns': [r'mysql', r'MySQL', r'mariadb'],
            'tags': ['sqli', 'mysql'],
            'priority': 2,
        },
        'mssql': {
            'patterns': [r'mssql', r'MSSQL', r'SQL Server'],
            'tags': ['sqli', 'mssql', 'xp_cmdshell'],
            'priority': 1,
        },
        'postgresql': {
            'patterns': [r'postgres', r'PostgreSQL'],
            'tags': ['sqli', 'postgres'],
            'priority': 2,
        },
        'mongodb': {
            'patterns': [r'mongodb', r'MongoDB', r'\.json'],
            'tags': ['nosqli', 'mongodb', 'injection'],
            'priority': 2,
        },
    }

    # Auth mechanism fingerprints
    AUTH_MECHANISMS = {
        'jwt': {
            'patterns': [r'jwt', r'JWT', r'Authorization.*Bearer', r'\.jwt'],
            'tags': ['jwt', 'auth-bypass', 'token-crack'],
            'priority': 2,
        },
        'oauth': {
            'patterns': [r'oauth', r'OAuth', r'/oauth/', r'client_id'],
            'tags': ['oauth', 'auth-bypass', 'token-leak'],
            'priority': 2,
        },
        'jwt-secret': {
            'patterns': [r'jwt_secret', r'secret_key', r'APP_KEY'],
            'tags': ['secret-leak', 'jwt', 'hardcoded-secrets'],
            'priority': 1,
        },
    }

    # API fingerprints
    APIS = {
        'graphql': {
            'patterns': [r'/graphql', r'GraphQL', r'__typename', r'query.*{'],
            'tags': ['graphql', 'info-disclosure', 'introspection'],
            'priority': 2,
        },
        'rest': {
            'patterns': [r'/api/', r'/v1/', r'/v2/', r'Content-Type.*json'],
            'tags': ['sqli', 'xss', 'xxe', 'info-disclosure'],
            'priority': 2,
        },
        'soap': {
            'patterns': [r'/soap', r'SOAP', r'\.wsdl', r'xmlns.*soap'],
            'tags': ['soap', 'xxe', 'misconfig'],
            'priority': 2,
        },
    }

    @classmethod
    def detect_from_headers(cls, headers: Dict[str, str]) -> Set[str]:
        """Extract tech from HTTP headers"""
        tech_found = set()
        headers_str = str(headers).lower()
        
        for tech_name, tech_info in {**cls.WEB_SERVERS, **cls.FRAMEWORKS}.items():
            for pattern in tech_info['patterns']:
                if re.search(pattern, headers_str, re.IGNORECASE):
                    tech_found.add(tech_name)
                    break
        
        return tech_found

    @classmethod
    def detect_from_html(cls, html_content: str) -> Set[str]:
        """Extract tech from HTML content (meta tags, comments, etc)"""
        tech_found = set()
        html_lower = html_content.lower()
        
        all_tech = {**cls.WEB_SERVERS, **cls.FRAMEWORKS, **cls.DATABASES, **cls.APIS}
        
        for tech_name, tech_info in all_tech.items():
            for pattern in tech_info['patterns']:
                if re.search(pattern, html_lower):
                    tech_found.add(tech_name)
                    break
        
        return tech_found

    @classmethod
    def detect_from_urls(cls, urls: List[str]) -> Set[str]:
        """Extract tech from URL patterns"""
        tech_found = set()
        urls_str = '\n'.join(urls).lower()
        
        all_tech = {**cls.WEB_SERVERS, **cls.FRAMEWORKS, **cls.DATABASES, **cls.APIS, **cls.AUTH_MECHANISMS}
        
        for tech_name, tech_info in all_tech.items():
            for pattern in tech_info['patterns']:
                if re.search(pattern, urls_str):
                    tech_found.add(tech_name)
                    break
        
        return tech_found

    @classmethod
    def get_nuclei_tags(cls, tech_stack: Set[str]) -> Tuple[str, List[str]]:
        """
        Convert detected tech stack to Nuclei tags with priority ordering.
        
        Returns: (tag_string, tag_list)
        
        Priority order:
        1. Server-specific (Apache, IIS, Nginx)
        2. Language/Framework (PHP, Java, Python)
        3. CMS-specific (WordPress, Drupal)
        4. Generic (SQLi, XSS, info-disclosure)
        """
        # Known-valid Nuclei community template tags. Tags outside this set are
        # silently ignored by Nuclei, causing 0-template scans with no warning.
        VALID_NUCLEI_TAGS = {
            # Severity/category
            'cve', 'misconfig', 'takeover', 'exposure', 'xss', 'sqli', 'rce', 'lfi', 'rfi',
            'ssrf', 'xxe', 'idor', 'redirect', 'oast', 'file-upload', 'default-credentials',
            'auth-bypass', 'cors', 'ssti', 'log4j', 'panel', 'login', 'api', 'fuzz',
            'info-disclosure', 'token-leak', 'jwt', 'oauth', 'actuator', 'webdav',
            'path-traversal', 'open-redirect', 'nosql', 'injection', 'hardcoded',
            'secret-exposure', 'wp-plugin', 'wp-theme',
            # Tech tags
            'wordpress', 'apache', 'nginx', 'php', 'java', 'spring', 'tomcat', 'drupal',
            'joomla', 'laravel', 'django', 'rails', 'graphql', 'iis', 'asp', 'aspx',
            'mysql', 'mssql', 'postgres', 'mongodb', 'nodejs', 'javascript',
        }

        # Map invalid/legacy tags used internally → valid Nuclei equivalents
        TAG_ALIASES = {
            'hardcoded-secrets': 'hardcoded',
            'secret-leak': 'secret-exposure',
            'token-crack': 'token-leak',
            'nosqli': 'nosql',
            'introspection': 'graphql',
            'wpscan': 'wordpress',
            'module': 'misconfig',
            'component': 'misconfig',
            'xp_cmdshell': 'sqli',
            'auth_bypass': 'auth-bypass',
        }

        all_tech = {**cls.WEB_SERVERS, **cls.FRAMEWORKS, **cls.DATABASES, **cls.APIS, **cls.AUTH_MECHANISMS}
        
        tags_by_priority = {}
        
        for tech in tech_stack:
            if tech in all_tech:
                tech_info = all_tech[tech]
                priority = tech_info.get('priority', 3)
                tags = tech_info.get('tags', [])
                
                if priority not in tags_by_priority:
                    tags_by_priority[priority] = []
                tags_by_priority[priority].extend(tags)
        
        # Build ordered tag list: Tier 1 → Tier 2 → Tier 3
        final_tags = []
        for priority in sorted(tags_by_priority.keys()):
            final_tags.extend(tags_by_priority[priority])
        
        # Add generic vulns if not present
        if 'cve' not in final_tags:
            final_tags.insert(0, 'cve')
        if 'misconfig' not in final_tags:
            final_tags.append('misconfig')
        
        # Remove duplicates, preserve order
        final_tags = list(dict.fromkeys(final_tags))

        # Resolve aliases and filter to known-valid tags only
        validated = []
        for tag in final_tags:
            resolved = TAG_ALIASES.get(tag, tag)
            if resolved in VALID_NUCLEI_TAGS:
                validated.append(resolved)
        final_tags = list(dict.fromkeys(validated)) or ['cve', 'misconfig', 'takeover']
        
        # Limit to reasonable number (Nuclei can handle 20-30 tags)
        final_tags = final_tags[:25]
        
        tag_string = ','.join(final_tags)
        
        return tag_string, final_tags

    @classmethod
    def get_tech_summary(cls, tech_stack: Set[str]) -> str:
        """Human-readable tech stack summary"""
        if not tech_stack:
            return "Unknown/Generic"
        
        return ' + '.join(sorted(tech_stack))


# Example usage
if __name__ == "__main__":
    # Test with sample data
    sample_headers = {
        'Server': 'Apache/2.4.41',
        'X-Powered-By': 'PHP/7.4.3',
    }
    
    sample_html = """
    <meta name="generator" content="WordPress 5.8">
    <link rel="stylesheet" href="/wp-content/themes/twentytwentyone/style.css">
    """
    
    sample_urls = [
        "https://example.com/wp-admin",
        "https://example.com/api/v1/users",
        "https://example.com/actuator/health",
    ]
    
    tech_from_headers = TechDetector.detect_from_headers(sample_headers)
    tech_from_html = TechDetector.detect_from_html(sample_html)
    tech_from_urls = TechDetector.detect_from_urls(sample_urls)
    
    all_tech = tech_from_headers | tech_from_html | tech_from_urls
    
    print(f"Detected tech: {all_tech}")
    tag_string, tag_list = TechDetector.get_nuclei_tags(all_tech)
    print(f"Nuclei tags: {tag_string}")
    print(f"Summary: {TechDetector.get_tech_summary(all_tech)}")
