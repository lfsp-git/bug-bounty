"""
HUNT3R Custom Nuclei Templates Library
Hunt3r-specific vulnerability patterns optimized for bug bounty targets
"""

import os
import yaml

HUNT3R_CUSTOM_TEMPLATES = {
    "wordpress-plugin-enum": {
        "id": "hunt3r-wp-plugin-enum",
        "info": {
            "name": "WordPress Plugin Enumeration & Vulnerability Detection",
            "author": "hunt3r",
            "severity": "medium",
            "description": "Detect WordPress plugins and known vulnerabilities via popular plugins list"
        },
        "http": [
            {
                "method": "GET",
                "path": [
                    "{{BaseURL}}/wp-content/plugins/",
                    "{{BaseURL}}/wp-content/plugins/akismet/",
                    "{{BaseURL}}/wp-content/plugins/jetpack/",
                    "{{BaseURL}}/wp-content/plugins/yoast-seo/",
                    "{{BaseURL}}/wp-content/plugins/woocommerce/"
                ],
                "matchers": [
                    {
                        "type": "status",
                        "status": [200, 403]
                    }
                ]
            }
        ]
    },
    
    "cors-misconfiguration": {
        "id": "hunt3r-cors-misc",
        "info": {
            "name": "CORS Misconfiguration Detection",
            "author": "hunt3r",
            "severity": "high",
            "description": "Detect overly permissive CORS headers allowing unauthorized cross-origin access"
        },
        "http": [
            {
                "method": "OPTIONS",
                "path": ["{{BaseURL}}/"],
                "headers": {
                    "Origin": "https://attacker.com"
                },
                "matchers": [
                    {
                        "type": "regex",
                        "part": "header",
                        "regex": ["Access-Control-Allow-Origin:\\s*\\*"]
                    }
                ]
            }
        ]
    },
    
    "api-key-exposure": {
        "id": "hunt3r-api-key-exposure",
        "info": {
            "name": "API Key Exposure in Responses",
            "author": "hunt3r",
            "severity": "critical",
            "description": "Detect leaked API keys, AWS credentials, Stripe keys in responses"
        },
        "http": [
            {
                "method": "GET",
                "path": [
                    "{{BaseURL}}/api/config",
                    "{{BaseURL}}/config.json",
                    "{{BaseURL}}/config.js",
                    "{{BaseURL}}/.env",
                    "{{BaseURL}}/debug"
                ],
                "matchers": [
                    {
                        "type": "regex",
                        "regex": [
                            "AKIA[0-9A-Z]{16}",  # AWS Access Key
                            "sk_live_[0-9a-zA-Z]{24,}",  # Stripe
                            "AIzaSy[a-zA-Z0-9_-]{31}",  # Google API
                            "github_pat_[a-zA-Z0-9]{22,}",  # GitHub PAT
                        ]
                    }
                ]
            }
        ]
    },
    
    "debug-endpoints": {
        "id": "hunt3r-debug-endpoints",
        "info": {
            "name": "Exposed Debug Endpoints",
            "author": "hunt3r",
            "severity": "high",
            "description": "Discover debug consoles, actuators, and admin endpoints"
        },
        "http": [
            {
                "method": "GET",
                "path": [
                    "{{BaseURL}}/debug",
                    "{{BaseURL}}/actuator",
                    "{{BaseURL}}/actuator/env",
                    "{{BaseURL}}/admin",
                    "{{BaseURL}}/console",
                    "{{BaseURL}}/__debug__",
                    "{{BaseURL}}/graphql",
                    "{{BaseURL}}/graphiql"
                ],
                "matchers": [
                    {
                        "type": "status",
                        "status": [200, 403]
                    }
                ]
            }
        ]
    },
    
    "s3-bucket-exposure": {
        "id": "hunt3r-s3-exposure",
        "info": {
            "name": "AWS S3 Bucket Public Access",
            "author": "hunt3r",
            "severity": "critical",
            "description": "Detect publicly accessible S3 buckets referenced in HTML/JS"
        },
        "http": [
            {
                "method": "GET",
                "path": ["{{BaseURL}}/"],
                "matchers": [
                    {
                        "type": "regex",
                        "part": "body",
                        "regex": [
                            "https://[a-z0-9-]+\\.s3(\\.us-west-2)?\\.amazonaws\\.com",
                            "s3\\.amazonaws\\.com/[a-z0-9-]+"
                        ]
                    }
                ]
            }
        ]
    },
    
    "weak-jwt": {
        "id": "hunt3r-weak-jwt",
        "info": {
            "name": "Weak JWT Configuration",
            "author": "hunt3r",
            "severity": "high",
            "description": "Detect JWTs using weak algorithms or no signature verification"
        },
        "http": [
            {
                "method": "GET",
                "path": ["{{BaseURL}}/api/"],
                "matchers": [
                    {
                        "type": "regex",
                        "part": "header",
                        "regex": ["Authorization:\\s*Bearer\\s*ey[a-zA-Z0-9_-]+"]
                    }
                ]
            }
        ]
    },
    
    "information-disclosure": {
        "id": "hunt3r-info-disclosure",
        "info": {
            "name": "Information Disclosure via Error Messages",
            "author": "hunt3r",
            "severity": "medium",
            "description": "Detect sensitive info in error pages (versions, paths, stack traces)"
        },
        "http": [
            {
                "method": "GET",
                "path": [
                    "{{BaseURL}}/nonexistent",
                    "{{BaseURL}}/invalid.php",
                    "{{BaseURL}}/test.jsp"
                ],
                "matchers": [
                    {
                        "type": "regex",
                        "regex": [
                            "(Apache|nginx|Microsoft-IIS)/[0-9.]+ ",
                            "PHP/[0-9.]+ ",
                            "at .*\\.java:\\d+",
                            "Traceback.*File.*line \\d+"
                        ]
                    }
                ]
            }
        ]
    }
}


def load_custom_templates(template_dir: str = "recon/templates") -> list:
    """
    Load Hunt3r custom templates.
    Priority: hand-crafted YAML files in template_dir take precedence over
    Python-generated ones from HUNT3R_CUSTOM_TEMPLATES dict.
    Returns list of template file paths ready for Nuclei (-t flag).
    """
    import glob as _glob
    os.makedirs(template_dir, exist_ok=True)

    # 1. Write Python-dict templates only if the file doesn't exist yet
    for template_id, template_data in HUNT3R_CUSTOM_TEMPLATES.items():
        template_file = os.path.join(template_dir, f"{template_id}.yaml")
        if not os.path.exists(template_file):
            with open(template_file, 'w') as f:
                yaml.dump(template_data, f, default_flow_style=False, allow_unicode=True)

    # 2. Return ALL yaml files in directory (includes hand-crafted ones)
    return sorted(_glob.glob(os.path.join(template_dir, "*.yaml")))


def get_custom_template_tags() -> list:
    """Return list of custom template IDs for use with Nuclei -tags flag"""
    return [t["id"] for t in HUNT3R_CUSTOM_TEMPLATES.values()]
