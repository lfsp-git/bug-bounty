"""
Hunt3r-v1: Centralized Configuration Constants
Extracted magic numbers for maintainability and security.
"""

# ============================================================================
# SCORING & INTELLIGENCE CONSTANTS
# ============================================================================
CRITICAL_SCORE_THRESHOLD = 70
STANDARD_SCORE_THRESHOLD = 50
MIN_SUBDOMAINS_FOR_CRITICAL = 50
SCORE_PENALTY_SECURITY_PLATFORM = 30
SCORE_PENALTY_WEAK_VPS = 20

# Target scoring keywords and their weights
PREMIUM_KEYWORDS = ['fintech', 'crypto', 'bank', 'payment', 'financial']
STANDARD_KEYWORDS = ['tech', 'cloud', 'social', 'media', 'platform']
LOW_KEYWORDS = ['cms', 'devops', 'framework']

# ============================================================================
# WATCHDOG CONSTANTS
# ============================================================================
WATCHDOG_SLEEP_MIN_SECONDS = 14400  # 4 hours
WATCHDOG_SLEEP_MAX_SECONDS = 21600  # 6 hours
WATCHDOG_MAX_TARGETS_PER_CYCLE = 50
WATCHDOG_CACHE_DURATION_SECONDS = 43200  # 12 hours
WATCHDOG_HOT_PROGRAMS_COUNT = 15  # Top N programs for VIP queue

# ============================================================================
# SCANNING CONSTANTS
# ============================================================================
MAX_URLS_FOR_NUCLEI = 2000  # Hard cap before removing CVEs/misconfig
URL_RATE_LIMIT_PER_SECOND = 100  # HTTPX rate limiting
NUCLEI_CONCURRENCY = 50
NUCLEI_RATE_LIMIT = 150
NUCLEI_BATCH_SIZE = 50

# Nuclei tag defaults
DEFAULT_NUCLEI_TAGS = ['exposure', 'takeover']
NUCLEI_PHASE1_TAGS_TECH = ['server', 'app', 'exposure', 'takeover', 'misconfig']
NUCLEI_PHASE2_TAGS_INJECTION = ['xss', 'sqli', 'ssrf', 'lfi', 'dast', 'exposure', 'takeover']

# ============================================================================
# TIME CONSTANTS
# ============================================================================
CACHE_TTL_RECON_SECONDS = 1800  # Subdomain/DNS data cache
CACHE_TTL_API_SECONDS = 3600    # HackerOne program data cache
CACHE_BUSTER_THRESHOLD = 50     # Force re-scan if subdomains < this

# ============================================================================
# CONCURRENCY & THREADING
# ============================================================================
MAX_WORKERS_THREADPOOL = 5  # For concurrent API calls
DEFAULT_TIMEOUT_HTTP = 15   # HTTP request timeout
DEFAULT_TIMEOUT_LONG = 60   # Long-running operations

# ============================================================================
# PATH & DIRECTORY CONSTANTS
# ============================================================================
RECON_DB_DIR = "recon/db"
BASELINES_DIR = "recon/baselines"
CACHE_DIR = "recon/cache"
CUSTOM_TEMPLATES_DIR = "recon/custom_templates"
LOGS_DIR = "logs"
CONFIG_DIR = "config"

# ============================================================================
# NUCLEI EXECUTION MODES
# ============================================================================
NUCLEI_CMD_TIMEOUT = 3600  # 1 hour for full nuclei scan
NUCLEI_STEALTH_MODE = True  # Use conservative limits on VPS
NUCLEI_NO_HEADLESS = True   # Don't use headless browser on VPS

# ============================================================================
# GIT REPOSITORY CONSTANTS
# ============================================================================
ALLOWED_GIT_PROVIDERS = [
    'https://github.com/',
    'https://gitlab.com/',
    'https://bitbucket.org/',
]
NUCLEI_TEMPLATES_REPO = 'https://github.com/projectdiscovery/nuclei-templates'

# ============================================================================
# AI/ANALYSIS CONSTANTS
# ============================================================================
AI_MAX_TOKENS_ANALYSIS = 500
AI_MAX_TOKENS_POC = 1000
AI_REQUEST_TIMEOUT = 60
PAYLOADS_CONTEXT_LIMIT = 2000  # Max characters of evidence to send to AI

# ============================================================================
# NOTIFICATION CONSTANTS
# ============================================================================
NOTIFY_CRITICAL_SEVERITY = ['critical', 'high']
NOTIFY_JS_SECRETS = True  # Always notify on JS secret findings
DISCORD_BATCH_SIZE = 5    # Group notifications before sending to Discord

# ============================================================================
# FILE SIZE LIMITS
# ============================================================================
MAX_FILE_SIZE_FOR_PARSING = 3000000  # 3MB for large file detection
MIN_EVIDENCE_LENGTH = 6  # Minimum characters for evidence (Micro category)

# ============================================================================
# UPDATE & VERSION
# ============================================================================
AUTO_UPDATE_ON_START = True
MAX_UPDATE_TIME_SECONDS = 120
UPDATE_CHECK_INTERVAL_HOURS = 24
