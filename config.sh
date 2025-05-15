# Configuration file for recon.sh

# Target domain for reconnaissance
TARGET_DOMAIN="crypto.com"

# Output directory (automatically includes date)
OUTPUT_DIR="recon_$(date +%Y%m%d)"

# Enable verbose output (true/false)
VERBOSE=true

# Enable amass for subdomain enumeration (slow, set to false for speed)
RUN_AMASS=false

# Enable github-subdomains (requires GITHUB_TOKEN)
RUN_GITHUB_SUBDOMAINS=true

# Task flags (set to true to run, false to skip)
RUN_ENUMERATE_SUBDOMAINS=true
RUN_RESOLVE_DNS=true
RUN_CHECK_LIVE_SUBDOMAINS=true
RUN_CHECK_SECURITY_HEADERS=true
RUN_SCAN_PORTS=true
RUN_EXTRACT_JS_FILES=true
RUN_SCAN_JS_FOR_SECRETS=true
RUN_ENUMERATE_DIRECTORIES=true
RUN_COLLECT_HISTORICAL_URLS=true
RUN_FILTER_WITH_GF=true
RUN_EXTRACT_GITHUB_ENDPOINTS=true
RUN_SCAN_GITHUB_FOR_SECRETS=true
