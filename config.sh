# Configuration file for recon.sh

# Target domain for reconnaissance
TARGET_DOMAIN="example.com"

# Output directory (automatically includes date)
OUTPUT_DIR="recon_$(date +%Y%m%d)"

# Task flags (set to true to run, false to skip)
RUN_ENUMERATE_SUBDOMAINS=true
RUN_CHECK_LIVE_SUBDOMAINS=true
RUN_EXTRACT_JS_FILES=true
RUN_SCAN_JS_FOR_SECRETS=true
RUN_COLLECT_HISTORICAL_URLS=true
RUN_FILTER_WITH_GF=true
RUN_EXTRACT_GITHUB_ENDPOINTS=true
RUN_SCAN_GITHUB_FOR_SECRETS=true
RUN_VULNERABILITY_SCAN=false
