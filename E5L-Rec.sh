#!/bin/bash

# ========== CONFIGURATION ==========
# Source configuration file (config.sh)
if [ -f "config.sh" ]; then
    source config.sh
else
    echo -e "\033[1;31m[-] Configuration file (config.sh) not found. Exiting...\033[0m"
    exit 1
fi

# ========== COLORS ==========
GREEN="\033[1;32m"
RED="\033[1;31m"
NC="\033[0m"

# ========== FUNCTIONS ==========
# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install Go-based tools
install_go_tool() {
    local tool=$1
    local package=$2
    if ! command_exists "$tool"; then
        echo -e "${RED}[-] Installing $tool...${NC}"
        go install "$package" || { echo -e "${RED}[-] Failed to install $tool${NC}"; exit 1; }
        export PATH=$PATH:$(go env GOPATH)/bin
    fi
}

# Function to install tools (if not already installed)
install_tools() {
    echo -e "${GREEN}[+] Checking and installing tools...${NC}"
    tools=(subfinder assetfinder amass httpx hakrawler gau waybackurls gf github-subdomains github-endpoints)

    # Install tools if missing
    for tool in "${tools[@]}"; do
        if ! command_exists "$tool"; then
            case $tool in
                subfinder)
                    install_go_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
                    ;;
                assetfinder)
                    install_go_tool assetfinder github.com/tomnomnom/assetfinder@latest
                    ;;
                amass)
                    install_go_tool amass github.com/owasp/amass/v3/...@latest
                    ;;
                httpx)
                    install_go_tool httpx github.com/projectdiscovery/httpx/cmd/httpx@latest
                    ;;
                hakrawler)
                    install_go_tool hakrawler github.com/hakluke/hakrawler@latest
                    ;;
                gau)
                    install_go_tool gau github.com/lc/gau@latest
                    ;;
                waybackurls)
                    install_go_tool waybackurls github.com/tomnomnom/waybackurls@latest
                    ;;
                gf)
                    install_go_tool gf github.com/tomnomnom/gf@latest
                    # Optionally configure gf patterns
                    if [ ! -d ~/.gf ]; then
                        git clone https://github.com/1ndianl33t/Gf-Patterns /tmp/Gf-Patterns
                        mkdir -p ~/.gf
                        cp /tmp/Gf-Patterns/*.json ~/.gf/
                        rm -rf /tmp/Gf-Patterns
                    fi
                    ;;
                github-subdomains)
                    install_go_tool github-subdomains github.com/gwen001/github-subdomains@latest
                    ;;
                github-endpoints)
                    install_go_tool github-endpoints github.com/gwen001/github-endpoints@latest
                    ;;
            esac
        fi
    done

    # Install trufflehog (Python-based)
    if ! command_exists trufflehog; then
        echo -e "${RED}[-] Installing trufflehog...${NC}"
        pip3 install trufflehog >/dev/null 2>&1 || { echo -e "${RED}[-] Failed to install trufflehog${NC}"; exit 1; }
    fi

    # Ensure basic tools are installed
    for tool in git curl grep; do
        if ! command_exists "$tool"; then
            echo -e "${RED}[-] $tool is required. Please install it (e.g., sudo apt install $tool).${NC}"
            exit 1
        fi
    done
}

# Function to enumerate subdomains
enumerate_subdomains() {
    local domain=$1
    local output_dir=$2

    echo -e "${GREEN}[+] Enumerating subdomains for $domain...${NC}"
    subfinder -d "$domain" -silent > "$output_dir/subs_subfinder.txt" 2>/dev/null
    assetfinder --subs-only "$domain" > "$output_dir/subs_assetfinder.txt" 2>/dev/null
    amass enum -passive -d "$domain" > "$output_dir/subs_amass.txt" 2>/dev/null
    github-subdomains -d "$domain" > "$output_dir/subs_github.txt" 2>/dev/null
    cat "$output_dir/subs_"*".txt" | sort -u > "$output_dir/subs.txt"
    rm "$output_dir/subs_"*".txt"
}

# Function to check live subdomains
check_live_subdomains() {
    local subs_file=$1
    local output_dir=$2

    echo -e "${GREEN}[+] Checking live subdomains...${NC}"
    cat "$subs_file" | httpx -silent -mc 200,302,403 > "$output_dir/live.txt" 2>/dev/null
}

# Function to extract JavaScript files
extract_js_files() {
    local live_file=$1
    local output_dir=$2

    echo -e "${GREEN}[+] Extracting JS files from live hosts...${NC}"
    cat "$live_file" | hakrawler -js -depth 2 2>/dev/null | sort -u > "$output_dir/js_files.txt"
}

# Function to scan JS files for secrets
scan_js_for_secrets() {
    local js_file=$1
    local output_dir=$2

    echo -e "${GREEN}[+] Scanning JS for secrets...${NC}"
    > "$output_dir/secrets.txt"
    while read -r js; do
        echo "[JS] $js" >> "$output_dir/secrets.txt"
        curl -s "$js" | grep -Ei "api[_-]?key|secret|token|authorization|bearer|access[_-]?token" >> "$output_dir/secrets.txt" 2>/dev/null
    done < "$js_file"
}

# Function to collect historical URLs
collect_historical_urls() {
    local subs_file=$1
    local output_dir=$2

    echo -e "${GREEN}[+] Collecting URLs (gau + wayback)...${NC}"
    (cat "$subs_file" | gau && cat "$subs_file" | waybackurls) | sort -u > "$output_dir/all_urls.txt" 2>/dev/null
}

# Function to filter URLs with GF patterns
filter_with_gf() {
    local urls_file=$1
    local output_dir=$2

    echo -e "${GREEN}[+] Filtering with GF patterns...${NC}"
    mkdir -p "$output_dir/gf_matches"
    patterns=(xss sqli ssrf redirect lfi idor)
    for p in "${patterns[@]}"; do
        cat "$urls_file" | gf "$p" > "$output_dir/gf_matches/$p.txt" 2>/dev/null
    done
}

# Function to extract GitHub endpoints
extract_github_endpoints() {
    local domain=$1
    local output_dir=$2

    echo -e "${GREEN}[+] Extracting endpoints from GitHub...${NC}"
    github-endpoints -d "$domain" > "$output_dir/github_endpoints.txt" 2>/dev/null
}

# Function to scan GitHub for secrets
scan_github_for_secrets() {
    local domain=$1
    local output_dir=$2

    echo -e "${GREEN}[+] Scanning GitHub for secrets...${NC}"
    trufflehog github --repo https://github.com/search?q="$domain" --json > "$output_dir/trufflehog_output.json" 2>/dev/null || echo "TruffleHog scan failed."
}

# Function to generate a summary report
generate_report() {
    local output_dir=$1

    echo -e "${GREEN}[+] Generating summary report...${NC}"
    echo "Reconnaissance Report for $TARGET_DOMAIN" > "$output_dir/report.txt"
    echo "" >> "$output_dir/report.txt"
    echo "Subdomains found: $(wc -l < "$output_dir/subs.txt" 2>/dev/null || echo 0)" >> "$output_dir/report.txt"
    echo "Live hosts found: $(wc -l < "$output_dir/live.txt" 2>/dev/null || echo 0)" >> "$output_dir/report.txt"
    echo "JS files extracted: $(wc -l < "$output_dir/js_files.txt" 2>/dev/null || echo 0)" >> "$output_dir/report.txt"
    echo "Secrets found in JS: $(grep -c '^[JS]' "$output_dir/secrets.txt" 2>/dev/null || echo 0)" >> "$output_dir/report.txt"
    echo "Historical URLs collected: $(wc -l < "$output_dir/all_urls.txt" 2>/dev/null || echo 0)" >> "$output_dir/report.txt"
    echo "GF matches:" >> "$output_dir/report.txt"
    for file in "$output_dir/gf_matches/"*.txt; do
        if [ -f "$file" ]; then
            echo "  - $(basename "$file"): $(wc -l < "$file" 2>/dev/null || echo 0) matches" >> "$output_dir/report.txt"
        fi
    done
    echo "GitHub endpoints found: $(wc -l < "$output_dir/github_endpoints.txt" 2>/dev/null || echo 0)" >> "$output_dir/report.txt"
    echo "" >> "$output_dir/report.txt"
    echo "Check the following directories for detailed results:" >> "$output_dir/report.txt"
    echo "- subs.txt: Subdomains" >> "$output_dir/report.txt"
    echo "- live.txt: Live hosts" >> "$output_dir/report.txt"
    echo "- js_files.txt: JavaScript files" >> "$output_dir/report.txt"
    echo "- secrets.txt: Secrets in JS" >> "$output_dir/report.txt"
    echo "- all_urls.txt: Gau + wayback URLs" >> "$output_dir/report.txt"
    echo "- gf_matches/: Param fuzzing sets" >> "$output_dir/report.txt"
    echo "- github_endpoints.txt: Endpoints from GitHub" >> "$output_dir/report.txt"
    echo "- trufflehog_output.json: GitHub secrets (JSON)" >> "$output_dir/report.txt"
}

# ========== MAIN WORKFLOW ==========
# Create output directory
mkdir -p "$OUTPUT_DIR"

# Install tools (if needed)
install_tools

# Perform reconnaissance tasks
if [ "${RUN_ENUMERATE_SUBDOMAINS}" = "true" ]; then
    enumerate_subdomains "$TARGET_DOMAIN" "$OUTPUT_DIR"
fi

if [ "${RUN_CHECK_LIVE_SUBDOMAINS}" = "true" ]; then
    check_live_subdomains "$OUTPUT_DIR/subs.txt" "$OUTPUT_DIR"
fi

if [ "${RUN_EXTRACT_JS_FILES}" = "true" ]; then
    extract_js_files "$OUTPUT_DIR/live.txt" "$OUTPUT_DIR"
fi

if [ "${RUN_SCAN_JS_FOR_SECRETS}" = "true" ]; then
    scan_js_for_secrets "$OUTPUT_DIR/js_files.txt" "$OUTPUT_DIR"
fi

if [ "${RUN_COLLECT_HISTORICAL_URLS}" = "true" ]; then
    collect_historical_urls "$OUTPUT_DIR/subs.txt" "$OUTPUT_DIR"
fi

if [ "${RUN_FILTER_WITH_GF}" = "true" ]; then
    filter_with_gf "$OUTPUT_DIR/all_urls.txt" "$OUTPUT_DIR"
fi

if [ "${RUN_EXTRACT_GITHUB_ENDPOINTS}" = "true" ]; then
    extract_github_endpoints "$TARGET_DOMAIN" "$OUTPUT_DIR"
fi

if [ "${RUN_SCAN_GITHUB_FOR_SECRETS}" = "true" ]; then
    scan_github_for_secrets "$TARGET_DOMAIN" "$OUTPUT_DIR"
fi

# Generate final report
generate_report "$OUTPUT_DIR"

# ========== DONE ==========
echo -e "${GREEN}\n[✓] Recon complete!${NC}"
echo -e "${GREEN}Files saved in: $OUTPUT_DIR${NC}"
echo -e "${GREEN}Key files:${NC}"
echo "- subs.txt           → Subdomains"
echo "- live.txt           → Live hosts"
echo "- js_files.txt       → JavaScript files"
echo "- secrets.txt        → Secrets in JS"
echo "- all_urls.txt       → Gau + wayback URLs"
echo "- gf_matches/*.txt   → Param fuzzing sets"
echo "- github_endpoints.txt → Endpoints from GitHub"
echo "- trufflehog_output.json → GitHub secrets (JSON)"

exit 0
