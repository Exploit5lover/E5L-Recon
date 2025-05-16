#!/bin/bash

# ========== WARNING ==========
echo -e "\033[1;33m[!] Ensure you have permission to scan the target domain. Unauthorized scanning is illegal.\033[0m"

# ========== CONFIGURATION ==========
if [ -f "config.sh" ]; then
    source config.sh
else
    echo -e "\033[1;31m[-] config.sh not found. Exiting...\033[0m"
    exit 1
fi

# Prompt for target domain
echo -n "Enter target domain (e.g., example.com): "
read TARGET_DOMAIN
if ! echo "$TARGET_DOMAIN" | grep -qE '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'; then
    echo -e "\033[1;31m[-] Invalid domain format. Use example.com format.\033[0m"
    exit 1
fi
echo -e "\033[1;32m[+] Target domain set to: $TARGET_DOMAIN\033[0m"

# Default config values if not set
VERBOSE=${VERBOSE:-true}
RUN_AMASS=${RUN_AMASS:-false}
RUN_GITHUB_SUBDOMAINS=${RUN_GITHUB_SUBDOMAINS:-true}
RUN_CHECK_SUBDOMAIN_TAKEOVER=${RUN_CHECK_SUBDOMAIN_TAKEOVER:-true}
RUN_RESOLVE_DNS=${RUN_RESOLVE_DNS:-true}
RUN_CHECK_LIVE_SUBDOMAINS=${RUN_CHECK_LIVE_SUBDOMAINS:-true}
RUN_CHECK_SECURITY_HEADERS=${RUN_CHECK_SECURITY_HEADERS:-true}
RUN_SCAN_PORTS=${RUN_SCAN_PORTS:-true}
RUN_EXTRACT_JS_FILES=${RUN_EXTRACT_JS_FILES:-true}
RUN_SCAN_JS_FOR_SECRETS=${RUN_SCAN_JS_FOR_SECRETS:-true}
RUN_ENUMERATE_DIRECTORIES=${RUN_ENUMERATE_DIRECTORIES:-true}
RUN_COLLECT_HISTORICAL_URLS=${RUN_COLLECT_HISTORICAL_URLS:-true}
RUN_FILTER_WITH_GF=${RUN_FILTER_WITH_GF:-true}
RUN_EXTRACT_GITHUB_ENDPOINTS=${RUN_EXTRACT_GITHUB_ENDPOINTS:-true}
RUN_SCAN_GITHUB_FOR_SECRETS=${RUN_SCAN_GITHUB_FOR_SECRETS:-true}

# Output directory (with target domain)
OUTPUT_DIR="recon_${TARGET_DOMAIN}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"


# ========== COLORS ==========
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
NC="\033[0m"

# ========== FUNCTIONS ==========
log() {
    if [ "$VERBOSE" = "true" ]; then
        echo -e "$1" | tee -a "$OUTPUT_DIR/recon.log"
    else
        echo -e "$1" >> "$OUTPUT_DIR/recon.log"
    fi
}

error() {
    echo -e "${RED}[-] $1${NC}" | tee -a "$OUTPUT_DIR/errors.log"
    # exit 1 #removed exit, now it will try to go on
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

install_go_tool() {
    local tool=$1
    local package=$2
    if ! command_exists "$tool"; then
        log "${YELLOW}[-] Installing $tool...${NC}"
        go install "$package" || { error "Failed to install $tool"; return 1; }
        export PATH=$PATH:$(go env GOPATH)/bin
        log "${GREEN}[+] $tool installed${NC}"
    fi
}

install_tools() {
    log "${GREEN}[+] Checking and installing tools...${NC}"
    tools=(subfinder assetfinder httpx katana gau waybackurls gf github-subdomains github-endpoints subjack dnsx naabu dirsearch)
    if [ "$RUN_AMASS" = "true" ]; then
        tools+=(amass)
    fi

    for tool in "${tools[@]}"; do
        if ! command_exists "$tool"; then
            case $tool in
                subfinder)
                    install_go_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
                    if command_exists subfinder; then
                        mkdir -p ~/.config/subfinder
                        echo -e "resolvers:\n  - 8.8.8.8\n  - 1.1.1.1\nsources:\n  - certspotter\n  - crtsh\n  - hackertarget" > ~/.config/subfinder/config.yaml
                    fi
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
                katana)
                    install_go_tool katana github.com/projectdiscovery/katana/cmd/katana@latest
                    ;;
                gau)
                    install_go_tool gau github.com/lc/gau@latest
                    ;;
                waybackurls)
                    install_go_tool waybackurls github.com/tomnomnom/waybackurls@latest
                    ;;
                gf)
                    install_go_tool gf github.com/tomnomnom/gf@latest
                    if command_exists gf; then
                        if [ ! -d ~/.gf ]; then
                            git clone https://github.com/1ndianl33t/Gf-Patterns /tmp/Gf-Patterns
                            mkdir -p ~/.gf
                            cp /tmp/Gf-Patterns/*.json ~/.gf/
                            rm -rf /tmp/Gf-Patterns
                        fi
                    fi
                    ;;
                github-subdomains)
                    install_go_tool github-subdomains github.com/gwen001/github-subdomains@latest
                    ;;
                github-endpoints)
                    install_go_tool github-endpoints github.com/gwen001/github-endpoints@latest
                    ;;
                subjack)
                    install_go_tool subjack github.com/haccer/subjack@latest
                    if command_exists subjack; then
                        # Download latest fingerprints for subjack
                        curl -s https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -o ~/.subjack/fingerprints.json || log "${YELLOW}[-] Failed to download subjack fingerprints${NC}"
                    fi
                    ;;
                dnsx)
                    install_go_tool dnsx github.com/projectdiscovery/dnsx/cmd/dnsx@latest
                    ;;
                naabu)
                    install_go_tool naabu github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
                    ;;
                dirsearch)
                    if [ ! -d /opt/dirsearch ]; then
                        log "${YELLOW}[-] Installing dirsearch...${NC}"
                        git clone https://github.com/maurosoria/dirsearch.git /opt/dirsearch
                        pip3 install -r /opt/dirsearch/requirements.txt || { error "Failed to install dirsearch"; return 1; }
                        ln -s /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch
                        log "${GREEN}[+] dirsearch installed${NC}"
                    fi
                    ;;
            esac
        fi
    done

    if ! command_exists gh; then
        log "${YELLOW}[-] Installing GitHub CLI (gh)...${NC}"
        sudo apt update
        sudo apt install -y gh || { error "Failed to install GitHub CLI (gh)"; return 1; }
        log "${GREEN}[+] GitHub CLI (gh) installed${NC}"
    fi

    if ! command_exists trufflehog; then
        log "${YELLOW}[-] Installing trufflehog...${NC}"
        pip3 install trufflehog >/dev/null 2>&1 || { error "Failed to install trufflehog"; return 1; }
        log "${GREEN}[+] trufflehog installed${NC}"
    fi

    if ! command_exists secretfinder; then
        log "${YELLOW}[-] Installing secretfinder...${NC}"
        # Check if the directory exists
        if [ ! -d /opt/secretfinder ]; then
            git clone https://github.com/m4ll0k/SecretFinder.git /opt/secretfinder
            if [ $? -eq 0 ]; then # Check if git clone was successful
                pip3 install -r /opt/secretfinder/requirements.txt || { error "Failed to install secretfinder requirements"; return 1; }
                ln -s /opt/secretfinder/secretfinder.py /usr/local/bin/secretfinder
                log "${GREEN}[+] secretfinder installed${NC}"
            else
                error "Failed to clone secretfinder"
                return 1
            fi
        else
            log "${YELLOW}[-] /opt/secretfinder already exists.  Skipping installation...${NC}"
        fi
    fi

    for tool in git curl grep; do
        if ! command_exists "$tool"; then
            error "$tool is required. Install it (e.g., sudo apt install $tool)"
            return 1
        fi
    done
}

check_github_token() {
    if [ -z "$GITHUB_TOKEN" ] || [ "$GITHUB_TOKEN" = "your_personal_access_token" ]; then
        error "GITHUB_TOKEN is not set or invalid in config.sh. Set a valid token in config.sh (GitHub > Settings > Developer settings > Personal access tokens, enable 'repo' scope)."
        return 1
    fi
    if ! echo "$GITHUB_TOKEN" | grep -q "^github_pat_"; then
        error "Invalid GITHUB_TOKEN format in config.sh. It should start with 'github_pat_'."
        return 1
    fi
    # Test token validity and rate limit
    local response
    response=$(curl -s -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user)
    if echo "$response" | grep -q '"message": "Bad credentials"'; then
        error "GITHUB_TOKEN is invalid. Generate a new token with 'repo' scope in GitHub > Settings > Developer settings > Personal access tokens."
        return 1
    fi
    local rate_limit
    rate_limit=$(curl -s -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/rate_limit | grep '"remaining":' | head -1 | awk '{print $2}' | tr -d ',')
    if [ "$rate_limit" -eq 0 ]; then
        error "GITHUB_TOKEN rate limit exceeded. Wait for reset or use a different token."
        return 1
    fi
    log "${GREEN}[+] GITHUB_TOKEN validated. Rate limit remaining: $rate_limit requests${NC}"
}

enumerate_subdomains() {
    local domain=$1
    local output_dir=$2

    log "${GREEN}[+] Enumerating subdomains for $domain...${NC}"
    > "$output_dir/subs_subfinder.txt"
    > "$output_dir/subs_assetfinder.txt"
    > "$output_dir/subs_github.txt"
    > "$output_dir/subs_amass.txt"

    timeout 300 subfinder -d "$domain" -silent > "$output_dir/subs_subfinder.txt" 2>>"$output_dir/errors.log" &
    log "${GREEN}[+] Running subfinder...${NC}"
    timeout 300 assetfinder --subs-only "$domain" > "$output_dir/subs_assetfinder.txt" 2>>"$output_dir/errors.log" &
    log "${GREEN}[+] Running assetfinder...${NC}"

    if [ "$RUN_GITHUB_SUBDOMAINS" = "true" ]; then
        check_github_token
        timeout 300 GITHUB_TOKEN="$GITHUB_TOKEN" github-subdomains -d "$domain" > "$output_dir/subs_github.txt" 2>>"$output_dir/errors.log" &
        log "${GREEN}[+] Running github-subdomains...${NC}"
    fi

    if [ "$RUN_AMASS" = "true" ]; then
        timeout 600 amass enum -passive -d "$domain" -o "$output_dir/subs_amass_raw.txt" 2>>"$output_dir/errors.log" &
        log "${GREEN}[+] Running amass...${NC}"
    fi

    wait

    if [ "$RUN_AMASS" = "true" ] && [ -f "$output_dir/subs_amass_raw.txt" ]; then
        grep -E "^[a-zA-Z0-9.-]+\.${domain}$" "$output_dir/subs_amass_raw.txt" > "$output_dir/subs_amass.txt" 2>>"$output_dir/errors.log"
        rm -f "$output_dir/subs_amass_raw.txt"
    fi

    for file in "$output_dir/subs_subfinder.txt" "$output_dir/subs_assetfinder.txt" "$output_dir/subs_github.txt" "$output_dir/subs_amass.txt"; do
        if [ -f "$file" ] && [ -s "$file" ]; then
            count=$(wc -l < "$file")
            tool=$(basename "$file" | sed 's/subs_//;s/\.txt//')
            log "${GREEN}[+] Found $count subdomains with $tool${NC}"
        fi
    done
    if [ "$subdomains_found" -eq 0 ]; then
        log "${YELLOW}[-] No subdomains found by enumeration tools${NC}"
    fi

    log "${GREEN}[+] Combining and deduplicating subdomains...${NC}"
    cat "$output_dir/subs_"*".txt" 2>/dev/null | sort -u -S 50M > "$output_dir/subs.txt" 2>>"$output_dir/errors.log"
    rm -f "$output_dir/subs_"*".txt"
    count=$(wc -l < "$output_dir/subs.txt" 2>/dev/null || echo 0)
    log "${GREEN}[+] Total subdomains: $count${NC}"
}

check_subdomain_takeover() {
    local subs_file=$1
    local output_dir=$2

    if [ ! -f "$subs_file" ] || [ ! -s "$subs_file" ]; then
        log "${YELLOW}[-] No subdomains found for takeover check${NC}"
        return
    fi

    log "${GREEN}[+] Checking for subdomain takeovers...${NC}"
    subjack -w "$subs_file" -t 10 -timeout 30 -ssl -c fingerprints.json -o "$output_dir/takeovers.txt" -ssl -a 2>>"$output_dir/errors.log"
    count=$(grep -c "Vulnerable" "$output_dir/takeovers.txt" 2>/dev/null || echo 0)
    if [ "$count" -eq 0 ]; then
        log "${YELLOW}[-] No subdomain takeovers found${NC}"
    else
        log "${GREEN}[+] Found $count vulnerable subdomains${NC}"
    fi
    if [ -f "$output_dir/takeovers.txt" ]; then #check if file exists before changing permissions
      chmod 600 "$output_dir/takeovers.txt"
    fi
}

resolve_dns() {
    local subs_file=$1
    local output_dir=$2

    if [ ! -f "$subs_file" ] || [ ! -s "$subs_file" ]; then
        log "${YELLOW}[-] No subdomains found for DNS resolution${NC}"
        return
    fi

    log "${GREEN}[+] Resolving DNS for subdomains...${NC}"
    cat "$subs_file" | dnsx -silent -a -aaaa -resp > "$output_dir/dns.txt" 2>>"$output_dir/errors.log"
    count=$(wc -l < "$output_dir/dns.txt" 2>/dev/null || echo 0)
    log "${GREEN}[+] Found $count IPs for subdomains${NC}"
}

check_live_subdomains() {
    local subs_file=$1
    local output_dir=$2

    if [ ! -f "$subs_file" ] || [ ! -s "$subs_file" ]; then
        log "${YELLOW}[-] No subdomains found for live check${NC}"
        return
    fi

    log "${GREEN}[+] Checking live subdomains...${NC}"
   httpx -l "$subs_file" -silent -mc 200,302,403 -timeout 10 > "$output_dir/live.txt" 2>>"$output_dir/errors.log"
    count=$(wc -l < "$output_dir/live.txt" 2>/dev/null || echo 0)
    log "${GREEN}[+] Found $count live hosts${NC}"
}

check_security_headers() {
    local live_file=$1
    local output_dir=$2

    if [ ! -f "$live_file" ] || [ ! -s "$live_file" ]; then
        log "${YELLOW}[-] No live hosts found for header check${NC}"
        return
    fi

    log "${GREEN}[+] Checking security headers...${NC}"
    cat "$live_file" | httpx -silent -sc -cl -hdr 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36' > "$output_dir/headers.txt" 2>>"$output_dir/errors.log"
    count=$(wc -l < "$output_dir/headers.txt" 2>/dev/null || echo 0)
    log "${GREEN}[+] Analyzed headers for $count hosts${NC}"
}

scan_ports() {
    local live_file=$1
    local output_dir=$2

    if [ ! -f "$live_file" ] || [ ! -s "$live_file" ]; then
        log "${YELLOW}[-] No live hosts found for port scanning${NC}"
        return
    fi

    log "${GREEN}[+] Scanning ports on live hosts...${NC}"
    # Consider adding -Pn for hosts that don't respond to ping
    cat "$live_file" | naabu -silent -p 80,443,8080,21,22,23,25,3389,110,143,445,3306,5432,5900,8000,8080,8443,8888 -n -top-ports 100 > "$output_dir/ports.txt" 2>>"$output_dir/errors.log"
    count=$(wc -l < "$output_dir/ports.txt" 2>/dev/null || echo 0)
    log "${GREEN}[+] Found open ports on $count hosts${NC}"
}

extract_js_files() {
    local live_file=$1
    local output_dir=$2

    if [ ! -f "$live_file" ] || [ ! -s "$live_file" ]; then
        log "${YELLOW}[-] No live hosts found for JS extraction${NC}"
        return
    fi

    log "${GREEN}[+] Extracting JS files with katana...${NC}"
    cat "$live_file" | katana -silent -c 25 -d 5 -js-crawl -delay 100ms -f url | grep -Ei "\.js(\?|$)" > "$output_dir/js_files.txt" 2>>"$output_dir/errors.log"
    count=$(wc -l < "$output_dir/js_files.txt" 2>/dev/null || echo 0)
    log "${GREEN}[+] Found $count JS files${NC}"
    if [ "$count" -eq 0 ]; then
        log "${YELLOW}[-] No JS files found. Possible issues: anti-crawling measures, network errors, or insufficient memory. Check errors.log.  Trying without -js-crawl...${NC}"
        cat "$live_file" | katana -silent -c 25  -d 5  -delay 100ms -f url | grep -Ei "\.js(\?|$)" > "$output_dir/js_files.txt" 2>>"$output_dir/errors.log"
        count=$(wc -l < "$output_dir/js_files.txt" 2>/dev/null || echo 0)
        log "${GREEN}[+] Found $count JS files${NC}"
        if [ "$count" -eq 0 ]; then
            log "${YELLOW}[-] No JS files found after retry.  Check errors.log for katana errors.${NC}"
        fi
    fi
}

scan_js_for_secrets() {
    local js_file=$1
    local output_dir=$2

    if [ ! -f "$js_file" ] || [ ! -s "$js_file" ]; then
        log "${YELLOW}[-] No JS files found for secret scanning${NC}"
        return
    fi

    log "${GREEN}[+] Scanning JS for secrets with secretfinder...${NC}"
    > "$output_dir/secrets.txt"
    while read -r js; do
        timeout 120 secretfinder -i "$js" -o cli >> "$output_dir/secrets_tmp.txt" 2>>"$output_dir/errors.log"
    done < "$js_file"
    if [ -f "$output_dir/secrets_tmp.txt" ]; then
        cat "$output_dir/secrets_tmp.txt" | grep -v "Checking URL" | grep -E "\[.*\]" >> "$output_dir/secrets.txt"
        rm -f "$output_dir/secrets_tmp.txt"
    fi
    count=$(grep -c '^\[' "$output_dir/secrets.txt" 2>/dev/null || echo 0)
    log "${GREEN}[+] Found $count potential secrets${NC}"
    if [ -f "$output_dir/secrets.txt" ]; then #check if file exists before changing permissions
      chmod 600 "$output_dir/secrets.txt"
    fi
}

enumerate_directories() {
    local live_file=$1
    local output_dir=$2

    if [ ! -f "$live_file" ] || [ ! -s "$live_file" ]; then
        log "${YELLOW}[-] No live hosts found for directory enumeration${NC}"
        return
    fi

    log "${GREEN}[+] Enumerating directories...${NC}"
    > "$output_dir/dirs.txt"
    while read -r url; do
        timeout 180 dirsearch -u "$url" -e php,asp,aspx,js,html,txt,xml,json -t 20 --simple-report="$output_dir/dirs_tmp.txt" -x 400,403,404,405,500,503 2>>"$output_dir/errors.log"
        if [ -f "$output_dir/dirs_tmp.txt" ]; then
            cat "$output_dir/dirs_tmp.txt" >> "$output_dir/dirs.txt"
            rm -f "$output_dir/dirs_tmp.txt"
        fi
        sleep 1
    done < "$live_file"
    count=$(wc -l < "$output_dir/dirs.txt" 2>/dev/null || echo 0)
    log "${GREEN}[+] Found $count directories${NC}"
}

collect_historical_urls() {
    local subs_file=$1
    local output_dir=$2

    if [ ! -f "$subs_file" ] || [ ! -s "$subs_file" ]; then
        log "${YELLOW}[-] No subdomains found for URL collection${NC}"
        return
    fi

    log "${GREEN}[+] Collecting historical URLs...${NC}"
    (cat "$subs_file" | timeout 300 gau && cat "$subs_file" | timeout 300 waybackurls) 2>>"$output_dir/errors.log" | sort -u -S 50M > "$output_dir/all_urls.txt"
    count=$(wc -l < "$output_dir/all_urls.txt" 2>/dev/null || echo 0)
    log "${GREEN}[+] Found $count URLs${NC}"
}

filter_with_gf() {
    local urls_file=$1
    local output_dir=$2

    if [ ! -f "$urls_file" ] || [ ! -s "$urls_file" ]; then
        log "${YELLOW}[-] No URLs found for GF filtering${NC}"
        return
    fi

    log "${GREEN}[+] Filtering URLs with GF patterns...${NC}"
    mkdir -p "$output_dir/gf_matches"
    patterns=(xss sqli ssrf redirect lfi idor)
    for p in "${patterns[@]}"; do
        cat "$urls_file" | gf "$p" > "$output_dir/gf_matches/$p.txt" 2>>"$output_dir/errors.log"
        count=$(wc -l < "$output_dir/gf_matches/$p.txt" 2>/dev/null || echo 0)
        log "${GREEN}[+] Found $count $p matches${NC}"
    done
}

extract_github_endpoints() {
    local domain=$1
    local output_dir=$2

    check_github_token
    log "${GREEN}[+] Extracting GitHub endpoints...${NC}"
    timeout 300 GITHUB_TOKEN="$GITHUB_TOKEN" github-endpoints -d "$domain" > "$output_dir/github_endpoints.txt" 2>>"$output_dir/errors.log"
    count=$(wc -l < "$output_dir/github_endpoints.txt" 2>/dev/null || echo 0)
    log "${GREEN}[+] Found $count endpoints${NC}"
}

scan_github_for_secrets() {
    local domain=$1
    local output_dir=$2

    check_github_token
    log "${GREEN}[+] Scanning GitHub for secrets...${NC}"
    > "$output_dir/repos.txt"
    > "$output_dir/trufflehog_output.json"

    # Authenticate gh with GITHUB_TOKEN
    echo "$GITHUB_TOKEN" | gh auth login --with-token 2>>"$output_dir/errors.log" || {
        log "${RED}[-] Failed to authenticate GitHub CLI. Check GITHUB_TOKEN in config.sh.${NC}"
        return
    }

    # Find repositories related to the domain
   timeout 300 gh search repos "$domain" --limit 10 --json url --jq '.[].url' > "$output_dir/repos.txt" 2>>"$output_dir/errors.log"
    local repo_count
    repo_count=$(wc -l < "$output_dir/repos.txt" 2>/dev/null || echo 0)
    if [ "$repo_count" -eq 0 ]; then
        log "${YELLOW}[-] No GitHub repositories found for $domain${NC}"
        return
    fi
    log "${GREEN}[+] Found $repo_count repositories related to $domain${NC}"

    # Scan each repository with trufflehog
    local secret_count=0
    while read -r repo; do
        log "${GREEN}[+] Scanning repository $repo...${NC}"
        for attempt in {1..2}; do
            if timeout 300 GITHUB_TOKEN="$GITHUB_TOKEN" trufflehog github --repo "$repo" --json --concurrency 1 >> "$output_dir/trufflehog_output.json" 2>>"$output_dir/errors.log"; then
                break
            else
                log "${YELLOW}[-] TruffleHog scan failed for $repo (attempt $attempt). Retrying after 10 seconds...${NC}"
                sleep 10
            fi
        done
    done < "$output_dir/repos.txt"

    secret_count=$(grep -c '"DetectorName"' "$output_dir/trufflehog_output.json" 2>/dev/null || echo 0)
    log "${GREEN}[+] Found $secret_count secrets in $repo_count repositories${NC}"
    if [ "$secret_count" -eq 0 ]; then
        log "${YELLOW}[-] No secrets found in scanned repositories${NC}"
    fi
    if [ -f "$output_dir/trufflehog_output.json" ]; then #check file before changing perms
      chmod 600 "$output_dir/trufflehog_output.json"
    fi
}

generate_report() {
    local output_dir=$1

    log "${GREEN}[+] Generating summary report...${NC}"
    report="$output_dir/report.txt"
    echo "Reconnaissance Report for $TARGET_DOMAIN" > "$report"
    echo "Generated on $(date)" >> "$report"
    echo "" >> "$report"
    echo "Subdomains found: $(wc -l < "$output_dir/subs.txt" 2>/dev/null || echo 0)" >> "$report"
    echo "Subdomain takeovers found: $(grep -c "Vulnerable" "$output_dir/takeovers.txt" 2>/dev/null || echo 0)" >> "$report"
    echo "IPs resolved: $(wc -l < "$output_dir/dns.txt" 2>/dev/null || echo 0)" >> "$report"
    echo "Live hosts found: $(wc -l < "$output_dir/live.txt" 2>/dev/null || echo 0)" >> "$report"
    echo "Security headers analyzed: $(wc -l < "$output_dir/headers.txt" 2>/dev/null || echo 0)" >> "$report"
    echo "Open ports found: $(wc -l < "$output_dir/ports.txt" 2>/dev/null || echo 0)" >> "$report"
    echo "JS files extracted: $(wc -l < "$output_dir/js_files.txt" 2>/dev/null || echo 0)" >> "$report"
    echo "Secrets found in JS: $(grep -c '^\[' "$output_dir/secrets.txt" 2>/dev/null || echo 0)" >> "$report"
    echo "Directories found: $(wc -l < "$output_dir/dirs.txt" 2>/dev/null || echo 0)" >> "$report"
    echo "Historical URLs collected: $(wc -l < "$output_dir/all_urls.txt" 2>/dev/null || echo 0)" >> "$report"
    echo "GF matches:" >> "$report"
    for file in "$output_dir/gf_matches/"*.txt; do
        if [ -f "$file" ]; then
            echo "  - $(basename "$file"): $(wc -l < "$file" 2>/dev/null || echo 0) matches" >> "$report"
        fi
    done
    echo "GitHub endpoints found: $(wc -l < "$output_dir/github_endpoints.txt" 2>/dev/null || echo 0)" >> "$report"
    echo "GitHub secrets found: $(grep -c '"DetectorName"' "$output_dir/trufflehog_output.json" 2>/dev/null || echo 0)" >> "$report"
    echo "" >> "$report"
    echo "Check the following files for detailed results:" >> "$report"
    echo "- subs.txt           → Subdomains" >> "$report"
    echo "- takeovers.txt      → Subdomain takeovers" >> "$report"
    echo "- dns.txt            → DNS resolutions" >> "$report"
    echo "- live.txt           → Live hosts" >> "$report"
    echo "- headers.txt        → Security headers" >> "$report"
    echo "- ports.txt          → Open ports" >> "$report"
    echo "- js_files.txt       → JavaScript files" >> "$report"
    echo "- secrets.txt        → Secrets in JS" >> "$report"
    echo "- dirs.txt           → Directories" >> "$report"
    echo "- all_urls.txt       → Historical URLs" >> "$report"
    echo "- gf_matches/*.txt   → Param fuzzing sets" >> "$report"
    echo "- github_endpoints.txt → GitHub endpoints" >> "$report"
    echo "- trufflehog_output.json → GitHub secrets" >> "$report"
    echo "- repos.txt          → Scanned GitHub repositories" >> "$report"
    echo "- report.txt         → Summary report" >> "$report"
    echo "- recon.log          → Execution log" >> "$report"
    echo "- errors.log         → Error log" >> "$report"
    log "${GREEN}[+] Report saved to $report${NC}"
    chmod 600 "$report"
}

# ========== MAIN WORKFLOW ==========
mkdir -p "$OUTPUT_DIR"
touch "$OUTPUT_DIR/recon.log" "$OUTPUT_DIR/errors.log"
chmod 600 "$OUTPUT_DIR/recon.log" "$OUTPUT_DIR/errors.log"

install_tools

if [ "${RUN_ENUMERATE_SUBDOMAINS}" = "true" ]; then
    enumerate_subdomains "$TARGET_DOMAIN" "$OUTPUT_DIR"
fi

if [ "${RUN_CHECK_SUBDOMAIN_TAKEOVER}" = "true" ]; then
    check_subdomain_takeover "$OUTPUT_DIR/subs.txt" "$OUTPUT_DIR"
fi

if [ "${RUN_RESOLVE_DNS}" = "true" ]; then
    resolve_dns "$OUTPUT_DIR/subs.txt" "$OUTPUT_DIR"
fi

if [ "${RUN_CHECK_LIVE_SUBDOMAINS}" = "true" ]; then
    check_live_subdomains "$OUTPUT_DIR/subs.txt" "$OUTPUT_DIR"
fi

if [ "${RUN_CHECK_SECURITY_HEADERS}" = "true" ]; then
    check_security_headers "$OUTPUT_DIR/live.txt" "$OUTPUT_DIR"
fi

if [ "${RUN_SCAN_PORTS}" = "true" ]; then
    scan_ports "$OUTPUT_DIR/live.txt" "$OUTPUT_DIR"
fi

if [ "${RUN_EXTRACT_JS_FILES}" = "true" ]; then
    extract_js_files "$OUTPUT_DIR/live.txt" "$OUTPUT_DIR"
fi

if [ "${RUN_SCAN_JS_FOR_SECRETS}" = "true" ]; then
    scan_js_for_secrets "$OUTPUT_DIR/js_files.txt" "$OUTPUT_DIR"
fi

if [ "${RUN_ENUMERATE_DIRECTORIES}" = "true" ]; then
    enumerate_directories "$OUTPUT_DIR/live.txt" "$OUTPUT_DIR"
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

generate_report "$OUTPUT_DIR"

# ========== DONE ==========
log "${GREEN}\n[✓] Recon complete!${NC}"
log "${GREEN}Files saved in: $OUTPUT_DIR${NC}"
log "${GREEN}Key files:${NC}"
log "- subs.txt           → Subdomains"
log "- takeovers.txt      → Subdomain takeovers"
log "- dns.txt            → DNS resolutions"
log "- live.txt           → Live hosts"
log "- headers.txt        → Security headers"
log "- ports.txt          → Open ports"
log "- js_files.txt       → JavaScript files"
log "- secrets.txt        → Secrets in JS"
log "- dirs.txt           → Directories"
log "- all_urls.txt       → Historical URLs"
log "- gf_matches/*.txt   → Param fuzzing sets"
log "- github_endpoints.txt → GitHub endpoints"
log "- trufflehog_output.json → GitHub secrets"
log "- repos.txt          → Scanned GitHub repositories"
log "- report.txt         → Summary report"
log "- recon.log          → Execution log"
log "- errors.log         → Error log"

exit 0
