#!/bin/bash
# GNU General Public License v3.0
# Copyright (C) 2026 sigithdteam-lab 
# =============================================================================
# WebShell Detector Pro v7.0 (Auto Pattern Update Edition)
# =============================================================================

set -euo pipefail

# =============================================================================
# KONFIGURASI
# =============================================================================

VERSION="7.0"
SCAN_DIR=""
LOG_DIR="/var/log/webshell_detector"
PATTERN_DIR="${LOG_DIR}/patterns"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/scan_${TIMESTAMP}.log"
REPORT_FILE="${LOG_DIR}/report_${TIMESTAMP}.txt"
ALERT_FILE="${LOG_DIR}/alerts_${TIMESTAMP}.txt"
JSON_FILE="${LOG_DIR}/scan_${TIMESTAMP}.json"
PATTERN_CACHE="${PATTERN_DIR}/pattern_cache.txt"

# Warna output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# Counter
TOTAL_SCANNED=0
SUSPICIOUS_FOUND=0
CRITICAL_FOUND=0
MALWARE_FOUND=0
CRYPTO_FOUND=0
RANSOMWARE_FOUND=0
PHISHING_FOUND=0
CUSTOM_FOUND=0
PATTERNS_UPDATED=0

# Opsi
MODE="normal"
OUTPUT_JSON=false
DEEP_SCAN=false
AUTO_UPDATE=true
UPDATE_ONLY=false

# =============================================================================
# KONFIGURASI DETEKSI
# =============================================================================

SKIP_DIRS=(
    "/proc" "/sys" "/dev" "/run" "/tmp" "/var/tmp"
    "/var/log" "/var/cache" "/usr/share/doc" "/usr/share/man"
    "/snap" "/var/lib/docker"
)

SCAN_EXTS=(
    "php" "php3" "php4" "php5" "php7" "phtml" "phps"
    "inc" "module" "theme" "engine" "cgi" "pl" "py"
    "js" "css" "html" "htm" "txt" "dat" "conf"
    "bak" "old" "swp" "swo" "tmp" "log"
    "sh" "bash" "zsh" "rb" "go" "java" "jsp" "asp" "aspx"
)

MAX_FILE_SIZE=5242880
DEEP_MAX_FILE_SIZE=20971520

# =============================================================================
# PATTERN SOURCES
# =============================================================================

declare -A PATTERN_SOURCES=(
    # YARA Rules - Malware Detection
    ["YARA_INDEX"]="https://raw.githubusercontent.com/Yara-Rules/rules/master/index.yar"
    ["YARA_MALWARE"]="https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/index.yar"
    ["YARA_WEBSHELLS"]="https://raw.githubusercontent.com/Yara-Rules/rules/master/webshells/index.yar"
    
    # PHP Malware Finder
    ["PHP_MALWARE_FINDER"]="https://raw.githubusercontent.com/php-malware-finder/php-malware-finder/master/malware.php"
    
    # Wordfence Patterns
    ["WORDFENCE"]="https://raw.githubusercontent.com/wordfence/patterns/main/patterns.php"
    
    # Neo23x0 Signature Base
    ["SIGNATURE_BASE"]="https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/general_reference.yar"
    
    # MalwareBazaar
    ["MALWARE_BAZAAR"]="https://mb-api.abuse.ch/api/v1/"
    
    # Exploit DB
    ["EXPLOIT_DB"]="https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv"
    
    # CVE List
    ["CVE_LIST"]="https://raw.githubusercontent.com/CVEProject/cvelist/master/cve-2025.json"
    
    # Custom Pattern Repositories
    ["CUSTOM_PATTERNS"]="https://raw.githubusercontent.com/sigithdteam/webshell-patterns/main/patterns.txt"
)

# =============================================================================
# PATTERN DETEKSI
# =============================================================================

declare -a DANGEROUS_PATTERNS=()
declare -a DANGEROUS_FUNCTIONS=()
declare -a SUSPICIOUS_NAMES=()
declare -a CRITICAL_PATTERNS=()
declare -a CRYPTO_PATTERNS=()
declare -a RANSOMWARE_PATTERNS=()
declare -a PHISHING_PATTERNS=()
declare -a MALWARE_INDICATORS=()
declare -a YARA_PATTERNS=()
declare -a FALCO_PATTERNS=()
declare -a OBFUSCATED_PATTERNS=()
declare -a WP_MALWARE_PATTERNS=()
declare -a PHP_OBJECT_INJECTION=()
declare -a INTERPRETER_PATTERNS=()
declare -a COOKIE_PATTERNS=()
declare -a LARAVEL_PATTERNS=()
declare -a JOOMLA_PATTERNS=()
declare -a DRUPAL_PATTERNS=()
declare -a CUSTOM_KEYWORD_PATTERNS=()

# =============================================================================
# FUNGSI PATTERN UPDATE
# =============================================================================

init_pattern_dir() {
    mkdir -p "$PATTERN_DIR" 2>/dev/null || true
    mkdir -p "${PATTERN_DIR}/yara" 2>/dev/null || true
    mkdir -p "${PATTERN_DIR}/custom" 2>/dev/null || true
}

download_pattern() {
    local source_name="$1"
    local url="$2"
    local output_file="${PATTERN_DIR}/$(echo "$source_name" | tr '[:upper:]' '[:lower:]').txt"
    
    echo -e "${CYAN}Downloading patterns from: ${source_name}${NC}"
    
    if command -v curl &>/dev/null; then
        if curl -sSL --connect-timeout 10 --max-time 30 "$url" -o "$output_file" 2>/dev/null; then
            if [[ -s "$output_file" ]]; then
                echo -e "${GREEN}✓ Downloaded: ${source_name}${NC}"
                return 0
            else
                echo -e "${YELLOW}✗ Empty response from: ${source_name}${NC}"
                rm -f "$output_file"
                return 1
            fi
        else
            echo -e "${RED}✗ Failed to download: ${source_name}${NC}"
            return 1
        fi
    elif command -v wget &>/dev/null; then
        if wget -q --timeout=10 --tries=2 "$url" -O "$output_file" 2>/dev/null; then
            if [[ -s "$output_file" ]]; then
                echo -e "${GREEN}✓ Downloaded: ${source_name}${NC}"
                return 0
            else
                echo -e "${YELLOW}✗ Empty response from: ${source_name}${NC}"
                rm -f "$output_file"
                return 1
            fi
        else
            echo -e "${RED}✗ Failed to download: ${source_name}${NC}"
            return 1
        fi
    else
        echo -e "${RED}✗ No download tool available (curl/wget)${NC}"
        return 1
    fi
}

extract_patterns_yara() {
    local file="$1"
    local pattern_type="$2"
    local -n target_array="$3"
    
    if [[ ! -f "$file" ]]; then
        return 1
    fi
    
    # Extract patterns from YARA rules
    while IFS= read -r line; do
        # Match pattern definitions in YARA
        if echo "$line" | grep -qE '^\s*\$[a-zA-Z0-9_]+[[:space:]]*='; then
            local pattern=$(echo "$line" | sed -n 's/.*= *"\([^"]*\)".*/\1/p' | head -1)
            if [[ -n "$pattern" ]] && [[ ${#pattern} -gt 3 ]]; then
                # Escape regex special characters for grep compatibility
                local escaped_pattern=$(echo "$pattern" | sed 's/\([][(){}.*+?^$|]\)/\\\1/g')
                target_array+=("$escaped_pattern")
            fi
        fi
    done < "$file"
}

extract_patterns_php() {
    local file="$1"
    local -n target_array="$2"
    
    if [[ ! -f "$file" ]]; then
        return 1
    fi
    
    # Extract patterns from PHP malware finder format
    while IFS= read -r line; do
        # Look for pattern definitions in PHP array
        if echo "$line" | grep -qE "=>[[:space:]]*['\"]"; then
            local pattern=$(echo "$line" | sed -n "s/.*=>[[:space:]]*['\"]\([^'\"]*\)['\"].*/\1/p")
            if [[ -n "$pattern" ]] && [[ ${#pattern} -gt 3 ]]; then
                target_array+=("$pattern")
            fi
        fi
    done < "$file"
}

extract_patterns_generic() {
    local file="$1"
    local -n target_array="$2"
    
    if [[ ! -f "$file" ]]; then
        return 1
    fi
    
    # Generic pattern extraction (simple strings)
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        
        # Look for potential patterns (alphanumeric, underscores, special chars)
        if echo "$line" | grep -qE '[a-zA-Z0-9_]{4,}'; then
            # Extract potential patterns
            local patterns=$(echo "$line" | grep -oE '[a-zA-Z0-9_]{4,}' | head -5)
            for pattern in $patterns; do
                if [[ -n "$pattern" ]] && [[ ${#pattern} -gt 3 ]]; then
                    target_array+=("$pattern")
                fi
            done
        fi
    done < "$file"
}

update_patterns_online() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}🔄 Updating Patterns from Internet${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    init_pattern_dir
    
    local downloaded=0
    local successful=0
    
    # Download from all sources
    for source_name in "${!PATTERN_SOURCES[@]}"; do
        local url="${PATTERN_SOURCES[$source_name]}"
        if download_pattern "$source_name" "$url"; then
            successful=$((successful + 1))
        fi
        downloaded=$((downloaded + 1))
    done
    
    echo -e "${GREEN}✓ Downloaded $successful/$downloaded pattern sources${NC}"
    
    # Process downloaded files and extract patterns
    echo -e "${CYAN}Extracting patterns...${NC}"
    
    # Reset arrays before adding external patterns
    local yara_patterns_temp=()
    local php_patterns_temp=()
    local generic_patterns_temp=()
    
    # Process YARA files
    for yara_file in "${PATTERN_DIR}"/yara_*.txt; do
        if [[ -f "$yara_file" ]]; then
            extract_patterns_yara "$yara_file" "yara" yara_patterns_temp
        fi
    done
    
    # Process PHP malware finder files
    for php_file in "${PATTERN_DIR}"/php_malware_finder.txt; do
        if [[ -f "$php_file" ]]; then
            extract_patterns_php "$php_file" php_patterns_temp
        fi
    done
    
    # Process generic pattern files
    for gen_file in "${PATTERN_DIR}"/*.txt; do
        if [[ -f "$gen_file" ]] && [[ ! "$gen_file" =~ (yara_|php_malware_finder) ]]; then
            extract_patterns_generic "$gen_file" generic_patterns_temp
        fi
    done
    
    # Merge patterns (deduplicate)
    local merged_patterns=()
    for pattern in "${yara_patterns_temp[@]}" "${php_patterns_temp[@]}" "${generic_patterns_temp[@]}"; do
        if [[ -n "$pattern" ]] && [[ ! " ${merged_patterns[@]} " =~ " ${pattern} " ]]; then
            merged_patterns+=("$pattern")
        fi
    done
    
    PATTERNS_UPDATED=${#merged_patterns[@]}
    echo -e "${GREEN}✓ Extracted $PATTERNS_UPDATED new patterns${NC}"
    
    # Save pattern cache
    printf '%s\n' "${merged_patterns[@]}" > "$PATTERN_CACHE"
    
    # Update main pattern arrays
    update_main_patterns "${merged_patterns[@]}"
}

update_main_patterns() {
    local new_patterns=("$@")
    
    # Add new patterns to appropriate arrays
    for pattern in "${new_patterns[@]}"; do
        # Skip if too short or common words
        if [[ ${#pattern} -lt 3 ]]; then
            continue
        fi
        
        # Categorize patterns
        if echo "$pattern" | grep -qiE "(eval|exec|shell|system|passthru|popen|proc_open|assert)"; then
            DANGEROUS_FUNCTIONS+=("$pattern")
        elif echo "$pattern" | grep -qiE "(c99|r57|wso|b374k|webshell|backdoor|shell|cmd)"; then
            CRITICAL_PATTERNS+=("$pattern")
            SUSPICIOUS_NAMES+=("$pattern")
        elif echo "$pattern" | grep -qiE "(xmrig|miner|stratum|pool|crypto|eth|btc|monero)"; then
            CRYPTO_PATTERNS+=("$pattern")
        elif echo "$pattern" | grep -qiE "(encrypt|decrypt|ransom|lock|crypt)"; then
            RANSOMWARE_PATTERNS+=("$pattern")
        elif echo "$pattern" | grep -qiE "(phish|login|oauth|auth|credential)"; then
            PHISHING_PATTERNS+=("$pattern")
        elif echo "$pattern" | grep -qiE "(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin)"; then
            OBFUSCATED_PATTERNS+=("$pattern")
        elif echo "$pattern" | grep -qiE "(curl|wget|nc|ncat|socat|python|perl|ruby)"; then
            FALCO_PATTERNS+=("$pattern")
        else
            YARA_PATTERNS+=("$pattern")
        fi
    done
    
    echo -e "${GREEN}✓ Patterns categorized and integrated${NC}"
}

# =============================================================================
# FUNGSI LOAD PATTERNS (Core + External)
# =============================================================================

load_patterns() {
    echo -e "${CYAN}Loading base patterns...${NC}"
    
    # ============================================================
    # CORE DANGEROUS PATTERNS
    # ============================================================
    DANGEROUS_PATTERNS=(
        "shell_exec[[:space:]]*("
        "system[[:space:]]*("
        "exec[[:space:]]*("
        "passthru[[:space:]]*("
        "popen[[:space:]]*("
        "proc_open[[:space:]]*("
        "pcntl_exec[[:space:]]*("
        "eval[[:space:]]*("
        "assert[[:space:]]*("
        "create_function[[:space:]]*("
        "call_user_func[[:space:]]*("
        "call_user_func_array[[:space:]]*("
        "base64_decode.*eval"
        "gzinflate.*eval"
        "gzuncompress.*eval"
        "str_rot13.*eval"
        "curl_exec[[:space:]]*("
        "fsockopen[[:space:]]*("
        "socket_create[[:space:]]*("
        "file_put_contents.*base64"
        "system.*base64"
        "exec.*base64"
        "shell_exec.*base64"
        "popen.*base64"
        "eval.*gzinflate"
        "eval.*base64_decode"
        "eval.*gzuncompress"
        "eval.*str_rot13"
        "eval.*hex2bin"
        "preg_replace.*\/e"
        "mb_ereg_replace.*\/e"
        "ob_start.*system"
    )

    # ============================================================
    # CORE DANGEROUS FUNCTIONS
    # ============================================================
    DANGEROUS_FUNCTIONS=(
        "eval" "system" "exec" "shell_exec" "passthru" "popen" "proc_open"
        "curl_exec" "phpinfo" "dl" "fsockopen" "pfsockopen"
        "gzinflate" "gzuncompress" "highlight_file" "ini_alter"
        "set_time_limit" "readlink" "symlink" "link"
        "mail" "mb_send_mail" "pcntl_exec" "create_function"
        "call_user_func" "call_user_func_array" "curl_multi_exec"
        "stream_socket_client" "socket_create" "register_shutdown_function"
        "assert" "preg_replace" "mb_ereg_replace"
        "system" "exec" "shell_exec" "passthru" "popen"
        "proc_open" "pcntl_exec" "eval" "assert"
        "base64_decode" "gzinflate" "gzuncompress"
        "str_rot13" "hex2bin" "gzdecode"
        "include" "require" "include_once" "require_once"
        "file_get_contents" "file_put_contents" "fopen" "fwrite"
        "chmod" "chown" "chgrp" "mkdir" "rmdir" "unlink"
        "symlink" "readlink" "realpath"
    )

    # ============================================================
    # CORE SUSPICIOUS NAMES
    # ============================================================
    SUSPICIOUS_NAMES=(
        "shell" "cmd" "c99" "r57" "backdoor" "webshell" "eval"
        "exec" "phpshell" "phpcmd" "adminer" "hack" "exploit"
        "malware" "virus" "c99shell" "r57shell" "wso" "b374k"
        "cmd.php" "admin.php" "wp-login.php" "db.php"
        "crypt" "miner" "ransom" "xmrig" "stratum"
        "shell.php" "cmd.php" "backdoor.php" "webshell.php"
        "hack.php" "exploit.php" "shell.asp" "cmd.aspx"
        "shell.jsp" "cmd.jsp" "upload.php" "filemanager.php"
        "phpmyadmin" "mysql" "phpinfo" "test" "tmp" "temp"
    )

    # ============================================================
    # CORE CRITICAL PATTERNS
    # ============================================================
    CRITICAL_PATTERNS=(
        "c99shell" "r57shell" "wso" "b374k" "webshell" "backdoor"
        "cmd.php" "admin.php" "shell.php" "drakon" "packetcrypt"
        "cve_2024" "cve_2025" "exploit" "payload"
        "reverse_shell" "bind_shell" "meterpreter"
        "cve_2026" "cve_2027" "zero-day" "0day"
        "shellcode" "exploit_db" "metasploit"
        "c99" "r57" "wso" "b374k" "drakon"
    )

    # ============================================================
    # CORE CRYPTO PATTERNS
    # ============================================================
    CRYPTO_PATTERNS=(
        "xmrig" "xmr-stak" "minerd" "minergate"
        "cpuminer" "ccminer" "ethminer" "cgminer"
        "bfgminer" "sgminer" "claymore" "nbminer"
        "t-rex" "gminer" "lolminer" "phoenixminer"
        "teamredminer" "nanominer" "bminer" "wildrig" "srbminer"
        "stratum" "pool.*mine" "crypto_miner" "packetcrypt"
        "monero" "bitcoin" "ethereum" "litecoin" "dogecoin"
        "mining" "cryptonight" "randomx" "kawpow" "ethash"
        "nicehash" "hashflare" "genesis-mining"
    )

    # ============================================================
    # CORE RANSOMWARE PATTERNS
    # ============================================================
    RANSOMWARE_PATTERNS=(
        "file_put_contents.*.encrypted"
        "file_put_contents.*.locked"
        "file_put_contents.*.crypted"
        "readme.html" "how_to_decrypt" "ransom_note"
        "Dragon_Readme" "openssl_encrypt" "mcrypt_encrypt"
        "decrypt_instructions" "ransomware"
        ".encrypted" ".locked" ".crypted" ".enc"
        "ransom" "decrypt" "recover_files"
        "bitcoin_wallet" "monero_wallet"
    )

    # ============================================================
    # CORE PHISHING PATTERNS
    # ============================================================
    PHISHING_PATTERNS=(
        "login.php" "signin.php" "oauth.php" "auth.php"
        "fb-login" "google-login" "microsoft-login"
        "credential.*harvest" "phishing"
        "password" "username" "email" "credit_card"
        "ssn" "social_security" "bank_account"
        "paypal" "stripe" "square" "venmo"
    )

    # ============================================================
    # CORE MALWARE INDICATORS
    # ============================================================
    MALWARE_INDICATORS=(
        "botnet" "c2" "callback" "beacon"
        "download.*execute" "remote.*include"
        "crontab" "systemd" "persistence"
        "cve" "exploit" "payload" "shellcode"
        "malware" "virus" "trojan" "worm"
        "keylogger" "spyware" "adware" "ransomware"
    )

    # ============================================================
    # CORE YARA PATTERNS
    # ============================================================
    YARA_PATTERNS=(
        "system[[:space:]]*([[:space:]]*[$]_" "passthru[[:space:]]*([[:space:]]*[$]_"
        "shell_exec[[:space:]]*([[:space:]]*[$]_" "exec[[:space:]]*([[:space:]]*[$]_"
        "eval[[:space:]]*([[:space:]]*[$]_" "base64_decode.*eval"
        "gzinflate.*eval" "gzuncompress.*eval"
        "assert[[:space:]]*([[:space:]]*" "fwrite[[:space:]]*("
        "file_put_contents[[:space:]]*(" "move_uploaded_file[[:space:]]*("
        "[$]_FILES" "chmod[[:space:]]*(" "mkdir[[:space:]]*("
        "gzdecode.*eval" "hex2bin.*eval"
        "str_rot13.*eval" "base64_decode.*gzinflate"
        "include.*base64" "require.*base64"
        "file_get_contents.*base64" "curl_exec.*base64"
    )

    # ============================================================
    # CORE FALCO PATTERNS
    # ============================================================
    FALCO_PATTERNS=(
        "curl.*http" "wget.*http" "nc.*-e" "ncat.*-e"
        "socat.*exec" "python.*-c" "perl.*-e"
        "id[[:space:]]*;" "whoami[[:space:]]*;" "uname[[:space:]]*;"
        "base64.*-d"
        "bash.*-c" "sh.*-c" "zsh.*-c"
        "ssh.*-o" "scp.*-P"
    )

    # ============================================================
    # CORE OBFUSCATED PATTERNS
    # ============================================================
    OBFUSCATED_PATTERNS=(
        "system[[:space:]]*([[:space:]]*base64"
        "eval[[:space:]]*([[:space:]]*base64"
        "base64_decode[[:space:]]*([[:space:]]*[A-Za-z0-9+/]{50,}"
        "str_rot13.*eval" "hex2bin.*eval" "gzdecode.*eval"
        "preg_replace.*\/e.*base64" "obfuscated"
        "chr[[:space:]]*([[:space:]]*[0-9]+"
        "ord[[:space:]]*([[:space:]]*['\"]"
        "pack[[:space:]]*([[:space:]]*['\"]H"
        "unpack[[:space:]]*([[:space:]]*['\"]H"
    )

    # ============================================================
    # CORE WORDPRESS MALWARE
    # ============================================================
    WP_MALWARE_PATTERNS=(
        "db.php.*<?php" "advanced-cache.php.*<?php"
        "functions.php.*base64_decode"
        "wp-config.php.*eval" "mu-plugins.*base64"
        "wp-content.*malware" "wp-includes.*backdoor"
        "theme.*functions.*eval" "plugin.*backdoor"
        "wp-admin.*shell" "wp-login.*phishing"
    )

    # ============================================================
    # CORE PHP OBJECT INJECTION
    # ============================================================
    PHP_OBJECT_INJECTION=(
        "unserialize[[:space:]]*([[:space:]]*[$]_"
        "__wakeup[[:space:]]*(" "__destruct[[:space:]]*("
        "__toString[[:space:]]*(" "__call[[:space:]]*("
        "__get[[:space:]]*(" "__set[[:space:]]*("
        "__isset[[:space:]]*(" "__unset[[:space:]]*("
        "__sleep[[:space:]]*(" "__wakeup[[:space:]]*("
        "__serialize[[:space:]]*(" "__unserialize[[:space:]]*("
    )

    # ============================================================
    # CORE INTERPRETER PATTERNS
    # ============================================================
    INTERPRETER_PATTERNS=(
        "perl[[:space:]]+-e" "php[[:space:]]+-r"
        "php[[:space:]]+-c" "lua[[:space:]]+-e"
        "python[[:space:]]+-c" "ruby[[:space:]]+-e"
        "os.system[[:space:]]*(" "os.popen[[:space:]]*("
        "zlib.decompress[[:space:]]*(" "socket.connect[[:space:]]*("
        "subprocess.*call" "subprocess.*Popen"
    )

    # ============================================================
    # CORE COOKIE PATTERNS
    # ============================================================
    COOKIE_PATTERNS=(
        "cookie.*eval" "[$]_COOKIE.*eval"
        "base64_decode.*[$]_COOKIE" "gzinflate.*[$]_COOKIE"
        "[$]_COOKIE[[:space:]]*\[.*\][[:space:]]*;"
        "[$]_COOKIE.*system" "[$]_COOKIE.*exec"
        "[$]_COOKIE.*shell_exec" "[$]_COOKIE.*passthru"
    )

    # ============================================================
    # CORE LARAVEL PATTERNS
    # ============================================================
    LARAVEL_PATTERNS=(
        "laravel.*backdoor" "storage.*shell"
        "bootstrap.*cache.*eval" "config.*malware"
        "routes.*webshell" "middleware.*backdoor"
        "vendor.*malware" "artisan.*shell"
    )

    # ============================================================
    # CORE JOOMLA PATTERNS
    # ============================================================
    JOOMLA_PATTERNS=(
        "joomla.*backdoor" "administrator.*shell"
        "components.*malware" "modules.*backdoor"
        "plugins.*webshell" "templates.*eval"
        "libraries.*phishing" "configuration.*crypt"
    )

    # ============================================================
    # CORE DRUPAL PATTERNS
    # ============================================================
    DRUPAL_PATTERNS=(
        "drupal.*backdoor" "sites.*shell"
        "modules.*malware" "themes.*backdoor"
        "profiles.*webshell" "includes.*eval"
        "core.*phishing" "database.*crypt"
    )

    # ============================================================
    # CUSTOM KEYWORD PATTERNS - Indonesian Hackers
    # ============================================================
    CUSTOM_KEYWORD_PATTERNS=(
        "sincan" "sincan2" "ulga" "solder" "sodok" "mhl" "malanghackerlink" "ijoo" "ij0o"
    )

    # Tambahkan custom keywords ke SUSPICIOUS_NAMES
    SUSPICIOUS_NAMES+=("${CUSTOM_KEYWORD_PATTERNS[@]}")

    # Tambahkan custom keywords ke DANGEROUS_PATTERNS untuk deteksi konten
    for keyword in "${CUSTOM_KEYWORD_PATTERNS[@]}"; do
        DANGEROUS_PATTERNS+=("$keyword")
    done

    # Load cached patterns if available
    if [[ -f "$PATTERN_CACHE" ]] && [[ "$AUTO_UPDATE" == true ]]; then
        echo -e "${CYAN}Loading cached external patterns...${NC}"
        local cached_count=0
        while IFS= read -r pattern; do
            if [[ -n "$pattern" ]] && [[ ! " ${YARA_PATTERNS[@]} " =~ " ${pattern} " ]]; then
                YARA_PATTERNS+=("$pattern")
                cached_count=$((cached_count + 1))
            fi
        done < "$PATTERN_CACHE"
        echo -e "${GREEN}✓ Loaded $cached_count cached patterns${NC}"
    fi

    # Merge all pattern arrays for deduplication
    merge_patterns
}

merge_patterns() {
    # Combine all patterns into one master list for performance
    local all_patterns=(
        "${DANGEROUS_PATTERNS[@]}"
        "${DANGEROUS_FUNCTIONS[@]}"
        "${SUSPICIOUS_NAMES[@]}"
        "${CRITICAL_PATTERNS[@]}"
        "${CRYPTO_PATTERNS[@]}"
        "${RANSOMWARE_PATTERNS[@]}"
        "${PHISHING_PATTERNS[@]}"
        "${MALWARE_INDICATORS[@]}"
        "${YARA_PATTERNS[@]}"
        "${FALCO_PATTERNS[@]}"
        "${OBFUSCATED_PATTERNS[@]}"
        "${WP_MALWARE_PATTERNS[@]}"
        "${PHP_OBJECT_INJECTION[@]}"
        "${INTERPRETER_PATTERNS[@]}"
        "${COOKIE_PATTERNS[@]}"
        "${LARAVEL_PATTERNS[@]}"
        "${JOOMLA_PATTERNS[@]}"
        "${DRUPAL_PATTERNS[@]}"
        "${CUSTOM_KEYWORD_PATTERNS[@]}"
    )
    
    # Sort and deduplicate
    local sorted_patterns=($(printf '%s\n' "${all_patterns[@]}" | sort -u))
    echo -e "${GREEN}✓ Total unique patterns: ${#sorted_patterns[@]}${NC}"
}

# =============================================================================
# FUNGSI UTILITY
# =============================================================================

check_dependencies() {
    local missing=()
    
    for cmd in grep sed awk find file stat; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${YELLOW}Warning: Missing optional dependencies: ${missing[*]}${NC}"
        echo -e "${YELLOW}Some features may not work properly${NC}"
    fi
    
    # Check for download tools
    if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
        echo -e "${RED}Error: curl or wget required for pattern updates${NC}"
        if [[ "$AUTO_UPDATE" == true ]]; then
            echo -e "${YELLOW}Disabling auto-update...${NC}"
            AUTO_UPDATE=false
        fi
    fi
    
    # Check for jq (optional, for JSON output)
    if ! command -v jq &>/dev/null; then
        echo -e "${YELLOW}Warning: jq not installed. JSON output disabled.${NC}"
        OUTPUT_JSON=false
    fi
}

init() {
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    mkdir -p "$PATTERN_DIR" 2>/dev/null || true
    
    {
        echo "╔════════════════════════════════════════════════════════════════╗"
        echo "║     WebShell Detector Pro v${VERSION} - Auto Pattern Update   ║"
        echo "║     LOG ONLY - No files are deleted                           ║"
        echo "║     Scan started: $(date)                                      ║"
        echo "║     Mode: ${MODE}                                              ║"
        echo "║     Auto-Update: ${AUTO_UPDATE}                                ║"
        echo "║     Directory: ${SCAN_DIR}                                    ║"
        echo "╚════════════════════════════════════════════════════════════════╝"
    } > "$LOG_FILE"
    
    echo -e "${GREEN}Log file: $LOG_FILE${NC}"
}

log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%H:%M:%S')
    case "$level" in
        "INFO")    echo -e "${GREEN}[${timestamp}] [INFO]${NC} $message" | tee -a "$LOG_FILE" ;;
        "WARN")    echo -e "${YELLOW}[${timestamp}] [WARN]${NC} $message" | tee -a "$LOG_FILE" ;;
        "ERROR")   echo -e "${RED}[${timestamp}] [ERROR]${NC} $message" | tee -a "$LOG_FILE" ;;
        "FOUND")   echo -e "${YELLOW}[${timestamp}] [⚠️]${NC} $message" | tee -a "$LOG_FILE" ;;
        "CRITICAL") echo -e "${RED}[${timestamp}] [💀]${NC} $message" | tee -a "$LOG_FILE" ;;
        "MALWARE")  echo -e "${MAGENTA}[${timestamp}] [🦠]${NC} $message" | tee -a "$LOG_FILE" ;;
        "CRYPTO")   echo -e "${CYAN}[${timestamp}] [⛏️]${NC} $message" | tee -a "$LOG_FILE" ;;
        "RANSOM")   echo -e "${RED}[${timestamp}] [🔒]${NC} $message" | tee -a "$LOG_FILE" ;;
        "PHISH")    echo -e "${YELLOW}[${timestamp}] [🎣]${NC} $message" | tee -a "$LOG_FILE" ;;
        "UPDATE")   echo -e "${BLUE}[${timestamp}] [⬇️]${NC} $message" | tee -a "$LOG_FILE" ;;
        *)         echo "$message" | tee -a "$LOG_FILE" ;;
    esac
}

show_banner() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║         WebShell Detector Pro v${VERSION}                      ║"
    echo "║     Auto Pattern Update Edition - v7.0                        ║"
    echo "║     LOG ONLY - No files are deleted                            ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""
}

show_help() {
    cat << EOF
${BLUE}WebShell Detector Pro v${VERSION} - Auto Pattern Update Edition${NC}

${BOLD}USAGE:${NC}
    $0 [MODE] DIRECTORY [OPTIONS]

${BOLD}MODES:${NC}
    normal      - Quick scan (default)
    deep        - Deep scan with more patterns
    full        - Full scan + JSON output
    update-only - Only update patterns, no scan

${BOLD}EXAMPLES:${NC}
    # Quick scan with auto-update
    $0 /var/www/html

    # Deep scan with pattern update
    $0 deep /var/www/html

    # Only update patterns
    $0 update-only

    # Scan without pattern update
    $0 --no-update /var/www/html

${BOLD}OPTIONS:${NC}
    -j, --json          Output JSON
    --no-update         Skip pattern update
    -h, --help          Show this help

${BOLD}FEATURES:${NC}
    🔄 Auto-download patterns from 10+ sources
    🧠 Intelligent pattern extraction and categorization
    🚀 Optimized scanning with cached patterns
    📊 Comprehensive JSON/Text reports

EOF
    exit 0
}

# =============================================================================
# FUNGSI DETEKSI
# =============================================================================

check_file() {
    local file="$1"
    local found_patterns=()
    local is_critical=false
    local file_content=""
    local file_hash=""

    [[ -r "$file" ]] || return 0

    local filesize=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo 0)
    local max_size=$MAX_FILE_SIZE
    [[ "$DEEP_SCAN" == true ]] && max_size=$DEEP_MAX_FILE_SIZE
    [[ $filesize -gt $max_size ]] && return 0

    file_content=$(cat "$file" 2>/dev/null || echo "")
    [[ -z "$file_content" ]] && return 0

    if command -v md5sum &>/dev/null; then
        file_hash=$(md5sum "$file" | cut -d' ' -f1)
    elif command -v md5 &>/dev/null; then
        file_hash=$(md5 -q "$file" 2>/dev/null || echo "")
    fi

    local filename=$(basename "$file")
    
    local is_text=false
    if file "$file" 2>/dev/null | grep -q "text"; then
        is_text=true
    fi
    
    if [[ ${#file_content} -gt 0 ]] && [[ ${#file_content} -lt 1000000 ]]; then
        
        # Scan all pattern arrays
        local pattern_arrays=(
            "YARA_PATTERNS" "FALCO_PATTERNS" "CRYPTO_PATTERNS"
            "OBFUSCATED_PATTERNS" "WP_MALWARE_PATTERNS" "PHP_OBJECT_INJECTION"
            "INTERPRETER_PATTERNS" "COOKIE_PATTERNS" "RANSOMWARE_PATTERNS"
            "PHISHING_PATTERNS" "CRITICAL_PATTERNS" "DANGEROUS_PATTERNS"
            "LARAVEL_PATTERNS" "JOOMLA_PATTERNS" "DRUPAL_PATTERNS"
            "CUSTOM_KEYWORD_PATTERNS"
        )
        
        for arr_name in "${pattern_arrays[@]}"; do
            local -n arr="$arr_name"
            for pattern in "${arr[@]}"; do
                if [[ -n "$pattern" ]] && echo "$file_content" | grep -qiE "$pattern" 2>/dev/null; then
                    local prefix=$(echo "$arr_name" | cut -d'_' -f1)
                    found_patterns+=("${prefix}: $pattern")
                    is_critical=true
                    
                    # Update counters based on pattern type
                    case "$arr_name" in
                        "CRYPTO_PATTERNS") CRYPTO_FOUND=$((CRYPTO_FOUND + 1)) ;;
                        "RANSOMWARE_PATTERNS") RANSOMWARE_FOUND=$((RANSOMWARE_FOUND + 1)) ;;
                        "PHISHING_PATTERNS") PHISHING_FOUND=$((PHISHING_FOUND + 1)) ;;
                        "CUSTOM_KEYWORD_PATTERNS") CUSTOM_FOUND=$((CUSTOM_FOUND + 1)) ;;
                    esac
                fi
            done
        done
    fi

    # Check suspicious names
    for name in "${SUSPICIOUS_NAMES[@]}"; do
        if [[ -n "$name" ]] && echo "$filename" | grep -qi "$name" 2>/dev/null; then
            found_patterns+=("SUSPICIOUS_NAME: $name")
            is_critical=true
        fi
    done

    # Check dangerous functions (only text files)
    if [[ "$is_text" == true ]]; then
        for func in "${DANGEROUS_FUNCTIONS[@]}"; do
            if [[ -n "$func" ]] && grep -Eiq "${func}[[:space:]]*(" "$file" 2>/dev/null; then
                found_patterns+=("FUNCTION: $func()")
                is_critical=true
            fi
        done
    fi

    # Check custom keywords specifically
    for keyword in "${CUSTOM_KEYWORD_PATTERNS[@]}"; do
        if [[ -n "$keyword" ]]; then
            # Check in content
            if echo "$file_content" | grep -qi "$keyword" 2>/dev/null; then
                found_patterns+=("CUSTOM_KEYWORD: $keyword")
                is_critical=true
                CUSTOM_FOUND=$((CUSTOM_FOUND + 1))
            fi
            # Check in filename
            if echo "$filename" | grep -qi "$keyword" 2>/dev/null; then
                found_patterns+=("CUSTOM_KEYWORD_FILENAME: $keyword")
                is_critical=true
                CUSTOM_FOUND=$((CUSTOM_FOUND + 1))
            fi
        fi
    done

    # Report findings
    if [[ ${#found_patterns[@]} -gt 0 ]]; then
        TOTAL_SCANNED=$((TOTAL_SCANNED + 1))
        SUSPICIOUS_FOUND=$((SUSPICIOUS_FOUND + 1))

        local filepath=$(realpath "$file" 2>/dev/null || echo "$file")

        if [[ "$is_critical" == true ]]; then
            CRITICAL_FOUND=$((CRITICAL_FOUND + 1))
            
            local icon="💀"
            local level="CRITICAL"
            
            local combined=$(printf '%s\n' "${found_patterns[@]}")
            if echo "$combined" | grep -q "CRYPTO"; then
                icon="⛏️"; level="CRYPTO"
            elif echo "$combined" | grep -q "RANSOMWARE"; then
                icon="🔒"; level="RANSOM"
            elif echo "$combined" | grep -q "PHISHING"; then
                icon="🎣"; level="PHISH"
            elif echo "$combined" | grep -q "MALWARE"; then
                icon="🦠"; level="MALWARE"
            elif echo "$combined" | grep -q "CUSTOM_KEYWORD"; then
                icon="🔍"; level="CRITICAL"
            fi
            
            log "$level" "$icon $filepath"
            {
                echo "[$(date)] $level: $filepath"
                echo "Hash: ${file_hash:-N/A}"
                echo "Patterns:"
                for p in "${found_patterns[@]}"; do
                    echo "  - $p"
                done
                echo ""
            } >> "$ALERT_FILE"
        else
            log "FOUND" "⚠️  $filepath"
        fi

        {
            echo "─────────────────────────────────────────────────"
            echo "File: $filepath"
            echo "Hash: ${file_hash:-N/A}"
            echo "Patterns:"
            for p in "${found_patterns[@]}"; do
                echo "  - $p"
            done
            echo ""
        } >> "$REPORT_FILE"

        if [[ "$OUTPUT_JSON" == true ]]; then
            local patterns_json=$(printf '%s\n' "${found_patterns[@]}" | jq -R . | jq -s . 2>/dev/null || echo '[]')
            echo "{\"file\":\"$filepath\",\"critical\":$is_critical,\"patterns\":$patterns_json,\"md5\":\"${file_hash:-null}\"}" >> "$JSON_FILE.tmp"
        fi
    fi
}

# =============================================================================
# FUNGSI SCAN
# =============================================================================

scan_directory() {
    local dir="$1"
    log "INFO" "Scanning directory: $dir"
    
    local total_files=0
    local scanned_files=0
    
    total_files=$(find "$dir" -type f 2>/dev/null | wc -l)
    log "INFO" "Total files in directory: $total_files"
    
    while IFS= read -r -d '' file; do
        local skip=false
        for skip_dir in "${SKIP_DIRS[@]}"; do
            if [[ "$file" == "$skip_dir"/* ]] || [[ "$file" == "$skip_dir" ]]; then
                skip=true
                break
            fi
        done
        [[ "$skip" == "true" ]] && continue
        
        local ext="${file##*.}"
        local should_scan=false
        
        for scan_ext in "${SCAN_EXTS[@]}"; do
            if [[ "$ext" == "$scan_ext" ]]; then
                should_scan=true
                break
            fi
        done
        
        if [[ "$should_scan" == false ]] && [[ "$DEEP_SCAN" == true ]]; then
            if file "$file" 2>/dev/null | grep -q "text"; then
                should_scan=true
            fi
        fi
        
        if [[ "$should_scan" == true ]]; then
            scanned_files=$((scanned_files + 1))
            if [[ $((scanned_files % 50)) -eq 0 ]]; then
                echo -ne "\r${CYAN}Scanned: $scanned_files / $total_files files${NC}    "
            fi
            check_file "$file"
        fi
    done < <(find "$dir" -type f -print0 2>/dev/null)
    
    echo -e "\r${GREEN}Scan complete! Scanned: $scanned_files files${NC}    "
}

# =============================================================================
# GENERATE REPORT
# =============================================================================

generate_report() {
    {
        echo ""
        echo "╔═══════════════════════════════════════════════════════════════╗"
        echo "║                    SCAN REPORT                                ║"
        echo "╚═══════════════════════════════════════════════════════════════╝"
        echo ""
        echo "Scan Details:"
        echo "  Directory: $SCAN_DIR"
        echo "  Date: $(date)"
        echo "  Mode: $MODE"
        echo "  Version: $VERSION (Auto Pattern Update)"
        echo "  Patterns Updated: $PATTERNS_UPDATED"
        echo ""
        echo "File Scan Statistics:"
        echo "  Suspicious Files: $SUSPICIOUS_FOUND"
        echo "  Critical Files: $CRITICAL_FOUND"
        echo "  Crypto Miners: $CRYPTO_FOUND"
        echo "  Ransomware: $RANSOMWARE_FOUND"
        echo "  Phishing Pages: $PHISHING_FOUND"
        echo "  Custom Keywords Found: $CUSTOM_FOUND"
        echo ""
        
        if [[ $CRITICAL_FOUND -gt 0 ]]; then
            echo "💀 CRITICAL FILES:"
            echo "─────────────────────────────────────────────────────────────────"
            cat "$ALERT_FILE" 2>/dev/null || echo "  (None)"
            echo ""
        fi

        echo "─────────────────────────────────────────────────────────────────"
        echo ""
        echo "⚠️  REMEMBER: No files were deleted. Review findings carefully."
        echo ""
        echo "Log file: $LOG_FILE"
        echo "Report: $REPORT_FILE"
        echo "Alerts: $ALERT_FILE"
        if [[ "$OUTPUT_JSON" == true ]]; then
            echo "JSON: $JSON_FILE"
        fi
    } | tee -a "$LOG_FILE"
}

# =============================================================================
# GENERATE JSON
# =============================================================================

generate_json() {
    if [[ "$OUTPUT_JSON" == true ]] && [[ -f "$JSON_FILE.tmp" ]]; then
        {
            echo "{"
            echo "  \"scan\": {"
            echo "    \"directory\": \"$SCAN_DIR\","
            echo "    \"timestamp\": \"$(date -Iseconds)\","
            echo "    \"version\": \"$VERSION\","
            echo "    \"mode\": \"$MODE\","
            echo "    \"patterns_updated\": $PATTERNS_UPDATED,"
            echo "    \"suspicious_found\": $SUSPICIOUS_FOUND,"
            echo "    \"critical_found\": $CRITICAL_FOUND,"
            echo "    \"crypto_found\": $CRYPTO_FOUND,"
            echo "    \"ransomware_found\": $RANSOMWARE_FOUND,"
            echo "    \"phishing_found\": $PHISHING_FOUND,"
            echo "    \"custom_found\": $CUSTOM_FOUND"
            echo "  },"
            echo "  \"files\": ["
            paste -sd, "$JSON_FILE.tmp" 2>/dev/null
            echo "  ]"
            echo "}"
        } > "$JSON_FILE"
        rm -f "$JSON_FILE.tmp" 2>/dev/null
        log "INFO" "JSON saved to $JSON_FILE"
    fi
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    check_dependencies
    load_patterns
    
    show_banner

    local args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            normal|deep|full|update-only)
                MODE="$1"
                shift
                ;;
            --no-update)
                AUTO_UPDATE=false
                shift
                ;;
            -j|--json)
                OUTPUT_JSON=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                echo -e "${RED}Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
            *)
                args+=("$1")
                shift
                ;;
        esac
    done

    if [[ "$MODE" == "update-only" ]]; then
        echo -e "${BOLD}🔄 Pattern Update Only Mode${NC}"
        update_patterns_online
        echo -e "${GREEN}✓ Patterns updated successfully!${NC}"
        echo -e "${CYAN}Pattern cache: $PATTERN_CACHE${NC}"
        exit 0
    fi

    if [[ ${#args[@]} -eq 0 ]]; then
        echo -e "${RED}Error: No directory specified.${NC}"
        show_help
        exit 1
    else
        SCAN_DIR="${args[0]}"
    fi

    if [[ ! -d "$SCAN_DIR" ]]; then
        echo -e "${RED}Error: Directory '$SCAN_DIR' not found!${NC}"
        exit 1
    fi
    if [[ ! -r "$SCAN_DIR" ]]; then
        echo -e "${RED}Error: Cannot read directory '$SCAN_DIR'${NC}"
        exit 1
    fi

    case "$MODE" in
        deep|full) DEEP_SCAN=true ;;
    esac
    
    if [[ "$MODE" == "full" ]]; then
        OUTPUT_JSON=true
    fi

    init

    # Auto-update patterns if enabled
    if [[ "$AUTO_UPDATE" == true ]]; then
        update_patterns_online
        echo ""
    fi

    echo -e "${BLUE}Starting file scan...${NC}"
    echo -e "${CYAN}Mode: $MODE${NC}"
    echo -e "${CYAN}Patterns loaded: $(printf '%s\n' "${YARA_PATTERNS[@]}" | wc -l)${NC}"
    echo ""
    scan_directory "$SCAN_DIR"

    if [[ "$OUTPUT_JSON" == true ]]; then
        generate_json
    fi

    generate_report

    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}SUMMARY${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    echo -e "${CYAN}📊 Pattern Updates: $PATTERNS_UPDATED new patterns${NC}"
    echo ""
    
    if [[ $CRITICAL_FOUND -gt 0 ]]; then
        echo -e "${RED}💀 CRITICAL: $CRITICAL_FOUND threats${NC}"
    fi
    if [[ $CRYPTO_FOUND -gt 0 ]]; then
        echo -e "${CYAN}⛏️ CRYPTO MINERS: $CRYPTO_FOUND${NC}"
    fi
    if [[ $RANSOMWARE_FOUND -gt 0 ]]; then
        echo -e "${RED}🔒 RANSOMWARE: $RANSOMWARE_FOUND${NC}"
    fi
    if [[ $PHISHING_FOUND -gt 0 ]]; then
        echo -e "${YELLOW}🎣 PHISHING: $PHISHING_FOUND${NC}"
    fi
    if [[ $CUSTOM_FOUND -gt 0 ]]; then
        echo -e "${MAGENTA}🔍 CUSTOM KEYWORDS: $CUSTOM_FOUND${NC}"
    fi
    if [[ $SUSPICIOUS_FOUND -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  SUSPICIOUS: $SUSPICIOUS_FOUND${NC}"
    fi
    if [[ $SUSPICIOUS_FOUND -eq 0 ]]; then
        echo -e "${GREEN}✅ No suspicious files found!${NC}"
    fi

    echo ""
    echo -e "${BLUE}Logs: $LOG_DIR${NC}"
    echo -e "${BLUE}Report: $REPORT_FILE${NC}"
    echo -e "${BLUE}Patterns: $PATTERN_DIR${NC}"
    echo -e "${BOLD}⚠️  No files deleted. Review findings carefully.${NC}"
}

# =============================================================================
# EKSEKUSI
# =============================================================================

main "$@"
