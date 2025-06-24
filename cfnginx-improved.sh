#!/bin/bash
# shellcheck disable=SC2034
# CloudflareNginx Installer v3.0
# Enhanced version with improved security, error handling, and features

set -euo pipefail

# Configuration - Using readonly for constants
readonly SCRIPT_VERSION="3.0"
readonly BLUE='\033[0;34m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly RED='\033[0;31m'
readonly NC='\033[0m'
readonly LOG_FILE="/var/log/cloudflarenginx-install.log"
readonly CONFIG_FILE="/etc/cloudflarenginx.conf"
readonly BACKUP_DIR="/var/backups/cloudflarenginx"
readonly CURL_TIMEOUT=30

# Initialize variables
DOMAIN=""
PORT=""
CF_EMAIL=""
CF_API_KEY=""
WEBHOOK_URL=""
WEBHOOK_MODE="B"
WEBHOOK_PLATFORM="D"
SSL_SUCCESS=0
QUIET_MODE=0
DRY_RUN=0
ROLLBACK_ENABLED=1

# Create temp directory with validation
TMP_DIR=""
create_temp_dir() {
    TMP_DIR=$(mktemp -d 2>/dev/null) || {
        echo -e "${RED}Failed to create temporary directory${NC}" >&2
        exit 1
    }
    if [[ ! -d "$TMP_DIR" ]] || [[ ! -w "$TMP_DIR" ]]; then
        echo -e "${RED}Invalid temporary directory: $TMP_DIR${NC}" >&2
        exit 1
    fi
}

# Enhanced cleanup function with signal handling
cleanup() {
    local exit_code=$?
    if [[ -n "${TMP_DIR:-}" ]] && [[ -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
    
    # If installation failed and rollback is enabled
    if [[ $exit_code -ne 0 ]] && [[ $ROLLBACK_ENABLED -eq 1 ]] && [[ $DRY_RUN -eq 0 ]]; then
        log_error "Installation failed, initiating rollback..."
        perform_rollback
    fi
    
    exit $exit_code
}

# Enhanced signal handling
trap cleanup EXIT
trap 'echo -e "\n${RED}Installation interrupted${NC}"; exit 130' INT TERM

# Check for root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root${NC}" >&2
        echo -e "${YELLOW}Try: sudo $0 $*${NC}" >&2
        exit 1
    fi
}

# Enhanced logging functions
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

log_and_print() {
    if [[ "$QUIET_MODE" != "1" ]]; then
        echo -e "${BLUE}$1${NC}"
    fi
    log "INFO: $1"
}

log_success() {
    if [[ "$QUIET_MODE" != "1" ]]; then
        echo -e "${GREEN}✓ $1${NC}"
    fi
    log "SUCCESS: $1"
}

log_warning() {
    if [[ "$QUIET_MODE" != "1" ]]; then
        echo -e "${YELLOW}⚠ $1${NC}"
    fi
    log "WARNING: $1"
}

log_error() {
    if [[ "$QUIET_MODE" != "1" ]]; then
        echo -e "${RED}✗ $1${NC}"
    fi
    log "ERROR: $1"
}

log_dry_run() {
    if [[ "$QUIET_MODE" != "1" ]]; then
        echo -e "${YELLOW}[DRY RUN] $1${NC}"
    fi
    log "DRY RUN: $1"
}

# Escape JSON strings to prevent injection
escape_json() {
    local string="$1"
    string="${string//\\/\\\\}"
    string="${string//\"/\\\"}"
    string="${string//$'\n'/\\n}"
    string="${string//$'\r'/\\r}"
    string="${string//$'\t'/\\t}"
    echo "$string"
}

# Validation functions with enhanced checks
validate_domain() {
    local domain="$1"
    if [[ ! "$domain" =~ ^([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$ ]]; then
        log_error "Invalid domain format: $domain"
        echo -e "${RED}Please enter a valid domain name (e.g., example.com)${NC}" >&2
        return 1
    fi
    
    # Check if domain resolves (warning only)
    if ! host "$domain" >/dev/null 2>&1; then
        log_warning "Domain $domain does not resolve yet"
    fi
    
    return 0
}

validate_port() {
    local port="$1"
    if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
        log_error "Invalid port number: $port"
        echo -e "${RED}Port must be a number between 1 and 65535${NC}" >&2
        return 1
    fi
    
    # Check if port is already in use
    if lsof -Pi :"$port" -sTCP:LISTEN -t >/dev/null 2>&1; then
        log_warning "Port $port is already in use"
    fi
    
    return 0
}

validate_email() {
    local email="$1"
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log_error "Invalid email format: $email"
        echo -e "${RED}Please enter a valid email address${NC}" >&2
        return 1
    fi
    return 0
}

validate_webhook_url() {
    local url="$1"
    if [[ ! "$url" =~ ^https?://.+ ]]; then
        log_error "Invalid webhook URL: $url"
        echo -e "${RED}Webhook URL must start with http:// or https://${NC}" >&2
        return 1
    fi
    
    # Test webhook connectivity (with timeout)
    if ! curl -s -o /dev/null -w "%{http_code}" --max-time "$CURL_TIMEOUT" "$url" >/dev/null 2>&1; then
        log_warning "Cannot reach webhook URL: $url"
    fi
    
    return 0
}

# Validate Cloudflare API credentials
validate_cloudflare_api() {
    log_and_print "Validating Cloudflare API credentials..."
    
    local response
    response=$(curl -s --max-time "$CURL_TIMEOUT" -X GET "https://api.cloudflare.com/client/v4/user" \
        -H "X-Auth-Email: $CF_EMAIL" \
        -H "X-Auth-Key: $CF_API_KEY" \
        -H "Content-Type: application/json" 2>/dev/null)
    
    if [[ -z "$response" ]]; then
        log_error "Failed to connect to Cloudflare API"
        return 1
    fi
    
    if echo "$response" | grep -q '"success":true'; then
        log_success "Cloudflare API credentials validated"
        return 0
    else
        log_error "Invalid Cloudflare API credentials"
        echo -e "${RED}Please check your email and API key${NC}" >&2
        return 1
    fi
}

show_header() {
    if [[ "$QUIET_MODE" != "1" ]]; then
        clear
        echo -e "${BLUE}"
        echo "==============================================="
        echo "     Cloudflare Nginx Automated Setup v${SCRIPT_VERSION}     "
        echo "==============================================="
        echo -e "${NC}"
    fi
    log "Installation started (v${SCRIPT_VERSION})"
}

show_help() {
    cat << EOF
Usage: $0 [options]

Options:
  -d, --domain DOMAIN       Set the domain name (required)
  -p, --port PORT           Set the application port (default: 3000)
  -e, --email EMAIL         Set the Cloudflare email (required)
  -k, --key API_KEY         Set the Cloudflare API key (required)
  -w, --webhook URL         Set the webhook URL
  -m, --webhook-mode MODE   Set webhook mode (S=Success, F=Failure, B=Both)
  -t, --webhook-type TYPE   Set webhook type (D=Discord, S=Slack, G=Google Chat)
  -c, --config FILE         Use configuration file
  -q, --quiet               Run in quiet mode (minimal output)
  --dry-run                 Test run without making changes
  --no-rollback            Disable automatic rollback on failure
  -h, --help                Show this help message

Examples:
  Basic usage:            $0 --domain example.com --port 3000 --email user@example.com --key abc123
  With webhook:           $0 --domain example.com --webhook "https://discord.com/webhook" --webhook-type D
  Dry run:                $0 --domain example.com --email user@example.com --key abc123 --dry-run
  Quiet mode:             $0 --domain example.com --email user@example.com --key abc123 --quiet
EOF
    exit 0
}

# Backup functions
create_backup() {
    local file="$1"
    local backup_name
    
    if [[ ! -f "$file" ]]; then
        return 0
    fi
    
    mkdir -p "$BACKUP_DIR" || {
        log_error "Failed to create backup directory"
        return 1
    }
    
    backup_name="${BACKUP_DIR}/$(basename "$file").$(date +%Y%m%d-%H%M%S).bak"
    
    if cp "$file" "$backup_name"; then
        log_success "Backed up $file to $backup_name"
        echo "$backup_name" >> "${TMP_DIR}/backup_list.txt"
        return 0
    else
        log_error "Failed to backup $file"
        return 1
    fi
}

perform_rollback() {
    log_and_print "Performing rollback..."
    
    if [[ -f "${TMP_DIR}/backup_list.txt" ]]; then
        while IFS= read -r backup_file; do
            if [[ -f "$backup_file" ]]; then
                local original_file
                original_file=$(echo "$backup_file" | sed 's|.*/\(.*\)\..*\.bak$|/etc/nginx/sites-available/\1|')
                
                if cp "$backup_file" "$original_file" 2>/dev/null; then
                    log_success "Restored $original_file"
                fi
            fi
        done < "${TMP_DIR}/backup_list.txt"
    fi
    
    # Reload nginx if it was modified
    if systemctl is-active --quiet nginx; then
        systemctl reload nginx >/dev/null 2>&1 || true
    fi
    
    log_and_print "Rollback completed"
}

# Configuration management
save_config() {
    if [[ $DRY_RUN -eq 1 ]]; then
        log_dry_run "Would save configuration to $CONFIG_FILE"
        return 0
    fi
    
    log_and_print "Saving configuration to $CONFIG_FILE"
    
    mkdir -p "$(dirname "$CONFIG_FILE")" || {
        log_error "Failed to create directory for config file"
        return 1
    }
    
    cat > "$CONFIG_FILE" <<EOF
# CloudflareNginx Configuration
# Generated: $(date)
# Version: $SCRIPT_VERSION
DOMAIN="$DOMAIN"
PORT="$PORT"
CF_EMAIL="$CF_EMAIL"
CF_API_KEY="$CF_API_KEY"
WEBHOOK_URL="$WEBHOOK_URL"
WEBHOOK_MODE="$WEBHOOK_MODE"
WEBHOOK_PLATFORM="$WEBHOOK_PLATFORM"
EOF
    
    chmod 600 "$CONFIG_FILE" || {
        log_error "Failed to set permissions on config file"
        return 1
    }
    
    log_success "Configuration saved successfully"
    return 0
}

# Check certificate expiry
check_certificate_expiry() {
    local domain="$1"
    local cert_path="/etc/letsencrypt/live/$domain/fullchain.pem"
    
    if [[ ! -f "$cert_path" ]]; then
        return 0
    fi
    
    local expiry_date
    expiry_date=$(openssl x509 -enddate -noout -in "$cert_path" 2>/dev/null | cut -d= -f2)
    
    if [[ -n "$expiry_date" ]]; then
        local expiry_epoch
        expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$expiry_date" +%s 2>/dev/null)
        local current_epoch
        current_epoch=$(date +%s)
        local days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
        
        if (( days_left < 30 )); then
            log_warning "Certificate expires in $days_left days"
        else
            log_success "Certificate valid for $days_left more days"
        fi
    fi
}

# Installation functions
install_dependencies() {
    if [[ $DRY_RUN -eq 1 ]]; then
        log_dry_run "Would install dependencies: nginx, python3-certbot-dns-cloudflare, curl, ufw, openssl, jq"
        return 0
    fi
    
    log_and_print "Installing required dependencies..."
    
    local dependencies=(
        nginx
        python3-certbot-dns-cloudflare
        curl
        ufw
        openssl
        jq
        lsof
        host
    )
    
    if ! apt-get update -qq >> "$LOG_FILE" 2>&1; then
        log_error "Failed to update package lists"
        return 1
    fi
    
    if ! apt-get install -y -qq "${dependencies[@]}" >> "$LOG_FILE" 2>&1; then
        log_error "Failed to install dependencies"
        return 1
    fi
    
    log_success "Dependencies installed successfully"
    return 0
}

setup_cloudflare_credentials() {
    local cloudflare_cred_path="/etc/letsencrypt/cloudflare.ini"
    
    if [[ $DRY_RUN -eq 1 ]]; then
        log_dry_run "Would setup Cloudflare credentials at $cloudflare_cred_path"
        return 0
    fi
    
    log_and_print "Setting up Cloudflare credentials..."
    
    mkdir -p "$(dirname "$cloudflare_cred_path")" || {
        log_error "Failed to create directory for Cloudflare credentials"
        return 1
    }
    
    cat > "$cloudflare_cred_path" <<EOF
# Cloudflare API credentials
dns_cloudflare_email = ${CF_EMAIL}
dns_cloudflare_api_key = ${CF_API_KEY}
EOF
    
    chmod 600 "$cloudflare_cred_path" || {
        log_error "Failed to set permissions on Cloudflare credentials"
        return 1
    }
    
    log_success "Cloudflare credentials configured successfully"
    return 0
}

generate_ssl_certificate() {
    if [[ $DRY_RUN -eq 1 ]]; then
        log_dry_run "Would generate SSL certificate for $DOMAIN"
        SSL_SUCCESS=1
        return 0
    fi
    
    log_and_print "Generating SSL certificate for $DOMAIN..."
    
    if certbot certonly --dns-cloudflare \
        --dns-cloudflare-credentials "/etc/letsencrypt/cloudflare.ini" \
        -d "$DOMAIN" \
        --non-interactive \
        --agree-tos \
        --email "$CF_EMAIL" >> "$LOG_FILE" 2>&1; then
        log_success "SSL certificate generated successfully"
        return 0
    else
        log_error "SSL certificate generation failed"
        echo -e "${YELLOW}Check /var/log/letsencrypt/letsencrypt.log for details${NC}"
        return 1
    fi
}

configure_nginx() {
    local domain="$1"
    local port="$2"
    local ssl_success="$3"
    
    if [[ $DRY_RUN -eq 1 ]]; then
        log_dry_run "Would configure Nginx for $domain on port $port"
        return 0
    fi
    
    log_and_print "Configuring Nginx for $domain..."
    
    local nginx_config="/etc/nginx/sites-available/$domain"
    
    # Backup existing configuration if it exists
    if [[ -f "$nginx_config" ]]; then
        create_backup "$nginx_config" || {
            log_error "Failed to backup existing Nginx configuration"
            return 1
        }
    fi
    
    if [[ "$ssl_success" -eq 1 ]]; then
        log_and_print "Creating Nginx configuration with SSL"
        cat > "$nginx_config" <<'EOF'
# Rate limiting
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=api:10m rate=20r/s;
limit_conn_zone $binary_remote_addr zone=addr:10m;

# HTTPS Configuration for DOMAIN_PLACEHOLDER
server {
    listen 80;
    server_name DOMAIN_PLACEHOLDER;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name DOMAIN_PLACEHOLDER;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/DOMAIN_PLACEHOLDER/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/DOMAIN_PLACEHOLDER/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 1.1.1.1 8.8.8.8 valid=300s;
    resolver_timeout 5s;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    # Rate limiting
    limit_req zone=general burst=20 nodelay;
    limit_conn addr 10;

    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }

    # Proxy configuration
    location / {
        limit_req zone=api burst=50 nodelay;
        
        proxy_pass http://127.0.0.1:PORT_PLACEHOLDER;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_buffering off;
        
        # Timeout settings
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        send_timeout 60s;
        
        # Security
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Server $host;
    }

    # Block access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    # Block common attack patterns
    location ~ (\.php|\.aspx|\.asp|\.jsp|\.cgi)$ {
        return 404;
    }
}
EOF
    else
        log_and_print "Creating Nginx configuration without SSL"
        cat > "$nginx_config" <<'EOF'
# Rate limiting
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=api:10m rate=20r/s;
limit_conn_zone $binary_remote_addr zone=addr:10m;

# HTTP Configuration for DOMAIN_PLACEHOLDER
server {
    listen 80;
    server_name DOMAIN_PLACEHOLDER;

    # Basic security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # Rate limiting
    limit_req zone=general burst=20 nodelay;
    limit_conn addr 10;

    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }

    # Proxy configuration
    location / {
        limit_req zone=api burst=50 nodelay;
        
        proxy_pass http://127.0.0.1:PORT_PLACEHOLDER;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeout settings
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        send_timeout 60s;
    }

    # Block access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    # Block common attack patterns
    location ~ (\.php|\.aspx|\.asp|\.jsp|\.cgi)$ {
        return 404;
    }
}
EOF
    fi
    
    # Replace placeholders
    sed -i "s/DOMAIN_PLACEHOLDER/$domain/g" "$nginx_config"
    sed -i "s/PORT_PLACEHOLDER/$port/g" "$nginx_config"
    
    # Enable the site
    ln -sf "$nginx_config" "/etc/nginx/sites-enabled/" || {
        log_error "Failed to enable Nginx site"
        return 1
    }
    
    # Test configuration
    if ! nginx -t >> "$LOG_FILE" 2>&1; then
        log_error "Nginx configuration test failed"
        echo -e "${YELLOW}Check /var/log/nginx/error.log for details${NC}"
        return 1
    fi
    
    # Reload Nginx
    if ! systemctl reload nginx >> "$LOG_FILE" 2>&1; then
        log_error "Failed to reload Nginx"
        return 1
    fi
    
    log_success "Nginx configured successfully"
    return 0
}

setup_firewall() {
    if [[ $DRY_RUN -eq 1 ]]; then
        log_dry_run "Would configure firewall rules"
        return 0
    fi
    
    log_and_print "Configuring firewall..."
    
    if ! command -v ufw >/dev/null 2>&1; then
        log_warning "UFW not found, skipping firewall configuration"
        return 0
    fi
    
    # Enable UFW if not already enabled
    if ! ufw status | grep -q "Status: active"; then
        log_and_print "Enabling UFW firewall"
        echo "y" | ufw enable >> "$LOG_FILE" 2>&1 || {
            log_error "Failed to enable UFW"
            return 1
        }
    fi
    
    # Allow HTTP/HTTPS and SSH
    ufw allow 22/tcp >> "$LOG_FILE" 2>&1
    ufw allow 80/tcp >> "$LOG_FILE" 2>&1
    ufw allow 443/tcp >> "$LOG_FILE" 2>&1
    ufw reload >> "$LOG_FILE" 2>&1
    
    log_success "Firewall configured successfully"
    return 0
}

setup_webhooks() {
    if [[ -z "$WEBHOOK_URL" ]] || [[ $DRY_RUN -eq 1 ]]; then
        if [[ $DRY_RUN -eq 1 ]] && [[ -n "$WEBHOOK_URL" ]]; then
            log_dry_run "Would configure webhook notifications"
        fi
        return 0
    fi
    
    log_and_print "Configuring webhook notifications..."
    
    if ! validate_webhook_url "$WEBHOOK_URL"; then
        log_warning "Invalid webhook URL provided, skipping webhook setup"
        return 0
    fi
    
    mkdir -p /etc/letsencrypt/renewal-hooks/{deploy,post} || {
        log_error "Failed to create renewal hook directories"
        return 1
    }
    
    # Deploy hook (successful renewal) with enhanced security
    cat > /etc/letsencrypt/renewal-hooks/deploy/webhook-notify.sh <<'EOF'
#!/bin/bash
# Webhook notification for successful certificate renewal

WEBHOOK_URL="WEBHOOK_URL_PLACEHOLDER"
WEBHOOK_MODE="WEBHOOK_MODE_PLACEHOLDER"
WEBHOOK_PLATFORM="WEBHOOK_PLATFORM_PLACEHOLDER"
DOMAIN="DOMAIN_PLACEHOLDER"
CURL_TIMEOUT=30

# Function to escape JSON strings
escape_json() {
    local string="$1"
    string="${string//\\/\\\\}"
    string="${string//\"/\\\"}"
    string="${string//$'\n'/\\n}"
    string="${string//$'\r'/\\r}"
    string="${string//$'\t'/\\t}"
    echo "$string"
}

send_discord_webhook() {
    local message
    message=$(escape_json "SSL certificate renewed successfully for $DOMAIN")
    curl -s -X POST -H "Content-Type: application/json" \
    --max-time "$CURL_TIMEOUT" \
    -d "{\"content\": \"$message\", \"embeds\": [{\"title\": \"Certificate Renewal\", \"description\": \"Domain: $DOMAIN\", \"color\": 65280}]}" \
    "$WEBHOOK_URL" >/dev/null 2>&1
}

send_slack_webhook() {
    local message
    message=$(escape_json "SSL certificate renewed successfully for $DOMAIN")
    curl -s -X POST -H "Content-Type: application/json" \
    --max-time "$CURL_TIMEOUT" \
    -d "{\"text\": \"$message\"}" \
    "$WEBHOOK_URL" >/dev/null 2>&1
}

send_googlechat_webhook() {
    local message
    message=$(escape_json "SSL certificate renewed successfully for $DOMAIN")
    curl -s -X POST -H "Content-Type: application/json" \
    --max-time "$CURL_TIMEOUT" \
    -d "{\"text\": \"$message\"}" \
    "$WEBHOOK_URL" >/dev/null 2>&1
}

if [[ "$WEBHOOK_MODE" =~ [SsBb] ]]; then
    case "$WEBHOOK_PLATFORM" in
        D|d) send_discord_webhook ;;
        S|s) send_slack_webhook ;;
        G|g) send_googlechat_webhook ;;
        *) send_discord_webhook ;;
    esac
fi
EOF
    
    # Post hook (failed renewal) with enhanced security
    cat > /etc/letsencrypt/renewal-hooks/post/webhook-notify-failure.sh <<'EOF'
#!/bin/bash
# Webhook notification for failed certificate renewal

WEBHOOK_URL="WEBHOOK_URL_PLACEHOLDER"
WEBHOOK_MODE="WEBHOOK_MODE_PLACEHOLDER"
WEBHOOK_PLATFORM="WEBHOOK_PLATFORM_PLACEHOLDER"
DOMAIN="DOMAIN_PLACEHOLDER"
CURL_TIMEOUT=30

# Function to escape JSON strings
escape_json() {
    local string="$1"
    string="${string//\\/\\\\}"
    string="${string//\"/\\\"}"
    string="${string//$'\n'/\\n}"
    string="${string//$'\r'/\\r}"
    string="${string//$'\t'/\\t}"
    echo "$string"
}

send_discord_webhook() {
    local message
    message=$(escape_json "SSL certificate renewal FAILED for $DOMAIN")
    curl -s -X POST -H "Content-Type: application/json" \
    --max-time "$CURL_TIMEOUT" \
    -d "{\"content\": \"$message\", \"embeds\": [{\"title\": \"Certificate Renewal Failed\", \"description\": \"Domain: $DOMAIN\", \"color\": 16711680}]}" \
    "$WEBHOOK_URL" >/dev/null 2>&1
}

send_slack_webhook() {
    local message
    message=$(escape_json "SSL certificate renewal FAILED for $DOMAIN")
    curl -s -X POST -H "Content-Type: application/json" \
    --max-time "$CURL_TIMEOUT" \
    -d "{\"text\": \"$message\"}" \
    "$WEBHOOK_URL" >/dev/null 2>&1
}

send_googlechat_webhook() {
    local message
    message=$(escape_json "SSL certificate renewal FAILED for $DOMAIN")
    curl -s -X POST -H "Content-Type: application/json" \
    --max-time "$CURL_TIMEOUT" \
    -d "{\"text\": \"$message\"}" \
    "$WEBHOOK_URL" >/dev/null 2>&1
}

if [[ "$WEBHOOK_MODE" =~ [FfBb] ]]; then
    case "$WEBHOOK_PLATFORM" in
        D|d) send_discord_webhook ;;
        S|s) send_slack_webhook ;;
        G|g) send_googlechat_webhook ;;
        *) send_discord_webhook ;;
    esac
fi
EOF
    
    # Replace placeholders
    for file in /etc/letsencrypt/renewal-hooks/deploy/webhook-notify.sh \
                /etc/letsencrypt/renewal-hooks/post/webhook-notify-failure.sh; do
        sed -i "s|WEBHOOK_URL_PLACEHOLDER|$WEBHOOK_URL|g" "$file"
        sed -i "s|WEBHOOK_MODE_PLACEHOLDER|$WEBHOOK_MODE|g" "$file"
        sed -i "s|WEBHOOK_PLATFORM_PLACEHOLDER|$WEBHOOK_PLATFORM|g" "$file"
        sed -i "s|DOMAIN_PLACEHOLDER|$DOMAIN|g" "$file"
    done
    
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/webhook-notify.sh \
             /etc/letsencrypt/renewal-hooks/post/webhook-notify-failure.sh || {
        log_error "Failed to set execute permissions on webhook scripts"
        return 1
    }
    
    log_success "Webhook notifications configured successfully"
    return 0
}

show_summary() {
    if [[ "$QUIET_MODE" = "1" ]]; then
        return
    fi
    
    echo -e "\n${GREEN}=== Installation Summary ===${NC}"
    echo -e "Domain: ${BLUE}$DOMAIN${NC}"
    echo -e "Application Port: ${BLUE}$PORT${NC}"
    echo -e "SSL Certificate: $([ $SSL_SUCCESS -eq 1 ] && echo "${GREEN}Installed${NC}" || echo "${YELLOW}Not Installed${NC}")"
    echo -e "Certificate Renewal: ${GREEN}Configured${NC}"
    
    if [[ -n "$WEBHOOK_URL" ]]; then
        echo -e "Webhook Notifications: ${GREEN}Enabled${NC}"
        echo -e "  - Mode: ${BLUE}$(case "$WEBHOOK_MODE" in
            S|s) echo "Success Only" ;;
            F|f) echo "Failure Only" ;;
            *) echo "Both Success and Failure" ;;
        esac)${NC}"
        echo -e "  - Platform: ${BLUE}$(case "$WEBHOOK_PLATFORM" in
            D|d) echo "Discord" ;;
            S|s) echo "Slack" ;;
            G|g) echo "Google Chat" ;;
            *) echo "Unknown" ;;
        esac)${NC}"
    else
        echo -e "Webhook Notifications: ${YELLOW}Disabled${NC}"
    fi
    
    echo -e "\n${GREEN}Access your application:${NC}"
    if [[ $SSL_SUCCESS -eq 1 ]]; then
        echo -e "  - HTTPS: ${BLUE}https://$DOMAIN${NC}"
        echo -e "  - Health Check: ${BLUE}https://$DOMAIN/health${NC}"
    else
        echo -e "  - HTTP: ${BLUE}http://$DOMAIN${NC}"
        echo -e "  - Health Check: ${BLUE}http://$DOMAIN/health${NC}"
        echo -e "  ${YELLOW}Note: SSL certificate was not installed${NC}"
    fi
    
    echo -e "\n${GREEN}Next steps:${NC}"
    echo -e "1. Configure your application to run on port ${BLUE}$PORT${NC}"
    echo -e "2. Set up monitoring for your domain"
    echo -e "3. Test the health check endpoint"
    
    echo -e "\n${YELLOW}Important files:${NC}"
    echo -e "  - Log file: $LOG_FILE"
    echo -e "  - Configuration: $CONFIG_FILE"
    echo -e "  - Nginx config: /etc/nginx/sites-available/$DOMAIN"
    echo -e "  - Backup directory: $BACKUP_DIR"
    
    if [[ $SSL_SUCCESS -eq 1 ]]; then
        echo -e "\n${GREEN}Certificate information:${NC}"
        echo -e "  - Certificate path: /etc/letsencrypt/live/$DOMAIN/"
        echo -e "  - Auto-renewal: Configured (runs daily)"
        check_certificate_expiry "$DOMAIN"
    fi
    
    if [[ $DRY_RUN -eq 1 ]]; then
        echo -e "\n${YELLOW}This was a DRY RUN - no changes were made${NC}"
    fi
}

# Main function
main() {
    # Check root privileges first
    check_root "$@"
    
    # Create log file
    touch "$LOG_FILE" 2>/dev/null || {
        echo -e "${RED}Failed to create log file${NC}" >&2
        exit 1
    }
    chmod 644 "$LOG_FILE" 2>/dev/null
    
    # Create temp directory
    create_temp_dir
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)
                DOMAIN="$2"
                shift 2
                ;;
            -p|--port)
                PORT="$2"
                shift 2
                ;;
            -e|--email)
                CF_EMAIL="$2"
                shift 2
                ;;
            -k|--key)
                CF_API_KEY="$2"
                shift 2
                ;;
            -w|--webhook)
                WEBHOOK_URL="$2"
                shift 2
                ;;
            -m|--webhook-mode)
                WEBHOOK_MODE="${2^^}"
                shift 2
                ;;
            -t|--webhook-type)
                WEBHOOK_PLATFORM="${2^^}"
                shift 2
                ;;
            -q|--quiet)
                QUIET_MODE="1"
                shift
                ;;
            --dry-run)
                DRY_RUN=1
                shift
                ;;
            --no-rollback)
                ROLLBACK_ENABLED=0
                shift
                ;;
            -h|--help)
                show_help
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}" >&2
                show_help
                exit 1
                ;;
        esac
    done

    show_header
    
    # Validate required parameters
    if [[ -z "$DOMAIN" ]]; then
        log_error "Domain is required"
        exit 1
    else
        validate_domain "$DOMAIN" || exit 1
    fi
    
    if [[ -z "$PORT" ]]; then
        PORT=3000
        log_and_print "Using default port 3000"
    else
        validate_port "$PORT" || exit 1
    fi
    
    if [[ -z "$CF_EMAIL" ]]; then
        log_error "Cloudflare email is required"
        exit 1
    else
        validate_email "$CF_EMAIL" || exit 1
    fi
    
    if [[ -z "$CF_API_KEY" ]]; then
        log_error "Cloudflare API key is required"
        exit 1
    fi

    # Validate webhook URL if provided
    if [[ -n "$WEBHOOK_URL" ]]; then
        validate_webhook_url "$WEBHOOK_URL" || {
            log_error "Invalid webhook URL"
            exit 1
        }
    fi
    
    # Start the installation process
    
    # Save configuration
    if ! save_config; then
        log_warning "Failed to save configuration, continuing anyway"
    fi
    
    # Validate Cloudflare API credentials
    if [[ $DRY_RUN -eq 0 ]]; then
        if ! validate_cloudflare_api; then
            log_error "Cloudflare API validation failed"
            exit 1
        fi
    else
        log_dry_run "Would validate Cloudflare API credentials"
    fi
    
    # Install dependencies
    if ! install_dependencies; then
        log_error "Failed to install required dependencies"
        exit 1
    fi
    
    # Setup Cloudflare credentials
    if ! setup_cloudflare_credentials; then
        log_error "Failed to setup Cloudflare credentials"
        exit 1
    fi
    
    # Generate SSL certificate
    if generate_ssl_certificate; then
        SSL_SUCCESS=1
    else
        log_error "SSL generation failed"
        exit 1
    fi
    
    # Configure Nginx
    if ! configure_nginx "$DOMAIN" "$PORT" "$SSL_SUCCESS"; then
        log_error "Failed to configure Nginx"
        exit 1
    fi
    
    # Setup firewall
    if ! setup_firewall; then
        log_warning "Firewall configuration failed, continuing anyway"
    fi
    
    # Setup webhooks if configured
    if [[ -n "$WEBHOOK_URL" ]]; then
        if ! setup_webhooks; then
            log_warning "Webhook configuration failed, continuing anyway"
        fi
    fi
    
    # Show summary
    show_summary
    
    log_success "Installation completed successfully"
    exit 0
}

# Run main function
main "$@"