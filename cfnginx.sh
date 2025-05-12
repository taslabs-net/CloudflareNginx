#!/bin/bash
# CloudflareNginx Installer v2.0
# Enhanced with better error handling, configuration options, and user experience

# Configuration
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'
LOG_FILE="/var/log/cloudflarenginx-install.log"
CONFIG_FILE="/etc/cloudflarenginx.conf"
TMP_DIR=$(mktemp -d)

# Initialize variables
DOMAIN=""
PORT="3000"
CF_EMAIL=""
CF_API_KEY=""
WEBHOOK_URL=""
WEBHOOK_MODE="B"
WEBHOOK_PLATFORM="D"
SSL_SUCCESS=0
RENEWAL_SUCCESS=0
NON_INTERACTIVE=0
QUIET_MODE=0

# Cleanup function
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Logging functions
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

log_and_print() {
    [ "$QUIET_MODE" -eq 0 ] && echo -e "${BLUE}$1${NC}"
    log "$1"
}

log_success() {
    [ "$QUIET_MODE" -eq 0 ] && echo -e "${GREEN}✓ $1${NC}"
    log "[SUCCESS] $1"
}

log_warning() {
    [ "$QUIET_MODE" -eq 0 ] && echo -e "${YELLOW}⚠ $1${NC}"
    log "[WARNING] $1"
}

log_error() {
    [ "$QUIET_MODE" -eq 0 ] && echo -e "${RED}✗ $1${NC}"
    log "[ERROR] $1"
}

# Helper functions
validate_domain() {
    [[ "$1" =~ ^([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$ ]] || {
        log_error "Invalid domain format: $1"
        return 1
    }
    return 0
}

validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )) || {
        log_error "Invalid port number: $1 (must be 1-65535)"
        return 1
    }
    return 0
}

validate_email() {
    [[ "$1" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || {
        log_error "Invalid email format: $1"
        return 1
    }
    return 0
}

ask_question() {
    local question=$1
    local var_name=$2
    local default_value=${3:-}
    local hide_input=${4:-0}

    [ "$NON_INTERACTIVE" -eq 1 ] && return 0

    echo -e "${BLUE}"
    if [ "$hide_input" -eq 1 ]; then
        read -r -s -p "$question [${default_value}]: " $var_name
    else
        read -r -p "$question [${default_value}]: " $var_name
    fi
    echo -e "${NC}"

    eval "[ -z \"\$$var_name\" ] && $var_name=\"$default_value\""
    log "User input for '$question': ${!var_name}"
}

# Core functions
show_header() {
    [ "$QUIET_MODE" -eq 1 ] && return
    clear
    echo -e "${BLUE}"
    echo "==============================================="
    echo "     Cloudflare Nginx Automated Setup v2.0     "
    echo "==============================================="
    echo -e "${NC}"
    log "CloudflareNginx installation started"
}

show_help() {
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -d, --domain DOMAIN       Set the domain name"
    echo "  -p, --port PORT           Set the application port (default: 3000)"
    echo "  -e, --email EMAIL         Set the Cloudflare email"
    echo "  -k, --key API_KEY         Set the Cloudflare API key"
    echo "  -w, --webhook URL         Set the webhook URL"
    echo "  -m, --webhook-mode MODE   Set webhook mode (S=Success, F=Failure, B=Both)"
    echo "  -t, --webhook-type TYPE   Set webhook type (D=Discord, S=Slack, G=Google Chat)"
    echo "  -c, --config FILE         Use configuration file"
    echo "  -n, --non-interactive     Run in non-interactive mode"
    echo "  -q, --quiet               Run in quiet mode (minimal output)"
    echo "  -h, --help                Show this help message"
    echo
    exit 0
}

load_config() {
    [ -f "$CONFIG_FILE" ] || return 1
    
    log_and_print "Loading configuration from $CONFIG_FILE"
    source "$CONFIG_FILE" || {
        log_error "Failed to load configuration file"
        return 1
    }
    
    # Validate loaded configuration
    validate_domain "$DOMAIN" || return 1
    validate_port "$PORT" || return 1
    validate_email "$CF_EMAIL" || return 1
    [ -n "$CF_API_KEY" ] || {
        log_error "Cloudflare API key not set in config"
        return 1
    }
    
    return 0
}

save_config() {
    log_and_print "Saving configuration to $CONFIG_FILE"
    cat > "$CONFIG_FILE" <<EOF
# CloudflareNginx Configuration
DOMAIN="$DOMAIN"
PORT="$PORT"
CF_EMAIL="$CF_EMAIL"
CF_API_KEY="$CF_API_KEY"
WEBHOOK_URL="$WEBHOOK_URL"
WEBHOOK_MODE="$WEBHOOK_MODE"
WEBHOOK_PLATFORM="$WEBHOOK_PLATFORM"
EOF
    
    chmod 600 "$CONFIG_FILE"
    log_success "Configuration saved"
}

install_dependencies() {
    log_and_print "Installing required dependencies..."
    
    local dependencies=(
        nginx
        python3-certbot-dns-cloudflare
        curl
        ufw
        openssl
    )
    
    apt-get update -qq >> "$LOG_FILE" 2>&1
    if ! apt-get install -y -qq "${dependencies[@]}" >> "$LOG_FILE" 2>&1; then
        log_error "Failed to install dependencies"
        return 1
    fi
    
    log_success "Dependencies installed"
    return 0
}

setup_cloudflare_credentials() {
    local cloudflare_cred_path="/etc/letsencrypt/cloudflare.ini"
    
    log_and_print "Setting up Cloudflare credentials..."
    
    mkdir -p "$(dirname "$cloudflare_cred_path")" || {
        log_error "Failed to create directory for Cloudflare credentials"
        return 1
    }
    
    cat > "$cloudflare_cred_path" <<EOF
dns_cloudflare_email = ${CF_EMAIL}
dns_cloudflare_api_key = ${CF_API_KEY}
EOF
    
    chmod 600 "$cloudflare_cred_path" || {
        log_error "Failed to set permissions on Cloudflare credentials"
        return 1
    }
    
    log_success "Cloudflare credentials configured"
    return 0
}

generate_ssl_certificate() {
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
        return 1
    fi
}

configure_nginx() {
    local domain=$1
    local port=$2
    local ssl_success=$3
    
    log_and_print "Configuring Nginx for $domain..."
    
    # Create Nginx configuration
    local nginx_config="/etc/nginx/sites-available/$domain"
    
    if [ "$ssl_success" -eq 1 ]; then
        cat > "$nginx_config" <<EOF
server {
    listen 80;
    server_name $domain;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $domain;

    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;

    location / {
        proxy_pass http://127.0.0.1:$port;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        proxy_buffering off;
    }
}
EOF
    else
        cat > "$nginx_config" <<EOF
server {
    listen 80;
    server_name $domain;

    location / {
        proxy_pass http://127.0.0.1:$port;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF
    fi
    
    # Enable the site
    ln -sf "$nginx_config" "/etc/nginx/sites-enabled/" || {
        log_error "Failed to enable Nginx site"
        return 1
    }
    
    # Test and reload Nginx
    if ! nginx -t >> "$LOG_FILE" 2>&1; then
        log_error "Nginx configuration test failed"
        return 1
    fi
    
    systemctl reload nginx >> "$LOG_FILE" 2>&1 || {
        log_error "Failed to reload Nginx"
        return 1
    }
    
    log_success "Nginx configured successfully"
    return 0
}

setup_firewall() {
    log_and_print "Configuring firewall..."
    
    if ! command -v ufw >/dev/null 2>&1; then
        log_warning "UFW not found, skipping firewall configuration"
        return 0
    fi
    
    ufw allow 80/tcp >> "$LOG_FILE" 2>&1
    ufw allow 443/tcp >> "$LOG_FILE" 2>&1
    ufw reload >> "$LOG_FILE" 2>&1
    
    log_success "Firewall configured"
    return 0
}

setup_webhooks() {
    [ -z "$WEBHOOK_URL" ] && return 0
    
    log_and_print "Configuring webhook notifications..."
    
    mkdir -p /etc/letsencrypt/renewal-hooks/{deploy,post} || {
        log_error "Failed to create renewal hook directories"
        return 1
    }
    
    # Deploy hook (successful renewal)
    cat > /etc/letsencrypt/renewal-hooks/deploy/webhook-notify.sh <<EOF
#!/bin/bash
WEBHOOK_URL="$WEBHOOK_URL"
WEBHOOK_MODE="$WEBHOOK_MODE"
WEBHOOK_PLATFORM="$WEBHOOK_PLATFORM"
DOMAIN="$DOMAIN"

if [[ "\$WEBHOOK_MODE" =~ [SsBb] ]]; then
    case "\$WEBHOOK_PLATFORM" in
        D|d)
            curl -s -X POST -H "Content-Type: application/json" -d '{
                "content": "SSL certificate renewed successfully for $DOMAIN",
                "embeds": [{
                    "title": "Certificate Renewal",
                    "description": "Domain: $DOMAIN",
                    "color": 65280
                }]
            }' "\$WEBHOOK_URL" >/dev/null 2>&1
            ;;
        S|s)
            curl -s -X POST -H "Content-Type: application/json" -d '{
                "text": "SSL certificate renewed successfully for $DOMAIN"
            }' "\$WEBHOOK_URL" >/dev/null 2>&1
            ;;
        G|g)
            curl -s -X POST -H "Content-Type: application/json" -d '{
                "text": "SSL certificate renewed successfully for $DOMAIN"
            }' "\$WEBHOOK_URL" >/dev/null 2>&1
            ;;
    esac
fi
EOF
    
    # Post hook (failed renewal)
    cat > /etc/letsencrypt/renewal-hooks/post/webhook-notify-failure.sh <<EOF
#!/bin/bash
WEBHOOK_URL="$WEBHOOK_URL"
WEBHOOK_MODE="$WEBHOOK_MODE"
WEBHOOK_PLATFORM="$WEBHOOK_PLATFORM"
DOMAIN="$DOMAIN"

if [[ "\$WEBHOOK_MODE" =~ [FfBb] ]]; then
    case "\$WEBHOOK_PLATFORM" in
        D|d)
            curl -s -X POST -H "Content-Type: application/json" -d '{
                "content": "SSL certificate renewal failed for $DOMAIN",
                "embeds": [{
                    "title": "Certificate Renewal Failed",
                    "description": "Domain: $DOMAIN",
                    "color": 16711680
                }]
            }' "\$WEBHOOK_URL" >/dev/null 2>&1
            ;;
        S|s)
            curl -s -X POST -H "Content-Type: application/json" -d '{
                "text": "SSL certificate renewal failed for $DOMAIN"
            }' "\$WEBHOOK_URL" >/dev/null 2>&1
            ;;
        G|g)
            curl -s -X POST -H "Content-Type: application/json" -d '{
                "text": "SSL certificate renewal failed for $DOMAIN"
            }' "\$WEBHOOK_URL" >/dev/null 2>&1
            ;;
    esac
fi
EOF
    
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/webhook-notify.sh \
             /etc/letsencrypt/renewal-hooks/post/webhook-notify-failure.sh || {
        log_error "Failed to set execute permissions on webhook scripts"
        return 1
    }
    
    log_success "Webhook notifications configured"
    return 0
}

test_certificate_renewal() {
    log_and_print "Testing certificate renewal..."
    
    if certbot renew --dry-run >> "$LOG_FILE" 2>&1; then
        log_success "Certificate renewal test successful"
        return 0
    else
        log_warning "Certificate renewal test failed"
        return 1
    fi
}

show_summary() {
    [ "$QUIET_MODE" -eq 1 ] && return
    
    echo -e "\n${GREEN}=== Installation Summary ===${NC}"
    echo -e "Domain: ${BLUE}$DOMAIN${NC}"
    echo -e "Application Port: ${BLUE}$PORT${NC}"
    echo -e "SSL Certificate: $([ $SSL_SUCCESS -eq 1 ] && echo "${GREEN}Installed${NC}" || echo "${YELLOW}Not Installed${NC}")"
    echo -e "Certificate Renewal: $([ $RENEWAL_SUCCESS -eq 1 ] && echo "${GREEN}Configured${NC}" || echo "${YELLOW}Not Tested${NC}")"
    
    if [ -n "$WEBHOOK_URL" ]; then
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
    if [ $SSL_SUCCESS -eq 1 ]; then
        echo -e "  - HTTPS: ${BLUE}https://$DOMAIN${NC}"
    else
        echo -e "  - HTTP: ${BLUE}http://$DOMAIN${NC}"
        echo -e "  ${YELLOW}Note: SSL certificate was not installed${NC}"
    fi
    
    echo -e "\n${YELLOW}Log file: $LOG_FILE${NC}"
    echo -e "${YELLOW}Configuration saved: $CONFIG_FILE${NC}"
}

# Main function
main() {
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
                WEBHOOK_MODE="$2"
                shift 2
                ;;
            -t|--webhook-type)
                WEBHOOK_PLATFORM="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                load_config || exit 1
                ;;
            -n|--non-interactive)
                NON_INTERACTIVE=1
                shift
                ;;
            -q|--quiet)
                QUIET_MODE=1
                shift
                ;;
            -h|--help)
                show_help
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                ;;
        esac
    done

    show_header
    
    # Validate required parameters
    if [ -z "$DOMAIN" ]; then
        [ "$NON_INTERACTIVE" -eq 1 ] && { log_error "Domain is required in non-interactive mode"; exit 1; }
        ask_question "Enter your domain name (e.g., example.com)" DOMAIN
    fi
    validate_domain "$DOMAIN" || exit 1
    
    if [ -z "$PORT" ]; then
        [ "$NON_INTERACTIVE" -eq 1 ] && PORT=3000
        ask_question "Enter your application port" PORT "3000"
    fi
    validate_port "$PORT" || exit 1
    
    if [ -z "$CF_EMAIL" ]; then
        [ "$NON_INTERACTIVE" -eq 1 ] && { log_error "Cloudflare email is required in non-interactive mode"; exit 1; }
        ask_question "Enter your Cloudflare email" CF_EMAIL
    fi
    validate_email "$CF_EMAIL" || exit 1
    
    if [ -z "$CF_API_KEY" ]; then
        [ "$NON_INTERACTIVE" -eq 1 ] && { log_error "Cloudflare API key is required in non-interactive mode"; exit 1; }
        ask_question "Enter your Cloudflare API key" CF_API_KEY "" 1
    fi
    
    # Save configuration
    save_config
    
    # Install dependencies
    install_dependencies || exit 1
    
    # Setup Cloudflare credentials
    setup_cloudflare_credentials || exit 1
    
    # Generate SSL certificate
    if generate_ssl_certificate; then
        SSL_SUCCESS=1
    else
        [ "$NON_INTERACTIVE" -eq 1 ] && exit 1
        ask_question "SSL generation failed. Continue without SSL? (Y/n)" CONTINUE "Y"
        [[ "${CONTINUE,,}" != "y" ]] && exit 1
    fi
    
    # Configure Nginx
    configure_nginx "$DOMAIN" "$PORT" "$SSL_SUCCESS" || exit 1
    
    # Setup firewall
    setup_firewall
    
    # Setup webhooks if configured
    if [ -n "$WEBHOOK_URL" ]; then
        setup_webhooks
    fi
    
    # Test certificate renewal if SSL was successful
    if [ "$SSL_SUCCESS" -eq 1 ]; then
        if test_certificate_renewal; then
            RENEWAL_SUCCESS=1
        else
            log_warning "Certificate renewal test failed (this might be temporary)"
        fi
    fi
    
    # Show summary
    show_summary
}

# Run main function
main "$@"
