#!/bin/bash
# CloudflareNginx Installer v2.4
# Non-interactive version with webhook support and robust error handling

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
PORT=""
CF_EMAIL=""
CF_API_KEY=""
WEBHOOK_URL=""
WEBHOOK_MODE="B"
WEBHOOK_PLATFORM="D"
SSL_SUCCESS=0
# Explicitly set QUIET_MODE with explicit type
QUIET_MODE=0

# Cleanup function
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Enhanced logging functions
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Modified logging functions with simplified conditions
log_and_print() {
    if [ "$QUIET_MODE" != "1" ]; then
        echo -e "${BLUE}$1${NC}"
    fi
    log "INFO: $1"
}

log_success() {
    if [ "$QUIET_MODE" != "1" ]; then
        echo -e "${GREEN}✓ $1${NC}"
    fi
    log "SUCCESS: $1"
}

log_warning() {
    if [ "$QUIET_MODE" != "1" ]; then
        echo -e "${YELLOW}⚠ $1${NC}"
    fi
    log "WARNING: $1"
}

log_error() {
    if [ "$QUIET_MODE" != "1" ]; then
        echo -e "${RED}✗ $1${NC}"
    fi
    log "ERROR: $1"
}

# Validation functions
validate_domain() {
    [[ "$1" =~ ^([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$ ]] || {
        log_error "Invalid domain format: $1"
        echo -e "${RED}Please enter a valid domain name (e.g., example.com)${NC}" >&2
        return 1
    }
    return 0
}

validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )) || {
        log_error "Invalid port number: $1"
        echo -e "${RED}Port must be a number between 1 and 65535${NC}" >&2
        return 1
    }
    return 0
}

validate_email() {
    [[ "$1" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || {
        log_error "Invalid email format: $1"
        echo -e "${RED}Please enter a valid email address${NC}" >&2
        return 1
    }
    return 0
}

validate_webhook_url() {
    [[ "$1" =~ ^https?://.+ ]] || {
        log_error "Invalid webhook URL: $1"
        echo -e "${RED}Webhook URL must start with http:// or https://${NC}" >&2
        return 1
    }
    return 0
}

show_header() {
    if [ "$QUIET_MODE" != "1" ]; then
        clear
        echo -e "${BLUE}"
        echo "==============================================="
        echo "     Cloudflare Nginx Automated Setup v2.4     "
        echo "==============================================="
        echo -e "${NC}"
    fi
    log "Installation started"
}

show_help() {
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -d, --domain DOMAIN       Set the domain name (required)"
    echo "  -p, --port PORT           Set the application port (default: 3000)"
    echo "  -e, --email EMAIL         Set the Cloudflare email (required)"
    echo "  -k, --key API_KEY         Set the Cloudflare API key (required)"
    echo "  -w, --webhook URL         Set the webhook URL"
    echo "  -m, --webhook-mode MODE   Set webhook mode (S=Success, F=Failure, B=Both)"
    echo "  -t, --webhook-type TYPE   Set webhook type (D=Discord, S=Slack, G=Google Chat)"
    echo "  -c, --config FILE         Use configuration file"
    echo "  -q, --quiet               Run in quiet mode (minimal output)"
    echo "  -h, --help                Show this help message"
    echo
    echo "Examples:"
    echo "  Basic usage:            $0 --domain example.com --port 3000 --email user@example.com --key abc123"
    echo "  With webhook:           $0 --domain example.com --webhook \"https://discord.com/webhook\" --webhook-type D"
    echo "  Quiet mode:             $0 --domain example.com --email user@example.com --key abc123 --quiet"
    exit 0
}

# Configuration management
save_config() {
    log_and_print "Saving configuration to $CONFIG_FILE"
    
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$CONFIG_FILE")" || {
        log_error "Failed to create directory for config file"
        return 1
    }
    
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
    
    chmod 600 "$CONFIG_FILE" || {
        log_error "Failed to set permissions on config file"
        return 1
    }
    
    log_success "Configuration saved successfully"
    return 0
}

# Installation functions
install_dependencies() {
    log_and_print "Installing required dependencies..."
    
    local dependencies=(
        nginx
        python3-certbot-dns-cloudflare
        curl
        ufw
        openssl
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
    local domain=$1
    local port=$2
    local ssl_success=$3
    
    log_and_print "Configuring Nginx for $domain..."
    
    # Create Nginx configuration
    local nginx_config="/etc/nginx/sites-available/$domain"
    
    if [ "$ssl_success" -eq 1 ]; then
        log_and_print "Creating Nginx configuration with SSL"
        cat > "$nginx_config" <<EOF
# HTTPS Configuration for $domain
server {
    listen 80;
    server_name $domain;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $domain;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 1.1.1.1 8.8.8.8 valid=300s;
    resolver_timeout 5s;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

    # Proxy configuration
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
}
EOF
    else
        log_and_print "Creating Nginx configuration without SSL"
        cat > "$nginx_config" <<EOF
# HTTP Configuration for $domain
server {
    listen 80;
    server_name $domain;

    # Basic security headers
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";

    # Proxy configuration
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
}
EOF
    fi
    
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
    
    # Allow HTTP/HTTPS
    ufw allow 80/tcp >> "$LOG_FILE" 2>&1
    ufw allow 443/tcp >> "$LOG_FILE" 2>&1
    ufw reload >> "$LOG_FILE" 2>&1
    
    log_success "Firewall configured successfully"
    return 0
}

setup_webhooks() {
    # Skip if webhook URL not provided
    if [ -z "$WEBHOOK_URL" ]; then
        return 0
    fi
    
    log_and_print "Configuring webhook notifications..."
    
    # Validate webhook URL
    if ! validate_webhook_url "$WEBHOOK_URL"; then
        log_warning "Invalid webhook URL provided, skipping webhook setup"
        return 0
    fi
    
    # Create renewal hooks directory
    mkdir -p /etc/letsencrypt/renewal-hooks/{deploy,post} || {
        log_error "Failed to create renewal hook directories"
        return 1
    }
    
    # Deploy hook (successful renewal)
    cat > /etc/letsencrypt/renewal-hooks/deploy/webhook-notify.sh <<EOF
#!/bin/bash
# Webhook notification for successful certificate renewal

WEBHOOK_URL="$WEBHOOK_URL"
WEBHOOK_MODE="$WEBHOOK_MODE"
WEBHOOK_PLATFORM="$WEBHOOK_PLATFORM"
DOMAIN="$DOMAIN"

send_discord_webhook() {
    local message="SSL certificate renewed successfully for \$DOMAIN"
    curl -s -X POST -H "Content-Type: application/json" \
    -d '{"content": "'"\$message"'", "embeds": [{"title": "Certificate Renewal", "description": "Domain: '\$DOMAIN'", "color": 65280}]}' \
    "\$WEBHOOK_URL" >/dev/null 2>&1
}

send_slack_webhook() {
    local message="SSL certificate renewed successfully for \$DOMAIN"
    curl -s -X POST -H "Content-Type: application/json" \
    -d '{"text": "'"\$message"'"}' \
    "\$WEBHOOK_URL" >/dev/null 2>&1
}

send_googlechat_webhook() {
    local message="SSL certificate renewed successfully for \$DOMAIN"
    curl -s -X POST -H "Content-Type: application/json" \
    -d '{"text": "'"\$message"'"}' \
    "\$WEBHOOK_URL" >/dev/null 2>&1
}

if [[ "\$WEBHOOK_MODE" =~ [SsBb] ]]; then
    case "\$WEBHOOK_PLATFORM" in
        D|d) send_discord_webhook ;;
        S|s) send_slack_webhook ;;
        G|g) send_googlechat_webhook ;;
        *) send_discord_webhook ;; # Default to Discord
    esac
fi
EOF
    
    # Post hook (failed renewal)
    cat > /etc/letsencrypt/renewal-hooks/post/webhook-notify-failure.sh <<EOF
#!/bin/bash
# Webhook notification for failed certificate renewal

WEBHOOK_URL="$WEBHOOK_URL"
WEBHOOK_MODE="$WEBHOOK_MODE"
WEBHOOK_PLATFORM="$WEBHOOK_PLATFORM"
DOMAIN="$DOMAIN"

send_discord_webhook() {
    local message="SSL certificate renewal FAILED for \$DOMAIN"
    curl -s -X POST -H "Content-Type: application/json" \
    -d '{"content": "'"\$message"'", "embeds": [{"title": "Certificate Renewal Failed", "description": "Domain: '\$DOMAIN'", "color": 16711680}]}' \
    "\$WEBHOOK_URL" >/dev/null 2>&1
}

send_slack_webhook() {
    local message="SSL certificate renewal FAILED for \$DOMAIN"
    curl -s -X POST -H "Content-Type: application/json" \
    -d '{"text": "'"\$message"'"}' \
    "\$WEBHOOK_URL" >/dev/null 2>&1
}

send_googlechat_webhook() {
    local message="SSL certificate renewal FAILED for \$DOMAIN"
    curl -s -X POST -H "Content-Type: application/json" \
    -d '{"text": "'"\$message"'"}' \
    "\$WEBHOOK_URL" >/dev/null 2>&1
}

if [[ "\$WEBHOOK_MODE" =~ [FfBb] ]]; then
    case "\$WEBHOOK_PLATFORM" in
        D|d) send_discord_webhook ;;
        S|s) send_slack_webhook ;;
        G|g) send_googlechat_webhook ;;
        *) send_discord_webhook ;; # Default to Discord
    esac
fi
EOF
    
    # Set execute permissions
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/webhook-notify.sh \
             /etc/letsencrypt/renewal-hooks/post/webhook-notify-failure.sh || {
        log_error "Failed to set execute permissions on webhook scripts"
        return 1
    }
    
    log_success "Webhook notifications configured successfully"
    return 0
}

show_summary() {
    # Skip in quiet mode
    if [ "$QUIET_MODE" = "1" ]; then
        return
    fi
    
    echo -e "\n${GREEN}=== Installation Summary ===${NC}"
    echo -e "Domain: ${BLUE}$DOMAIN${NC}"
    echo -e "Application Port: ${BLUE}$PORT${NC}"
    echo -e "SSL Certificate: $([ $SSL_SUCCESS -eq 1 ] && echo "${GREEN}Installed${NC}" || echo "${YELLOW}Not Installed${NC}")"
    echo -e "Certificate Renewal: ${GREEN}Configured${NC}"
    
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
    
    echo -e "\n${GREEN}Next steps:${NC}"
    echo -e "1. Configure your application to run on port ${BLUE}$PORT${NC}"
    echo -e "2. Set up monitoring for your domain"
    
    echo -e "\n${YELLOW}Important files:${NC}"
    echo -e "  - Log file: $LOG_FILE"
    echo -e "  - Configuration: $CONFIG_FILE"
    echo -e "  - Nginx config: /etc/nginx/sites-available/$DOMAIN"
    
    if [ $SSL_SUCCESS -eq 1 ]; then
        echo -e "\n${GREEN}Certificate information:${NC}"
        echo -e "  - Certificate path: /etc/letsencrypt/live/$DOMAIN/"
        echo -e "  - Auto-renewal: Configured (runs daily)"
    fi
}

# Main function
main() {
    # Create log file
    touch "$LOG_FILE" 2>/dev/null || {
        echo -e "${RED}Failed to create log file${NC}" >&2
        exit 1
    }
    chmod 644 "$LOG_FILE" 2>/dev/null
    
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
                WEBHOOK_MODE="${2^^}" # Convert to uppercase
                shift 2
                ;;
            -t|--webhook-type)
                WEBHOOK_PLATFORM="${2^^}" # Convert to uppercase
                shift 2
                ;;
            -q|--quiet)
                QUIET_MODE="1"
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
    if [ -z "$DOMAIN" ]; then
        log_error "Domain is required"
        exit 1
    else
        validate_domain "$DOMAIN" || exit 1
    fi
    
    if [ -z "$PORT" ]; then
        PORT=3000
        log_and_print "Using default port 3000"
    else
        validate_port "$PORT" || exit 1
    fi
    
    if [ -z "$CF_EMAIL" ]; then
        log_error "Cloudflare email is required"
        exit 1
    else
        validate_email "$CF_EMAIL" || exit 1
    fi
    
    if [ -z "$CF_API_KEY" ]; then
        log_error "Cloudflare API key is required"
        exit 1
    fi

    # Validate webhook URL if provided
    if [ -n "$WEBHOOK_URL" ]; then
        validate_webhook_url "$WEBHOOK_URL" || {
            log_error "Invalid webhook URL"
            exit 1
        }
    fi
    
    # Save configuration
    if ! save_config; then
        log_warning "Failed to save configuration, continuing anyway"
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
    if [ -n "$WEBHOOK_URL" ]; then
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
