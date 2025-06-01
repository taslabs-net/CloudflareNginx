#!/bin/bash
# CloudflareNginx Installer with WebSocket Support, Persistence, and Fixed Webhook Notifications
# PATCHED VERSION - Security hardened with input validation and proper escaping

# Configuration
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'
DEFAULT_PORT="443"
CLOUDFLARE_CRED_PATH="/etc/letsencrypt/cloudflare.ini"
TMP_DIR=$(mktemp -d)
WEBHOOK_URL=""
WEBHOOK_MODE=""
WEBHOOK_PLATFORM="D"  # Default to Discord
LOG_FILE="/var/log/cloudflarenginx-install.log"
CONFIG_FILE="/etc/cloudflarenginx.conf"

# Create log file and ensure it's writable with secure permissions
touch "$LOG_FILE" 2>/dev/null || true
chmod 600 "$LOG_FILE" 2>/dev/null || true

# Backup existing nginx configs before modifications
NGINX_BACKUP_DIR="/etc/nginx/backups/$(date +%Y%m%d_%H%M%S)"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

log() {
    echo "$(date): $1" >> "$LOG_FILE"
}

log_and_print() {
    echo -e "${BLUE}$1${NC}"
    log "$1"
}

log_success() {
    echo -e "${GREEN}✓ $1${NC}"
    log "[SUCCESS] $1"
}

log_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
    log "[WARNING] $1"
}

log_error() {
    echo -e "${RED}✗ $1${NC}"
    log "[ERROR] $1"
}

# Input sanitization functions
sanitize_domain() {
    # Allow only valid domain characters
    echo "$1" | sed 's/[^a-zA-Z0-9.-]//g' | tr '[:upper:]' '[:lower:]'
}

sanitize_email() {
    # Basic email sanitization
    echo "$1" | sed 's/[^a-zA-Z0-9.@_+-]//g'
}

sanitize_api_key() {
    # API keys should only contain alphanumeric and some special chars
    echo "$1" | sed 's/[^a-zA-Z0-9_-]//g'
}

sanitize_port() {
    # Ensure port is numeric only
    echo "$1" | sed 's/[^0-9]//g'
}

validate_url() {
    local url="$1"
    # Check if URL starts with https://
    if [[ ! "$url" =~ ^https:// ]]; then
        return 1
    fi
    # Basic URL validation
    if [[ ! "$url" =~ ^https://[a-zA-Z0-9.-]+(/.*)?$ ]]; then
        return 1
    fi
    return 0
}

escape_json() {
    # Properly escape string for JSON
    printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'
}

show_header() {
    clear
    echo -e "${BLUE}"
    echo "==============================================="
    echo "   Cloudflare Nginx Automated Setup (PATCHED)"
    echo "==============================================="
    echo -e "${NC}"
    log "CloudflareNginx installation started (patched version)"
}

check_root() {
    [ "$EUID" -eq 0 ] || { log_error "Please run as root"; exit 1; }
}

ask_question() {
    echo -e "${BLUE}"
    read -r -p "$1: " ${2}
    echo -e "${NC}"
    # Don't log sensitive data
    if [[ "$1" == *"API Key"* ]] || [[ "$1" == *"password"* ]]; then
        log "User input for '$1': [REDACTED]"
    else
        log "User input for '$1': ${!2}"
    fi
}

validate_domain() {
    local domain="$1"
    # Comprehensive domain validation
    if [[ ! "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        log_error "Invalid domain format"
        return 1
    fi
    # Check domain length
    if [ ${#domain} -gt 253 ]; then
        log_error "Domain name too long (max 253 characters)"
        return 1
    fi
    return 0
}

validate_port() {
    local port="$1"
    # Check if port is numeric
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        log_error "Port must be a number"
        return 1
    fi
    # Check port range
    if (( port < 1 || port > 65535 )); then
        log_error "Port must be between 1 and 65535"
        return 1
    fi
    # Check if port is already in use
    if ss -tuln | grep -q ":$port "; then
        log_warning "Port $port appears to be in use"
    fi
    return 0
}

install_core_dependencies() {
    log_and_print "Updating system packages..."
    apt-get update -qq >> "$LOG_FILE" 2>&1 && apt-get upgrade -y -qq >> "$LOG_FILE" 2>&1
    if [ $? -eq 0 ]; then
        log_success "System packages updated"
    else
        log_warning "Some updates may have failed. Check $LOG_FILE for details"
    fi
    
    log_and_print "Installing required components..."
    # Also install jq for proper JSON handling
    apt-get install -y -qq nginx python3-certbot-dns-cloudflare curl ufw jq >> "$LOG_FILE" 2>&1
    if [ $? -eq 0 ]; then
        log_success "Required components installed"
    else
        log_warning "Some components may not have installed correctly. Check $LOG_FILE for details"
    fi
}

handle_cloudflare_credentials() {
    ask_question "Enter your Cloudflare Email" CF_EMAIL
    CF_EMAIL=$(sanitize_email "$CF_EMAIL")
    
    ask_question "Enter your Cloudflare API Key" CF_API_KEY
    CF_API_KEY=$(sanitize_api_key "$CF_API_KEY")
    
    ask_question "Enter your Hostname (FQDN)" DOMAIN
    DOMAIN=$(sanitize_domain "$DOMAIN")
    
    if ! validate_domain "$DOMAIN"; then
        exit 1
    fi
    
    # Save configuration to persistent file (excluding sensitive data)
    cat > "$CONFIG_FILE" <<EOF
DOMAIN=$DOMAIN
CF_EMAIL=$CF_EMAIL
WEBHOOK_PLATFORM=$WEBHOOK_PLATFORM
WEBHOOK_MODE=$WEBHOOK_MODE
EOF
    chmod 600 "$CONFIG_FILE"
    
    mkdir -p $(dirname "$CLOUDFLARE_CRED_PATH") >> "$LOG_FILE" 2>&1
    cat > "$CLOUDFLARE_CRED_PATH" <<EOF
dns_cloudflare_email = ${CF_EMAIL}
dns_cloudflare_api_key = ${CF_API_KEY}
EOF
    chmod 600 "$CLOUDFLARE_CRED_PATH" >> "$LOG_FILE" 2>&1
    log_success "Cloudflare credentials saved"

    # Ask if the user wants webhook notifications
    ask_question "Do you want a webhook notification? (Y/N)" WEBHOOK_CHOICE
    WEBHOOK_CHOICE=$(echo "$WEBHOOK_CHOICE" | tr '[:lower:]' '[:upper:]')

    if [[ "$WEBHOOK_CHOICE" == "Y" ]]; then
        # Ask for webhook platform
        ask_question "Which webhook platform? (D)Discord, (S)Slack, or (G)Google Chat (default: D)" WEBHOOK_PLATFORM
        WEBHOOK_PLATFORM=${WEBHOOK_PLATFORM:-D}
        WEBHOOK_PLATFORM=$(echo "$WEBHOOK_PLATFORM" | tr '[:lower:]' '[:upper:]')
        
        # Validate platform selection
        if [[ ! "$WEBHOOK_PLATFORM" =~ ^[DSG]$ ]]; then
            log_warning "Invalid platform choice. Defaulting to Discord."
            WEBHOOK_PLATFORM="D"
        fi
        
        echo -e "${BLUE}Selected webhook platform: $(case "$WEBHOOK_PLATFORM" in
            D) echo "Discord" ;;
            S) echo "Slack" ;;
            G) echo "Google Chat" ;;
        esac)${NC}"
        
        ask_question "Do you want notifications for (S)Success, (F)Failure, or (B)Both? (default: B)" WEBHOOK_MODE
        WEBHOOK_MODE=${WEBHOOK_MODE:-B}
        WEBHOOK_MODE=$(echo "$WEBHOOK_MODE" | tr '[:lower:]' '[:upper:]')

        if [[ "$WEBHOOK_MODE" =~ ^[SBF]$ ]]; then
            ask_question "Webhook URL?" WEBHOOK_URL
            
            # Validate webhook URL
            if ! validate_url "$WEBHOOK_URL"; then
                log_error "Invalid webhook URL. Must start with https://"
                WEBHOOK_URL=""
            else
                # Test webhook immediately
                log_and_print "Testing webhook on $(case "$WEBHOOK_PLATFORM" in
                    D) echo "Discord" ;;
                    S) echo "Slack" ;;
                    G) echo "Google Chat" ;;
                esac)..."
                
                # Use jq for safe JSON creation
                local test_message="Testing webhook for domain: $DOMAIN"
                local TEST_PAYLOAD=""
                
                case "$WEBHOOK_PLATFORM" in
                    D) # Discord
                        TEST_PAYLOAD=$(jq -n \
                            --arg content "CloudflareNginx Webhook Test" \
                            --arg title "Test Successful" \
                            --arg desc "$test_message" \
                            '{
                                content: $content,
                                embeds: [{
                                    title: $title,
                                    description: $desc,
                                    color: 65280
                                }]
                            }')
                        ;;
                    S) # Slack
                        TEST_PAYLOAD=$(jq -n \
                            --arg text "CloudflareNginx Webhook Test" \
                            --arg msg "$test_message" \
                            '{
                                text: $text,
                                blocks: [{
                                    type: "section",
                                    text: {
                                        type: "mrkdwn",
                                        text: ("*Test Successful*\n" + $msg)
                                    }
                                }]
                            }')
                        ;;
                    G) # Google Chat
                        TEST_PAYLOAD=$(jq -n \
                            --arg text "CloudflareNginx Webhook Test" \
                            --arg msg "$test_message" \
                            '{
                                text: $text,
                                cards: [{
                                    header: {
                                        title: "Test Successful"
                                    },
                                    sections: [{
                                        widgets: [{
                                            textParagraph: {
                                                text: $msg
                                            }
                                        }]
                                    }]
                                }]
                            }')
                        ;;
                esac
                
                # Send test webhook
                HTTP_CODE=$(curl -s -o /tmp/webhook_response -w "%{http_code}" -X POST -H "Content-Type: application/json" \
                          -d "$TEST_PAYLOAD" "$WEBHOOK_URL" 2>> "$LOG_FILE")

                # Log the response and HTTP code
                cat /tmp/webhook_response >> "$LOG_FILE" 2>/dev/null
                echo "Webhook test HTTP response code: $HTTP_CODE" >> "$LOG_FILE"

                # Check if webhook succeeded
                WEBHOOK_SUCCESS=0
                case "$WEBHOOK_PLATFORM" in
                    D) [[ "$HTTP_CODE" == "204" || "$HTTP_CODE" == "200" ]] && WEBHOOK_SUCCESS=1 ;;
                    S) [[ $(cat /tmp/webhook_response 2>/dev/null) == "ok" ]] && WEBHOOK_SUCCESS=1 ;;
                    G) [[ $(cat /tmp/webhook_response 2>/dev/null) == *"name"* ]] && WEBHOOK_SUCCESS=1 ;;
                esac
                
                if [ $WEBHOOK_SUCCESS -eq 1 ]; then
                    log_success "Webhook test successful"
                    # Save webhook URL to config
                    echo "WEBHOOK_URL=$WEBHOOK_URL" >> "$CONFIG_FILE"
                else
                    log_warning "Webhook test might have failed. Check $LOG_FILE for details"
                    ask_question "Continue anyway? (Y/N)" CONTINUE
                    if [[ "${CONTINUE^^}" != "Y" ]]; then
                        exit 1
                    fi
                fi
            fi
        else
            log_warning "Invalid choice. Webhook notifications will not be configured."
        fi
    else
        log_and_print "Webhook notifications will not be configured."
    fi
}

send_webhook() {
    local status=$1
    local message=$2

    if [ -n "$WEBHOOK_URL" ] && validate_url "$WEBHOOK_URL"; then
        log "Sending webhook notification: $status - $message"
        
        # Check if should send based on webhook mode
        local should_send=0
        case "$WEBHOOK_MODE" in
            S) [[ "$status" == "success" ]] && should_send=1 ;;
            F) [[ "$status" == "failure" ]] && should_send=1 ;;
            B) should_send=1 ;;
        esac
        
        if [ $should_send -eq 1 ]; then
            # Create payload using jq for proper escaping
            local PAYLOAD=""
            local SUCCESS_COLOR="65280"
            local FAILURE_COLOR="16711680"
            local COLOR=$([ "$status" = "success" ] && echo "$SUCCESS_COLOR" || echo "$FAILURE_COLOR")
            
            case "$WEBHOOK_PLATFORM" in
                D) # Discord
                    PAYLOAD=$(jq -n \
                        --arg content "$message" \
                        --arg status "$status" \
                        --arg domain "$DOMAIN" \
                        --arg color "$COLOR" \
                        '{
                            content: $content,
                            embeds: [{
                                title: ("CloudNginx " + $status + " Notification"),
                                description: ("Domain: " + $domain),
                                color: ($color | tonumber)
                            }]
                        }')
                    ;;
                S) # Slack
                    PAYLOAD=$(jq -n \
                        --arg status "$status" \
                        --arg message "$message" \
                        --arg domain "$DOMAIN" \
                        '{
                            text: ("CloudNginx " + $status + " Notification"),
                            blocks: [{
                                type: "section",
                                text: {
                                    type: "mrkdwn",
                                    text: ("*" + $message + "*\nDomain: " + $domain)
                                }
                            }]
                        }')
                    ;;
                G) # Google Chat
                    PAYLOAD=$(jq -n \
                        --arg status "$status" \
                        --arg message "$message" \
                        --arg domain "$DOMAIN" \
                        '{
                            text: ("CloudflareNginx " + $status + " Notification"),
                            cards: [{
                                header: {
                                    title: ("CloudflareNginx " + $status + " Notification")
                                },
                                sections: [{
                                    widgets: [{
                                        textParagraph: {
                                            text: ($message + "\nDomain: " + $domain)
                                        }
                                    }]
                                }]
                            }]
                        }')
                    ;;
            esac
            
            # Send the webhook
            curl -s -X POST -H "Content-Type: application/json" -d "$PAYLOAD" "$WEBHOOK_URL" >> "$LOG_FILE" 2>&1
            
            if [ "$status" == "success" ]; then
                log_success "Webhook notification sent"
            else
                log_warning "Webhook failure notification sent"
            fi
        fi
    fi
}

generate_ssl() {
    log_and_print "Generating SSL certificate..."
    if certbot certonly --dns-cloudflare \
        --dns-cloudflare-credentials "$CLOUDFLARE_CRED_PATH" \
        -d "$DOMAIN" \
        --non-interactive \
        --agree-tos \
        --email "$CF_EMAIL" >> "$LOG_FILE" 2>&1; then
        log_success "SSL certificate generated successfully!"
        send_webhook "success" "SSL certificate generated successfully for domain: $DOMAIN"
        return 0
    else
        log_error "SSL certificate generation failed!"
        send_webhook "failure" "SSL certificate generation failed for domain: $DOMAIN"
        # Ask if user wants to continue setup despite SSL failure
        ask_question "SSL certificate generation failed! Continue with the setup anyway? (Y/N)" CONTINUE_SSL_FAIL
        CONTINUE_SSL_FAIL=$(echo "$CONTINUE_SSL_FAIL" | tr '[:lower:]' '[:upper:]')
        if [[ "$CONTINUE_SSL_FAIL" == "Y" ]]; then
            log_warning "Continuing setup despite SSL certificate failure"
            return 1
        else
            log_error "Setup aborted due to SSL certificate failure"
            exit 1
        fi
    fi
}

configure_nginx() {
    local DOMAIN=$1
    local PORT=$2
    local SSL_SUCCESS=$3
    
    log_and_print "Configuring NGINX for ${DOMAIN}..."
    
    # Create backup directory
    mkdir -p "$NGINX_BACKUP_DIR"
    
    # Backup existing config if it exists
    if [ -f "/etc/nginx/sites-available/${DOMAIN}" ]; then
        cp "/etc/nginx/sites-available/${DOMAIN}" "$NGINX_BACKUP_DIR/${DOMAIN}.bak"
        log_and_print "Backed up existing nginx config"
    fi
    
    # Create nginx configuration with escaped variables
    if [ "$SSL_SUCCESS" -eq 1 ]; then
        # Create full nginx configuration with SSL
        cat > "/etc/nginx/sites-available/${DOMAIN}" <<'EOF'
server {
    listen 80;
    server_name DOMAIN_PLACEHOLDER;
    
    # Redirect HTTP to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name DOMAIN_PLACEHOLDER;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/DOMAIN_PLACEHOLDER/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/DOMAIN_PLACEHOLDER/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/letsencrypt/live/DOMAIN_PLACEHOLDER/chain.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Proxy configuration
    location / {
        proxy_pass http://127.0.0.1:PORT_PLACEHOLDER;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_cache_bypass $http_upgrade;
        proxy_buffering off;
    }
}
EOF
    else
        # Create nginx configuration without SSL (HTTP only)
        cat > "/etc/nginx/sites-available/${DOMAIN}" <<'EOF'
server {
    listen 80;
    server_name DOMAIN_PLACEHOLDER;
    
    # Proxy configuration
    location / {
        proxy_pass http://127.0.0.1:PORT_PLACEHOLDER;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
EOF
        log_warning "Configured Nginx without SSL due to certificate failure"
    fi

    # Replace placeholders with actual values (safely)
    sed -i "s/DOMAIN_PLACEHOLDER/${DOMAIN}/g" "/etc/nginx/sites-available/${DOMAIN}"
    sed -i "s/PORT_PLACEHOLDER/${PORT}/g" "/etc/nginx/sites-available/${DOMAIN}"

    # Enable site configuration
    ln -sf "/etc/nginx/sites-available/${DOMAIN}" "/etc/nginx/sites-enabled/" >> "$LOG_FILE" 2>&1
    
    # Test nginx configuration before reloading
    if nginx -t >> "$LOG_FILE" 2>&1; then
        systemctl reload nginx >> "$LOG_FILE" 2>&1
        if [ $? -eq 0 ]; then
            log_success "Nginx configured successfully"
            return 0
        else
            log_error "Nginx reload failed!"
            # Attempt to restore backup
            if [ -f "$NGINX_BACKUP_DIR/${DOMAIN}.bak" ]; then
                cp "$NGINX_BACKUP_DIR/${DOMAIN}.bak" "/etc/nginx/sites-available/${DOMAIN}"
                nginx -t && systemctl reload nginx
                log_warning "Restored previous nginx configuration"
            fi
            return 1
        fi
    else
        log_error "Nginx configuration test failed! Check $LOG_FILE for details."
        rm -f "/etc/nginx/sites-enabled/${DOMAIN}"
        return 1
    fi
}

configure_firewall() {
    log_and_print "Configuring firewall..."
    if command -v ufw >/dev/null 2>&1; then
        ufw allow 80/tcp >> "$LOG_FILE" 2>&1
        ufw allow 443/tcp >> "$LOG_FILE" 2>&1
        ufw reload >> "$LOG_FILE" 2>&1
        log_success "Firewall rules added"
    else
        log_warning "UFW not found, firewall not configured"
    fi
}

ensure_service_persistence() {
    log_and_print "Ensuring service persistence..."
    
    # Enable and start Nginx if not already active
    if ! systemctl is-active --quiet nginx; then
        systemctl enable --now nginx >> "$LOG_FILE" 2>&1
    fi
    
    # Enable Certbot renewal timer
    if systemctl list-timers | grep -q certbot; then
        systemctl enable --now certbot.timer >> "$LOG_FILE" 2>&1
    fi
    
    log_success "Services configured for auto-start"
}

setup_certbot_renewal() {
    log_and_print "Setting up Certbot renewal..."
    
    # Create renewal hooks if webhook is enabled
    if [ -n "$WEBHOOK_URL" ] && validate_url "$WEBHOOK_URL"; then
        mkdir -p /etc/letsencrypt/renewal-hooks/deploy >> "$LOG_FILE" 2>&1
        mkdir -p /etc/letsencrypt/renewal-hooks/post >> "$LOG_FILE" 2>&1

        # Deploy hook for successful renewals
        cat > /etc/letsencrypt/renewal-hooks/deploy/webhook-notify.sh <<'EOFHOOK'
#!/bin/bash
# Load configuration
source /etc/cloudflarenginx.conf 2>/dev/null || exit 1

# Webhook configuration from config file
LOG_FILE="/var/log/cloudflarenginx-install.log"

# Function to validate URL
validate_url() {
    [[ "$1" =~ ^https:// ]]
}

# Send notification
echo "Sending successful renewal webhook notification for $DOMAIN" >> "$LOG_FILE"

if [[ "$WEBHOOK_MODE" == "S" || "$WEBHOOK_MODE" == "B" ]] && validate_url "$WEBHOOK_URL"; then
    MESSAGE="SSL certificate renewed successfully for domain: $DOMAIN"
    
    case "$WEBHOOK_PLATFORM" in
        D) # Discord
            PAYLOAD=$(jq -n \
                --arg content "$MESSAGE" \
                --arg domain "$DOMAIN" \
                '{
                    content: $content,
                    embeds: [{
                        title: "CloudflareNginx Success Notification",
                        description: ("Domain: " + $domain),
                        color: 65280
                    }]
                }')
            ;;
        S) # Slack
            PAYLOAD=$(jq -n \
                --arg message "$MESSAGE" \
                --arg domain "$DOMAIN" \
                '{
                    text: "CloudflareNginx Success Notification",
                    blocks: [{
                        type: "section",
                        text: {
                            type: "mrkdwn",
                            text: ("*" + $message + "*\nDomain: " + $domain)
                        }
                    }]
                }')
            ;;
        G) # Google Chat
            PAYLOAD=$(jq -n \
                --arg message "$MESSAGE" \
                --arg domain "$DOMAIN" \
                '{
                    text: "CloudflareNginx Success Notification",
                    cards: [{
                        header: {
                            title: "SSL Certificate Renewed"
                        },
                        sections: [{
                            widgets: [{
                                textParagraph: {
                                    text: ($message + "\nDomain: " + $domain)
                                }
                            }]
                        }]
                    }]
                }')
            ;;
    esac
    
    if [ -n "$PAYLOAD" ]; then
        curl -s -X POST -H "Content-Type: application/json" -d "$PAYLOAD" "$WEBHOOK_URL" >> "$LOG_FILE" 2>&1
    fi
fi
EOFHOOK
        chmod +x /etc/letsencrypt/renewal-hooks/deploy/webhook-notify.sh >> "$LOG_FILE" 2>&1

        # Post hook for failed renewals
        cat > /etc/letsencrypt/renewal-hooks/post/webhook-notify-failure.sh <<'EOFHOOK'
#!/bin/bash
# Load configuration
source /etc/cloudflarenginx.conf 2>/dev/null || exit 1

LOG_FILE="/var/log/cloudflarenginx-install.log"

# Function to validate URL
validate_url() {
    [[ "$1" =~ ^https:// ]]
}

# Check if certificate exists and is about to expire
CERT_FILE="/etc/letsencrypt/live/$DOMAIN/cert.pem"
if [ -f "$CERT_FILE" ]; then
    EXPIRY=$(openssl x509 -enddate -noout -in "$CERT_FILE" | cut -d= -f2)
    EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$EXPIRY" +%s)
    NOW_EPOCH=$(date +%s)
    DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
    
    # If less than 7 days until expiry, renewal likely failed
    if [ $DAYS_LEFT -lt 7 ]; then
        echo "Certificate has $DAYS_LEFT days left and renewal likely failed. Sending webhook." >> "$LOG_FILE"
        
        if [[ "$WEBHOOK_MODE" == "F" || "$WEBHOOK_MODE" == "B" ]] && validate_url "$WEBHOOK_URL"; then
            MESSAGE="SSL certificate renewal failed for domain: $DOMAIN. Certificate will expire in $DAYS_LEFT days"
            
            case "$WEBHOOK_PLATFORM" in
                D) # Discord
                    PAYLOAD=$(jq -n \
                        --arg content "$MESSAGE" \
                        --arg domain "$DOMAIN" \
                        --argjson days "$DAYS_LEFT" \
                        '{
                            content: $content,
                            embeds: [{
                                title: "CloudflareNginx Failure Alert",
                                description: ("Domain: " + $domain + "\nDays until expiry: " + ($days | tostring)),
                                color: 16711680
                            }]
                        }')
                    ;;
                S) # Slack
                    PAYLOAD=$(jq -n \
                        --arg message "$MESSAGE" \
                        --arg domain "$DOMAIN" \
                        --argjson days "$DAYS_LEFT" \
                        '{
                            text: "CloudflareNginx Failure Alert",
                            blocks: [{
                                type: "section",
                                text: {
                                    type: "mrkdwn",
                                    text: ("*" + $message + "*\nDomain: " + $domain + "\nDays until expiry: " + ($days | tostring))
                                }
                            }]
                        }')
                    ;;
                G) # Google Chat
                    PAYLOAD=$(jq -n \
                        --arg message "$MESSAGE" \
                        --arg domain "$DOMAIN" \
                        --argjson days "$DAYS_LEFT" \
                        '{
                            text: "CloudflareNginx Failure Alert",
                            cards: [{
                                header: {
                                    title: "SSL Certificate Renewal Failed"
                                },
                                sections: [{
                                    widgets: [{
                                        textParagraph: {
                                            text: ($message + "\nDomain: " + $domain + "\nDays until expiry: " + ($days | tostring))
                                        }
                                    }]
                                }]
                            }]
                        }')
                    ;;
            esac
            
            if [ -n "$PAYLOAD" ]; then
                curl -s -X POST -H "Content-Type: application/json" -d "$PAYLOAD" "$WEBHOOK_URL" >> "$LOG_FILE" 2>&1
            fi
        fi
    fi
fi
EOFHOOK
        chmod +x /etc/letsencrypt/renewal-hooks/post/webhook-notify-failure.sh >> "$LOG_FILE" 2>&1
        log_success "Webhook renewal hooks configured"
    fi

    # Test renewal
    log_and_print "Testing certificate renewal..."
    if certbot renew --dry-run >> "$LOG_FILE" 2>&1; then
        log_success "Certificate renewal configured successfully"
        send_webhook "success" "Certificate renewal system configured successfully for domain: $DOMAIN"
        return 0
    else
        log_warning "Certificate renewal test failed! Check $LOG_FILE for details. Continuing setup anyway."
        send_webhook "failure" "Certificate renewal configuration failed for domain: $DOMAIN, but setup will continue"
        return 1
    fi
}

main() {
    show_header
    check_root
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
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
            -q|--quiet)
                QUIET_MODE=1
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [options]"
                echo "Options:"
                echo "  -d, --domain DOMAIN          Domain name (required)"
                echo "  -p, --port PORT              Application port (default: 3000)"
                echo "  -e, --email EMAIL            Cloudflare email (required)"
                echo "  -k, --key KEY                Cloudflare API key (required)"
                echo "  -w, --webhook URL            Webhook URL"
                echo "  -m, --webhook-mode MODE      S=Success, F=Failure, B=Both (default: B)"
                echo "  -t, --webhook-type TYPE      D=Discord, S=Slack, G=Google Chat (default: D)"
                echo "  -q, --quiet                  Minimal output"
                echo "  -h, --help                   Show this help"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # If arguments provided, validate them
    if [ -n "$DOMAIN" ] || [ -n "$CF_EMAIL" ] || [ -n "$CF_API_KEY" ]; then
        # Sanitize and validate provided arguments
        [ -n "$DOMAIN" ] && DOMAIN=$(sanitize_domain "$DOMAIN")
        [ -n "$CF_EMAIL" ] && CF_EMAIL=$(sanitize_email "$CF_EMAIL")
        [ -n "$CF_API_KEY" ] && CF_API_KEY=$(sanitize_api_key "$CF_API_KEY")
        [ -n "$PORT" ] && PORT=$(sanitize_port "$PORT")
        
        # Validate required fields
        if [ -z "$DOMAIN" ] || [ -z "$CF_EMAIL" ] || [ -z "$CF_API_KEY" ]; then
            log_error "Domain, email, and API key are required when using command line arguments"
            exit 1
        fi
        
        if ! validate_domain "$DOMAIN"; then
            exit 1
        fi
        
        # Save credentials
        mkdir -p $(dirname "$CLOUDFLARE_CRED_PATH") >> "$LOG_FILE" 2>&1
        cat > "$CLOUDFLARE_CRED_PATH" <<EOF
dns_cloudflare_email = ${CF_EMAIL}
dns_cloudflare_api_key = ${CF_API_KEY}
EOF
        chmod 600 "$CLOUDFLARE_CRED_PATH" >> "$LOG_FILE" 2>&1
        
        # Validate webhook if provided
        if [ -n "$WEBHOOK_URL" ] && ! validate_url "$WEBHOOK_URL"; then
            log_error "Invalid webhook URL"
            exit 1
        fi
    else
        # Interactive mode
        handle_cloudflare_credentials
    fi
    
    install_core_dependencies
    
    # Validate port early
    if [ -z "$PORT" ]; then
        ask_question "Enter your application port (default: 3000)" PORT
        PORT=${PORT:-3000}
    fi
    PORT=$(sanitize_port "$PORT")
    
    if ! validate_port "$PORT"; then
        exit 1
    fi
    
    # Track SSL success/failure
    SSL_SUCCESS=1
    if ! generate_ssl; then
        SSL_SUCCESS=0
    fi
    
    # Setup renewal hooks regardless of SSL success
    RENEWAL_SUCCESS=1
    if ! setup_certbot_renewal; then
        RENEWAL_SUCCESS=0
    fi
    
    # Configure nginx with SSL_SUCCESS status
    NGINX_SUCCESS=1
    if ! configure_nginx "$DOMAIN" "$PORT" "$SSL_SUCCESS"; then
        NGINX_SUCCESS=0
        ask_question "Nginx configuration failed. Continue with the remaining setup? (Y/N)" CONTINUE_NGINX_FAIL
        CONTINUE_NGINX_FAIL=$(echo "$CONTINUE_NGINX_FAIL" | tr '[:lower:]' '[:upper:]')
        if [[ "$CONTINUE_NGINX_FAIL" != "Y" ]]; then
            exit 1
        fi
    fi
    
    configure_firewall
    ensure_service_persistence
    
    # Final status message
    log_success "Setup completed!"
    
    if [ "$SSL_SUCCESS" -eq 1 ]; then
        echo -e "${GREEN}Access your site at: https://${DOMAIN}${NC}"
    else
        echo -e "${YELLOW}Access your site at: http://${DOMAIN}${NC}"
        echo -e "${YELLOW}Note: SSL was not configured successfully.${NC}"
    fi
    
    if [ "$RENEWAL_SUCCESS" -eq 0 ]; then
        echo -e "${YELLOW}Certificate renewal test failed, but setup continued.${NC}"
    fi
    
    if [ "$NGINX_SUCCESS" -eq 0 ]; then
        echo -e "${YELLOW}Nginx configuration had issues. Please check manually.${NC}"
    fi
    
    # Final success webhook
    if [ "$SSL_SUCCESS" -eq 1 ] && [ "$NGINX_SUCCESS" -eq 1 ]; then
        send_webhook "success" "Full CloudflareNginx setup completed successfully for domain: $DOMAIN"
    else
        send_webhook "warning" "CloudflareNginx setup completed with warnings for domain: $DOMAIN"
    fi
    
    # Display important information
    echo -e "\n${BLUE}Important Notes:${NC}"
    echo -e "1. Your Cloudflare credentials are stored securely at ${CLOUDFLARE_CRED_PATH}"
    
    if [ "$SSL_SUCCESS" -eq 1 ]; then
        echo -e "2. SSL certificates will auto-renew before expiration"
        if [ "$RENEWAL_SUCCESS" -eq 0 ]; then
            echo -e "   - Warning: Renewal test failed, but this might be a temporary issue"
        fi
    else
        echo -e "2. SSL certificates were not configured successfully"
    fi
    
    echo -e "3. Nginx is configured to start automatically on boot"
    echo -e "4. Firewall rules (if UFW is present) are persistent"
    if [ -n "$WEBHOOK_URL" ]; then
        echo -e "5. Webhook notifications are enabled for: $WEBHOOK_MODE"
        echo -e "   - Webhook Platform: $(case "$WEBHOOK_PLATFORM" in
            D) echo "Discord" ;;
            S) echo "Slack" ;;
            G) echo "Google Chat" ;;
        esac)"
    fi
    echo -e "6. Configuration saved at: ${CONFIG_FILE}"
    echo -e "7. Nginx backups stored at: /etc/nginx/backups/"
    echo -e "\n${YELLOW}Detailed logs available at: ${LOG_FILE}${NC}"
}

main "$@"