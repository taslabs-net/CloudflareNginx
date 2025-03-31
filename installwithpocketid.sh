#!/bin/bash
# CloudflareNginx Installer with WebSocket Support, Persistence, and Fixed Webhook Notifications
# With cleaner output (less verbose)

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

# Create log file and ensure it's writable
touch "$LOG_FILE" 2>/dev/null || true
chmod 644 "$LOG_FILE" 2>/dev/null || true

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

show_header() {
    clear
    echo -e "${BLUE}"
    echo "==============================================="
    echo "        Cloudflare Nginx Automated Setup"
    echo "==============================================="
    echo -e "${NC}"
    log "CloudflareNginx installation started"
}

check_root() {
    [ "$EUID" -eq 0 ] || { log_error "Please run as root"; exit 1; }
}

ask_question() {
    echo -e "${BLUE}"
    read -r -p "$1: " ${2}
    echo -e "${NC}"
    log "User input for '$1': ${!2}"
}

validate_domain() {
    [[ "$1" =~ ^([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$ ]] || {
        log_error "Invalid domain format"; exit 1
    }
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
    apt-get install -y -qq nginx python3-certbot-dns-cloudflare curl ufw >> "$LOG_FILE" 2>&1
    if [ $? -eq 0 ]; then
        log_success "Required components installed"
    else
        log_warning "Some components may not have installed correctly. Check $LOG_FILE for details"
    fi
}

handle_cloudflare_credentials() {
    ask_question "Enter your Cloudflare Email" CF_EMAIL
    ask_question "Enter your Cloudflare API Key" CF_API_KEY
    ask_question "Enter your Hostname (FQDN)" DOMAIN
    
    validate_domain "$DOMAIN"
    
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
            # Test webhook immediately
            if [ -n "$WEBHOOK_URL" ]; then
                log_and_print "Testing webhook on $(case "$WEBHOOK_PLATFORM" in
                    D) echo "Discord" ;;
                    S) echo "Slack" ;;
                    G) echo "Google Chat" ;;
                esac)..."
                
                # Different payload format based on platform
                case "$WEBHOOK_PLATFORM" in
                    D) # Discord
                        TEST_PAYLOAD='{
                            "content": "CloudflareNginx Webhook Test",
                            "embeds": [{
                                "title": "Test Successful",
                                "description": "Testing webhook for domain: '"$DOMAIN"'",
                                "color": 65280
                            }]
                        }'
                        ;;
                    S) # Slack
                        TEST_PAYLOAD='{
                            "text": "CloudflareNginx Webhook Test",
                            "blocks": [
                                {
                                    "type": "section",
                                    "text": {
                                        "type": "mrkdwn",
                                        "text": "*Test Successful*\nTesting webhook for domain: '"$DOMAIN"'"
                                    }
                                }
                            ]
                        }'
                        ;;
                    G) # Google Chat
                        TEST_PAYLOAD='{
                            "text": "CloudflareNginx Webhook Test",
                            "cards": [{
                                "header": {
                                    "title": "Test Successful"
                                },
                                "sections": [{
                                    "widgets": [{
                                        "textParagraph": {
                                            "text": "Testing webhook for domain: '"$DOMAIN"'"
                                        }
                                    }]
                                }]
                            }]
                        }'
                        ;;
                esac
                
                # Send test webhook but redirect detailed output to log file
                HTTP_CODE=$(curl -s -o /tmp/webhook_response -w "%{http_code}" -X POST -H "Content-Type: application/json" \
                          -d "$TEST_PAYLOAD" "$WEBHOOK_URL" 2>> "$LOG_FILE")

                # Log the response and HTTP code
                cat /tmp/webhook_response >> "$LOG_FILE" 2>/dev/null
                echo "Webhook test HTTP response code: $HTTP_CODE" >> "$LOG_FILE"

                # Check if webhook succeeded based on platform and HTTP code
                WEBHOOK_SUCCESS=0
                case "$WEBHOOK_PLATFORM" in
                    D) # Discord - success codes are 204 (no content) or 200 (OK)
                        [[ "$HTTP_CODE" == "204" || "$HTTP_CODE" == "200" ]] && WEBHOOK_SUCCESS=1
                        ;;
                    S) # Slack
                        RESPONSE=$(cat /tmp/webhook_response 2>/dev/null)
                        [[ "$RESPONSE" == "ok" ]] && WEBHOOK_SUCCESS=1
                        ;;
                    G) # Google Chat
                        RESPONSE=$(cat /tmp/webhook_response 2>/dev/null)
                        [[ "$RESPONSE" == *"name"* ]] && WEBHOOK_SUCCESS=1
                        ;;
                esac
                
                if [ $WEBHOOK_SUCCESS -eq 1 ]; then
                    log_success "Webhook test successful"
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

    if [ -n "$WEBHOOK_URL" ]; then
        log "Sending webhook notification: $status - $message"
        
        # Check if should send based on webhook mode
        local should_send=0
        case "$WEBHOOK_MODE" in
            S)
                [[ "$status" == "success" ]] && should_send=1
                ;;
            F)
                [[ "$status" == "failure" ]] && should_send=1
                ;;
            B)
                should_send=1
                ;;
        esac
        
        if [ $should_send -eq 1 ]; then
            # Create payload based on platform
            local PAYLOAD=""
            local SUCCESS_COLOR="65280"  # Green in decimal
            local FAILURE_COLOR="16711680"  # Red in decimal
            local COLOR=$([ "$status" = "success" ] && echo "$SUCCESS_COLOR" || echo "$FAILURE_COLOR")
            
            case "$WEBHOOK_PLATFORM" in
                D) # Discord
                    PAYLOAD='{
                        "content": "'"$message"'",
                        "embeds": [{
                            "title": "CloudNginx '"$status"' Notification",
                            "description": "Domain: '"$DOMAIN"'",
                            "color": '"$COLOR"'
                        }]
                    }'
                    ;;
                S) # Slack
                    PAYLOAD='{
                        "text": "CloudNginx '"$status"' Notification",
                        "blocks": [
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": "*'"$message"'*\nDomain: '"$DOMAIN"'"
                                }
                            }
                        ]
                    }'
                    ;;
                G) # Google Chat
                    PAYLOAD='{
                        "text": "CloudflareNginx '"$status"' Notification",
                        "cards": [{
                            "header": {
                                "title": "CloudflareNginx '"$status"' Notification"
                            },
                            "sections": [{
                                "widgets": [{
                                    "textParagraph": {
                                        "text": "'"$message"'\nDomain: '"$DOMAIN"'"
                                    }
                                }]
                            }]
                        }]
                    }'
                    ;;
            esac
            
            # Send the webhook but log details to file
            curl -s -X POST -H "Content-Type: application/json" -d "$PAYLOAD" "$WEBHOOK_URL" >> "$LOG_FILE" 2>&1
            
            # Log success without showing details
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
    
    if [ "$SSL_SUCCESS" -eq 1 ]; then
        # Create full nginx configuration with SSL
        cat > "/etc/nginx/sites-available/${DOMAIN}" <<EOF
server {
    listen 80;
    server_name ${DOMAIN};
    
    # Redirect HTTP to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name ${DOMAIN};

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;

    # Proxy configuration
    location / {
        proxy_pass http://127.0.0.1:${PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF
    else
        # Create nginx configuration without SSL (HTTP only)
        cat > "/etc/nginx/sites-available/${DOMAIN}" <<EOF
server {
    listen 80;
    server_name ${DOMAIN};
    
    # Proxy configuration
    location / {
        proxy_pass http://127.0.0.1:${PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF
        log_warning "Configured Nginx without SSL due to certificate failure"
    fi

    # Enable site configuration
    ln -sf "/etc/nginx/sites-available/${DOMAIN}" "/etc/nginx/sites-enabled/" >> "$LOG_FILE" 2>&1
    nginx -t >> "$LOG_FILE" 2>&1 && systemctl reload nginx >> "$LOG_FILE" 2>&1
    if [ $? -eq 0 ]; then
        log_success "Nginx configured successfully"
    else
        log_error "Nginx configuration failed! Check $LOG_FILE for details."
        ask_question "Nginx configuration failed. Continue with the remaining setup? (Y/N)" CONTINUE_NGINX_FAIL
        CONTINUE_NGINX_FAIL=$(echo "$CONTINUE_NGINX_FAIL" | tr '[:lower:]' '[:upper:]')
        if [[ "$CONTINUE_NGINX_FAIL" != "Y" ]]; then
            exit 1
        fi
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
    if [ -n "$WEBHOOK_URL" ]; then
        mkdir -p /etc/letsencrypt/renewal-hooks/deploy >> "$LOG_FILE" 2>&1
        mkdir -p /etc/letsencrypt/renewal-hooks/post >> "$LOG_FILE" 2>&1

        # Deploy hook for successful renewals - complete standalone script
        cat > /etc/letsencrypt/renewal-hooks/deploy/webhook-notify.sh <<EOF
#!/bin/bash
# Webhook configuration
WEBHOOK_URL="$WEBHOOK_URL"
WEBHOOK_MODE="$WEBHOOK_MODE"
WEBHOOK_PLATFORM="$WEBHOOK_PLATFORM"
DOMAIN="$DOMAIN"
LOG_FILE="$LOG_FILE"

# Send notification
echo "Sending successful renewal webhook notification for \$DOMAIN" >> "\$LOG_FILE"

if [[ "$WEBHOOK_MODE" == "S" || "$WEBHOOK_MODE" == "B" ]]; then
    case "$WEBHOOK_PLATFORM" in
        D) # Discord
            curl -s -X POST -H "Content-Type: application/json" -d '{
                "content": "SSL certificate renewed successfully for domain: '$DOMAIN'",
                "embeds": [{
                    "title": "CloudflareNginx Success Notification",
                    "description": "Domain: '$DOMAIN'",
                    "color": 65280
                }]
            }' "$WEBHOOK_URL" >> "\$LOG_FILE" 2>&1
            ;;
        S) # Slack
            curl -s -X POST -H "Content-Type: application/json" -d '{
                "text": "CloudflareNginx Success Notification",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*SSL certificate renewed successfully*\nDomain: '$DOMAIN'"
                        }
                    }
                ]
            }' "$WEBHOOK_URL" >> "\$LOG_FILE" 2>&1
            ;;
        G) # Google Chat
            curl -s -X POST -H "Content-Type: application/json" -d '{
                "text": "CloudflareNginx Success Notification",
                "cards": [{
                    "header": {
                        "title": "SSL Certificate Renewed"
                    },
                    "sections": [{
                        "widgets": [{
                            "textParagraph": {
                                "text": "SSL certificate renewed successfully\nDomain: '$DOMAIN'"
                            }
                        }]
                    }]
                }]
            }' "$WEBHOOK_URL" >> "\$LOG_FILE" 2>&1
            ;;
    esac
fi
EOF
        chmod +x /etc/letsencrypt/renewal-hooks/deploy/webhook-notify.sh >> "$LOG_FILE" 2>&1

        # Post hook for failed renewals (runs after all renewal attempts)
        cat > /etc/letsencrypt/renewal-hooks/post/webhook-notify-failure.sh <<EOF
#!/bin/bash
# Webhook configuration
WEBHOOK_URL="$WEBHOOK_URL"
WEBHOOK_MODE="$WEBHOOK_MODE"
WEBHOOK_PLATFORM="$WEBHOOK_PLATFORM"
DOMAIN="$DOMAIN"
LOG_FILE="$LOG_FILE"

# Check if certificate exists and is about to expire (failed renewal)
CERT_FILE="/etc/letsencrypt/live/$DOMAIN/cert.pem"
if [ -f "\$CERT_FILE" ]; then
    EXPIRY=\$(openssl x509 -enddate -noout -in "\$CERT_FILE" | cut -d= -f2)
    EXPIRY_EPOCH=\$(date -d "\$EXPIRY" +%s)
    NOW_EPOCH=\$(date +%s)
    DAYS_LEFT=\$(( (\$EXPIRY_EPOCH - \$NOW_EPOCH) / 86400 ))
    
    # If less than 7 days until expiry, we consider the renewal failed
    if [ \$DAYS_LEFT -lt 7 ]; then
        echo "Certificate has \$DAYS_LEFT days left and renewal likely failed. Sending webhook." >> "\$LOG_FILE"
        
        if [[ "$WEBHOOK_MODE" == "F" || "$WEBHOOK_MODE" == "B" ]]; then
            case "$WEBHOOK_PLATFORM" in
                D) # Discord
                    curl -s -X POST -H "Content-Type: application/json" -d '{
                        "content": "SSL certificate renewal failed for domain: '$DOMAIN'. Certificate will expire in '\$DAYS_LEFT' days",
                        "embeds": [{
                            "title": "CloudflareNginx Failure Alert",
                            "description": "Domain: '$DOMAIN'",
                            "color": 16711680
                        }]
                    }' "$WEBHOOK_URL" >> "\$LOG_FILE" 2>&1
                    ;;
                S) # Slack
                    curl -s -X POST -H "Content-Type: application/json" -d '{
                        "text": "CloudflareNginx Failure Alert",
                        "blocks": [
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": "*SSL certificate renewal failed*\nDomain: '$DOMAIN'\nCertificate will expire in '\$DAYS_LEFT' days"
                                }
                            }
                        ]
                    }' "$WEBHOOK_URL" >> "\$LOG_FILE" 2>&1
                    ;;
                G) # Google Chat
                    curl -s -X POST -H "Content-Type: application/json" -d '{
                        "text": "CloudflareNginx Failure Alert",
                        "cards": [{
                            "header": {
                                "title": "SSL Certificate Renewal Failed"
                            },
                            "sections": [{
                                "widgets": [{
                                    "textParagraph": {
                                        "text": "SSL certificate renewal failed\nDomain: '$DOMAIN'\nCertificate will expire in '\$DAYS_LEFT' days"
                                    }
                                }]
                            }]
                        }]
                    }' "$WEBHOOK_URL" >> "\$LOG_FILE" 2>&1
                    ;;
            esac
        fi
    fi
fi
EOF
        chmod +x /etc/letsencrypt/renewal-hooks/post/webhook-notify-failure.sh >> "$LOG_FILE" 2>&1
        log_success "Webhook renewal hooks configured"
    fi

    # Test renewal - don't fail the script if this fails
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
    handle_cloudflare_credentials
    install_core_dependencies
    
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
    
    ask_question "Enter your application port (default: 3000)" PORT
    PORT=${PORT:-3000}
    
    # Configure nginx with SSL_SUCCESS status
    configure_nginx "$DOMAIN" "$PORT" "$SSL_SUCCESS"
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
    
    # Final success webhook
    if [ "$SSL_SUCCESS" -eq 1 ]; then
        send_webhook "success" "Full CloudflareNginx setup completed successfully for domain: $DOMAIN"
    else
        send_webhook "warning" "CloudflareNginx setup completed with warnings for domain: $DOMAIN (SSL issues encountered)"
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
    echo -e "\n${YELLOW}Detailed logs available at: ${LOG_FILE}${NC}"
}

main
