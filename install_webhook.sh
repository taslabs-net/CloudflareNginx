#!/bin/bash
# CloudNginx Installer with WebSocket Support, Persistence, and Fixed Webhook Notifications

# Configuration
BLUE='\033[0;34m'
NC='\033[0m'
DEFAULT_PORT="443"
CLOUDFLARE_CRED_PATH="/etc/letsencrypt/cloudflare.ini"
TMP_DIR=$(mktemp -d)
WEBHOOK_URL=""
WEBHOOK_MODE=""
WEBHOOK_PLATFORM="D"  # Default to Discord

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

show_header() {
    clear
    echo -e "${BLUE}"
    echo "==============================================="
    echo "        Cloudflare Nginx Automated Setup"
    echo "==============================================="
    echo -e "${NC}"
}

check_root() {
    [ "$EUID" -eq 0 ] || { echo "Please run as root"; exit 1; }
}

ask_question() {
    echo -e "${BLUE}"
    read -r -p "$1: " ${2}
    echo -e "${NC}"
}

validate_domain() {
    [[ "$1" =~ ^([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$ ]] || {
        echo "Invalid domain format"; exit 1
    }
}

install_core_dependencies() {
    echo -e "${BLUE}Updating system packages...${NC}"
    apt-get update -qq && apt-get upgrade -y -qq
    
    echo -e "${BLUE}Installing required components...${NC}"
    apt-get install -y -qq \
        nginx \
        python3-certbot-dns-cloudflare \
        curl \
        ufw
}

handle_cloudflare_credentials() {
    ask_question "Enter your Cloudflare Email" CF_EMAIL
    ask_question "Enter your Cloudflare API Key" CF_API_KEY
    ask_question "Enter your Hostname (FQDN)" DOMAIN
    
    validate_domain "$DOMAIN"
    
    mkdir -p $(dirname "$CLOUDFLARE_CRED_PATH")
    cat > "$CLOUDFLARE_CRED_PATH" <<EOF
dns_cloudflare_email = ${CF_EMAIL}
dns_cloudflare_api_key = ${CF_API_KEY}
EOF
    chmod 600 "$CLOUDFLARE_CRED_PATH"

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
            echo -e "${BLUE}Invalid platform choice. Defaulting to Discord.${NC}"
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
                echo -e "${BLUE}Testing webhook on $(case "$WEBHOOK_PLATFORM" in
                    D) echo "Discord" ;;
                    S) echo "Slack" ;;
                    G) echo "Google Chat" ;;
                esac)...${NC}"
                
                # Different payload format based on platform
                case "$WEBHOOK_PLATFORM" in
                    D) # Discord
                        TEST_PAYLOAD='{
                            "content": "CloudNginx Webhook Test",
                            "embeds": [{
                                "title": "Test Successful",
                                "description": "Testing webhook for domain: '"$DOMAIN"'",
                                "color": 65280
                            }]
                        }'
                        ;;
                    S) # Slack
                        TEST_PAYLOAD='{
                            "text": "CloudNginx Webhook Test",
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
                            "text": "CloudNginx Webhook Test",
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
                
                if curl -s -X POST -H "Content-Type: application/json" -d "$TEST_PAYLOAD" "$WEBHOOK_URL"; then
                    echo -e "${BLUE}Webhook test successful${NC}"
                else
                    echo -e "${BLUE}Warning: Webhook test failed. Check your URL and try again.${NC}"
                    ask_question "Continue anyway? (Y/N)" CONTINUE
                    if [[ "${CONTINUE^^}" != "Y" ]]; then
                        exit 1
                    fi
                fi
            fi
        else
            echo -e "${BLUE}Invalid choice. Webhook notifications will not be configured.${NC}"
        fi
    else
        echo -e "${BLUE}Webhook notifications will not be configured.${NC}"
    fi
}

send_webhook() {
    local status=$1
    local message=$2

    if [ -n "$WEBHOOK_URL" ]; then
        echo "Sending webhook notification: $status - $message"
        
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
                        "text": "CloudNginx '"$status"' Notification",
                        "cards": [{
                            "header": {
                                "title": "CloudNginx '"$status"' Notification"
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
            
            # Send the webhook with debug output
            echo "Sending webhook to platform: $WEBHOOK_PLATFORM"
            echo "Webhook URL: $WEBHOOK_URL"
            curl -v -X POST -H "Content-Type: application/json" -d "$PAYLOAD" "$WEBHOOK_URL"
        fi
    fi
}

generate_ssl() {
    echo -e "${BLUE}Generating SSL certificate...${NC}"
    if certbot certonly --dns-cloudflare \
        --dns-cloudflare-credentials "$CLOUDFLARE_CRED_PATH" \
        -d "$DOMAIN" \
        --non-interactive \
        --agree-tos \
        --email "$CF_EMAIL"; then
        echo -e "${BLUE}SSL certificate generated successfully!${NC}"
        send_webhook "success" "SSL certificate generated successfully for domain: $DOMAIN"
    else
        echo -e "${BLUE}SSL certificate generation failed!${NC}"
        send_webhook "failure" "SSL certificate generation failed for domain: $DOMAIN"
        exit 1
    fi
}

configure_nginx() {
    local DOMAIN=$1
    local PORT=$2
    
    echo -e "${BLUE}Configuring NGINX for ${DOMAIN}...${NC}"
    
    # Create full nginx configuration
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

    # Enable site configuration
    ln -sf "/etc/nginx/sites-available/${DOMAIN}" "/etc/nginx/sites-enabled/"
    nginx -t && systemctl reload nginx
}

configure_firewall() {
    if command -v ufw >/dev/null 2>&1; then
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw reload
    fi
}

ensure_service_persistence() {
    echo -e "${BLUE}Ensuring service persistence...${NC}"
    
    # Enable and start Nginx if not already active
    if ! systemctl is-active --quiet nginx; then
        systemctl enable --now nginx
    fi
    
    # Enable Certbot renewal timer
    if systemctl list-timers | grep -q certbot; then
        systemctl enable --now certbot.timer
    fi
}

setup_certbot_renewal() {
    echo -e "${BLUE}Setting up Certbot renewal...${NC}"
    
    # Create renewal hooks if webhook is enabled
    if [ -n "$WEBHOOK_URL" ]; then
        mkdir -p /etc/letsencrypt/renewal-hooks/deploy
        mkdir -p /etc/letsencrypt/renewal-hooks/post

        # Deploy hook for successful renewals - complete standalone script
        cat > /etc/letsencrypt/renewal-hooks/deploy/webhook-notify.sh <<EOF
#!/bin/bash
# Webhook configuration
WEBHOOK_URL="$WEBHOOK_URL"
WEBHOOK_MODE="$WEBHOOK_MODE"
WEBHOOK_PLATFORM="$WEBHOOK_PLATFORM"
DOMAIN="$DOMAIN"

# Send notification
echo "Sending successful renewal webhook notification for \$DOMAIN"
echo "Using webhook platform: $WEBHOOK_PLATFORM"

if [[ "$WEBHOOK_MODE" == "S" || "$WEBHOOK_MODE" == "B" ]]; then
    case "$WEBHOOK_PLATFORM" in
        D) # Discord
            curl -s -X POST -H "Content-Type: application/json" -d '{
                "content": "SSL certificate renewed successfully for domain: '$DOMAIN'",
                "embeds": [{
                    "title": "CloudNginx Success Notification",
                    "description": "Domain: '$DOMAIN'",
                    "color": 65280
                }]
            }' "$WEBHOOK_URL"
            ;;
        S) # Slack
            curl -s -X POST -H "Content-Type: application/json" -d '{
                "text": "CloudNginx Success Notification",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*SSL certificate renewed successfully*\nDomain: '$DOMAIN'"
                        }
                    }
                ]
            }' "$WEBHOOK_URL"
            ;;
        G) # Google Chat
            curl -s -X POST -H "Content-Type: application/json" -d '{
                "text": "CloudNginx Success Notification",
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
            }' "$WEBHOOK_URL"
            ;;
    esac
fi
EOF
        chmod +x /etc/letsencrypt/renewal-hooks/deploy/webhook-notify.sh

        # Post hook for failed renewals (runs after all renewal attempts)
        cat > /etc/letsencrypt/renewal-hooks/post/webhook-notify-failure.sh <<EOF
#!/bin/bash
# Webhook configuration
WEBHOOK_URL="$WEBHOOK_URL"
WEBHOOK_MODE="$WEBHOOK_MODE"
WEBHOOK_PLATFORM="$WEBHOOK_PLATFORM"
DOMAIN="$DOMAIN"

# Check if certificate exists and is about to expire (failed renewal)
CERT_FILE="/etc/letsencrypt/live/$DOMAIN/cert.pem"
if [ -f "\$CERT_FILE" ]; then
    EXPIRY=\$(openssl x509 -enddate -noout -in "\$CERT_FILE" | cut -d= -f2)
    EXPIRY_EPOCH=\$(date -d "\$EXPIRY" +%s)
    NOW_EPOCH=\$(date +%s)
    DAYS_LEFT=\$(( (\$EXPIRY_EPOCH - \$NOW_EPOCH) / 86400 ))
    
    # If less than 7 days until expiry, we consider the renewal failed
    if [ \$DAYS_LEFT -lt 7 ]; then
        echo "Certificate has \$DAYS_LEFT days left and renewal likely failed. Sending webhook."
        echo "Using webhook platform: $WEBHOOK_PLATFORM"
        
        if [[ "$WEBHOOK_MODE" == "F" || "$WEBHOOK_MODE" == "B" ]]; then
            case "$WEBHOOK_PLATFORM" in
                D) # Discord
                    curl -s -X POST -H "Content-Type: application/json" -d '{
                        "content": "SSL certificate renewal failed for domain: '$DOMAIN'. Certificate will expire in '\$DAYS_LEFT' days",
                        "embeds": [{
                            "title": "CloudNginx Failure Alert",
                            "description": "Domain: '$DOMAIN'",
                            "color": 16711680
                        }]
                    }' "$WEBHOOK_URL"
                    ;;
                S) # Slack
                    curl -s -X POST -H "Content-Type: application/json" -d '{
                        "text": "CloudNginx Failure Alert",
                        "blocks": [
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": "*SSL certificate renewal failed*\nDomain: '$DOMAIN'\nCertificate will expire in '\$DAYS_LEFT' days"
                                }
                            }
                        ]
                    }' "$WEBHOOK_URL"
                    ;;
                G) # Google Chat
                    curl -s -X POST -H "Content-Type: application/json" -d '{
                        "text": "CloudNginx Failure Alert",
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
                    }' "$WEBHOOK_URL"
                    ;;
            esac
        fi
    fi
fi
EOF
        chmod +x /etc/letsencrypt/renewal-hooks/post/webhook-notify-failure.sh
    fi

    # Test renewal
    if certbot renew --dry-run; then
        echo -e "${BLUE}Certificate renewal configured successfully${NC}"
        send_webhook "success" "Certificate renewal system configured successfully for domain: $DOMAIN"
    else
        echo -e "${BLUE}Certificate renewal test failed${NC}"
        send_webhook "failure" "Certificate renewal configuration failed for domain: $DOMAIN"
        exit 1
    fi
}

main() {
    show_header
    check_root
    handle_cloudflare_credentials
    install_core_dependencies
    generate_ssl
    setup_certbot_renewal
    
    ask_question "Enter your application port (default: 3000)" PORT
    PORT=${PORT:-3000}
    
    configure_nginx "$DOMAIN" "$PORT"
    configure_firewall
    ensure_service_persistence
    
    echo -e "${BLUE}Setup completed successfully!${NC}"
    echo -e "${BLUE}Access your site at: https://${DOMAIN}${NC}"
    
    # Final success webhook
    send_webhook "success" "Full CloudNginx setup completed successfully for domain: $DOMAIN"
    
    # Display important information
    echo -e "\n${BLUE}Important Notes:${NC}"
    echo -e "1. Your Cloudflare credentials are stored securely at ${CLOUDFLARE_CRED_PATH}"
    echo -e "2. SSL certificates will auto-renew before expiration"
    echo -e "3. Nginx is configured to start automatically on boot"
    echo -e "4. Firewall rules (if UFW is present) are persistent"
    if [ -n "$WEBHOOK_URL" ]; then
        echo -e "5. Webhook notifications are enabled for: $WEBHOOK_MODE"
        echo -e "   - Webhook Platform: $(case "$WEBHOOK_PLATFORM" in
            D) echo "Discord" ;;
            S) echo "Slack" ;;
            G) echo "Google Chat" ;;
        esac)"
        echo -e "   - Webhook URL: $WEBHOOK_URL"
    fi
}

main
