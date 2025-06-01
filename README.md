# Cloudflare Nginx SSL Automation
 
*Automated SSL configuration with 30 day renewal with Let's Encrypt for Nginx with Cloudflare DNS validation*

## Features

- **Automatic SSL Certificates**: Uses Let's Encrypt via Cloudflare DNS validation
- **Modern Security Configuration**:
  - TLS 1.2/1.3 only
  - Strong cipher suites
  - OCSP stapling
  - HTTP/2 support
- **WebSocket Ready**: Built-in proxy configuration for WebSocket support
- **Automatic Redirects**: Forces HTTPS and handles port redirection
- **Cloudflare Integration**: Securely stores API credentials
- **Firewall Configuration**: Automatic UFW setup (if installed)
- **Webhook Alerts**: Get alerts to Discord, Slack, or Google Chat

## 🛠️ What Problem This Solves

This script automates the complex process of:
1. Setting up proper SSL configuration with Nginx
2. Cloudflare API integration for DNS validation
3. Configuring modern security protocols
4. Creating production-ready reverse proxy setup
5. Implementing best practices for web server security

## 📋 Requirements

- Proxmox LXC container (or any Debian/Ubuntu server)
- Root access
- Domain name with DNS managed through Cloudflare

## 🔧 Installation

1. Download the script and make it executable:
```
curl -LO https://raw.githubusercontent.com/taslabs-net/CloudflareNginx/main/cfnginx.sh && chmod +x cfnginx.sh
```

2. Run with parameters:
```
sudo ./cfnginx.sh \
  --domain your-domain.com \
  --email your-cloudflare@email.com \
  --key your-cloudflare-api-key
```
| Parameter    | Flag               | Description                                     | Required |
|--------------|--------------------|-------------------------------------------------|----------|
| Domain       | `-d, --domain`     | Your domain name                                | Yes      |
| Port         | `-p, --port`       | Application port (default: 3000)                | No       |
| Email        | `-e, --email`      | Cloudflare account email                        | Yes      |
| API Key      | `-k, --key`        | Cloudflare Global API key                       | Yes      |
| Webhook URL  | `-w, --webhook`    | Notification webhook URL                        | No       |
| Webhook Mode | `-m, --webhook-mode` | S=Success, F=Failure, B=Both (default: B)     | No       |
| Webhook Type | `-t, --webhook-type` | D=Discord, S=Slack, G=Google Chat (default: D) | No       |
| Quiet Mode   | `-q, --quiet`      | Minimal console output                          | No       |
| Help         | `-h, --help`       | Show help information                           | No       |

```
sudo ./cfnginx.sh --domain example.com --email user@example.com --key abc123def456
```

```
sudo ./cfnginx.sh --domain example.com --port 8080 --email user@example.com --key abc123def456
```

```
sudo ./cfnginx.sh --domain example.com --email user@example.com --key abc123def456 --webhook "https://discord.com/api/webhooks/your-webhook-url"
```

```
sudo ./cfnginx.sh --domain example.com --email user@example.com --key abc123def456 --quiet
```

## 🖥️ What Happens During Installation

1. **System Preparation**:
   - Updates packages
   - Installs requirements (Nginx, Certbot, Cloudflare plugin)

2. **SSL Configuration**:
   - Creates secure Cloudflare credential file
   - Generates Let's Encrypt certificate using DNS challenge

3. **Nginx Setup**:
   - Creates optimized SSL configuration
   - Sets up HTTPS redirect
   - Configures reverse proxy with WebSocket support

4. **Security Hardening**:
   - Configures UFW firewall (if present)
   - Sets proper file permissions
   - Implements modern TLS settings

## 🔒 Security Notes

1. **Firewall**:
   - Ensure Proxmox host firewall allows ports 80/443
   - Script automatically configures container firewall if UFW is present

2. **Credential Storage**:
   - Cloudflare API keys stored in `/etc/letsencrypt/cloudflare.ini`
   - File permissions set to `600`

## 🐛 Troubleshooting

Common Issues:

1. **SSL Certificate Errors**:
   ```bash
   certbot certificates # Check certificate status
   systemctl status nginx # Verify Nginx running
   ```

2. **Port Conflicts**:
   ```bash
   ss -tulpn | grep ':443'
   ```

## 🧹 Uninstallation

1. Remove Nginx configuration:
```bash
rm /etc/nginx/sites-enabled/yourdomain.com
```

2. Remove certificates:
```bash
certbot delete --cert-name yourdomain.com
```

3. Remove Cloudflare credentials:
```bash
rm /etc/letsencrypt/cloudflare.ini
```

Logs and Configuration Files

Log file: /var/log/cloudflarenginx-install.log

Configuration: /etc/cloudflarenginx.conf

Nginx config: /etc/nginx/sites-available/your-domain.com

SSL certificates: /etc/letsencrypt/live/your-domain.com/

For detailed troubleshooting, check the logs at /var/log/cloudflarenginx-install.log