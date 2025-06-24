# Cloudflare Nginx SSL Automation
 
*Automated SSL configuration with 30 day renewal with Let's Encrypt for Nginx with Cloudflare DNS validation*

## Features

- **Automatic SSL Certificates**: Uses Let's Encrypt via Cloudflare DNS validation
- **Modern Security Configuration**:
  - TLS 1.2/1.3 only
  - Strong cipher suites
  - OCSP stapling
  - HTTP/2 support
  - Rate limiting and DDoS protection
  - Enhanced security headers (CSP, HSTS, etc.)
- **WebSocket Ready**: Built-in proxy configuration for WebSocket support
- **Automatic Redirects**: Forces HTTPS and handles port redirection
- **Cloudflare Integration**: Securely stores API credentials with validation
- **Firewall Configuration**: Automatic UFW setup (if installed)
- **Webhook Alerts**: Get alerts to Discord, Slack, or Google Chat
- **Health Monitoring**: Built-in health check endpoint
- **Backup & Rollback**: Automatic configuration backup and rollback on failure
- **Dry Run Mode**: Test configuration changes without applying them

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

### Standard Version
1. Download the script and make it executable:
```
curl -LO https://raw.githubusercontent.com/taslabs-net/CloudflareNginx/main/cfnginx.sh && chmod +x cfnginx.sh
```

### Enhanced Version (Recommended)
1. Download the improved script with additional security features:
```
curl -LO https://raw.githubusercontent.com/taslabs-net/CloudflareNginx/main/cfnginx-improved.sh && chmod +x cfnginx-improved.sh
```

2. Run with parameters:
```
sudo ./cfnginx-improved.sh \
  --domain your-domain.com \
  --email your-cloudflare@email.com \
  --key your-cloudflare-api-key
```

### Available Parameters

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
| Dry Run      | `--dry-run`        | Test configuration without making changes       | No       |
| No Rollback  | `--no-rollback`    | Disable automatic rollback on failure           | No       |
| Help         | `-h, --help`       | Show help information                           | No       |

### Example Commands

Basic installation:
```bash
sudo ./cfnginx-improved.sh --domain example.com --email user@example.com --key abc123def456
```

With custom port:
```bash
sudo ./cfnginx-improved.sh --domain example.com --port 8080 --email user@example.com --key abc123def456
```

With webhook notifications:
```bash
sudo ./cfnginx-improved.sh --domain example.com --email user@example.com --key abc123def456 \
  --webhook "https://discord.com/api/webhooks/your-webhook-url"
```

Test configuration without making changes:
```bash
sudo ./cfnginx-improved.sh --domain example.com --email user@example.com --key abc123def456 --dry-run
```

Quiet mode installation:
```bash
sudo ./cfnginx-improved.sh --domain example.com --email user@example.com --key abc123def456 --quiet
```

## 🖥️ What Happens During Installation

1. **Pre-flight Checks** (Enhanced version only):
   - Validates root privileges
   - Verifies Cloudflare API credentials
   - Checks domain resolution (warning only)
   - Tests port availability

2. **System Preparation**:
   - Updates packages
   - Installs requirements (Nginx, Certbot, Cloudflare plugin, jq, lsof)
   - Creates backup directory

3. **SSL Configuration**:
   - Creates secure Cloudflare credential file (600 permissions)
   - Validates API access before proceeding
   - Generates Let's Encrypt certificate using DNS challenge

4. **Nginx Setup**:
   - Backs up existing configurations
   - Creates optimized SSL configuration with:
     - Rate limiting zones
     - Security headers (HSTS, CSP, etc.)
     - Health check endpoint at `/health`
     - WebSocket support
   - Sets up HTTPS redirect
   - Configures reverse proxy

5. **Security Hardening**:
   - Configures UFW firewall (if present)
   - Sets proper file permissions
   - Implements modern TLS settings
   - Blocks common attack patterns
   - Adds connection limits

## 🔒 Security Notes

1. **Firewall**:
   - Ensure Proxmox host firewall allows ports 80/443
   - Script automatically configures container firewall if UFW is present
   - SSH (port 22) is also allowed to prevent lockout

2. **Credential Storage**:
   - Cloudflare API keys stored in `/etc/letsencrypt/cloudflare.ini`
   - File permissions set to `600` (owner read/write only)
   - Configuration file stored with secure permissions

3. **Enhanced Security** (Improved version):
   - Rate limiting to prevent DDoS attacks
   - Security headers for XSS, clickjacking prevention
   - Certificate validation and expiry monitoring
   - Automatic backups before configuration changes
   - JSON injection prevention in webhooks

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

## 📁 Logs and Configuration Files

- **Log file**: `/var/log/cloudflarenginx-install.log`
- **Configuration**: `/etc/cloudflarenginx.conf`
- **Nginx config**: `/etc/nginx/sites-available/your-domain.com`
- **SSL certificates**: `/etc/letsencrypt/live/your-domain.com/`
- **Backup directory**: `/var/backups/cloudflarenginx/` (Enhanced version)

For detailed troubleshooting, check the logs at `/var/log/cloudflarenginx-install.log`

## 🆕 Enhanced Version Features

The `cfnginx-improved.sh` script includes:

- **Pre-installation validation**: API credentials, domain resolution, port availability
- **Dry-run mode**: Test changes without applying them
- **Automatic rollback**: Restore previous configuration on failure
- **Health monitoring**: Built-in `/health` endpoint for uptime monitoring
- **Rate limiting**: Protection against DDoS attacks
- **Enhanced security headers**: CSP, HSTS, Referrer-Policy, and more
- **Certificate expiry monitoring**: Warnings for expiring certificates
- **Timeout handling**: All external calls have timeouts
- **Better error messages**: More descriptive error handling
- **Signal handling**: Graceful cleanup on interruption

## 📊 Health Check

After installation, you can monitor your service:
```bash
curl https://your-domain.com/health
```

This endpoint returns a simple "healthy" response and can be used with monitoring tools.