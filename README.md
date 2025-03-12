# Cloudflare Nginx SSL Automation

## Made it a [Wiki](https://github.com/taslabs-net/CloudflareNginx/wiki)
 
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

1. Download the script without webhook support:
```
curl -sLO https://raw.githubusercontent.com/taslabs-net/CloudflareNginx/main/install.sh
```
Download the script with webhook support for Discord, Google Chat, and Slack.  It will also ask if you want it on Successful Renewal Only, Failure Only, or Both (default)
```
curl -sLO https://raw.githubusercontent.com/taslabs-net/CloudflareNginx/main/install_webhook.sh
```
2. Make it executable:
```
chmod +x install.sh
```
```
chmod +x install_webhook.sh
```

3. Run as root:
```
sudo ./install.sh
```
```
sudo ./install_webhook.sh
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
