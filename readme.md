# Build and run instructions for mydj_server

## Quick Start Options

### Option 1: Simple Setup (Recommended for Development)
```bash
# Use the simple version without complex security features
docker-compose -f docker-compose.simple.yml up --build
```

### Option 2: Full Security Setup (Advanced - may require troubleshooting)
```bash
# Copy environment file
cp .env.example .env
# Edit .env with your configuration

# Build and start with full security features
docker-compose up --build
```

### Option 3: Full security with Wazuh (Production)
```bash
# Configure Wazuh Manager IP in .env
cp .env.example .env
# Set ENABLE_WAZUH=true and WAZUH_MANAGER=your_manager_ip

# Start with Wazuh components
docker-compose --profile wazuh up --build
```

## Common Issues and Solutions

### Issue 1: Permission Denied for Wazuh
**Problem:** `sed: can't read /var/ossec/etc/ossec.conf: Permission denied`

**Solution:** Use the simple setup first, or run with proper privileges:
```bash
# Option A: Use simple setup
docker-compose -f docker-compose.simple.yml up --build

# Option B: Run full setup with privileged mode (less secure)
# Modify docker-compose.yml to add 'privileged: true' under mydj-server service
```

### Issue 2: Nginx Configuration Missing
**Problem:** `not a directory: unknown: Are you trying to mount a directory onto a file`

**Solution:** The nginx configuration is now included. Make sure you're using the updated files.

## Security Features Implemented

✅ **Implemented in Docker:**
- Multi-stage build with security hardening
- Non-root user execution
- Resource limits for DoS protection
- Security headers via Nginx
- File integrity monitoring
- Log aggregation and rotation
- Health checks and monitoring

✅ **Wazuh Integration:**
- Real-time log monitoring
- File integrity monitoring
- Vulnerability detection
- Active response capabilities
- Custom rules for API security

✅ **Fail2ban Integration:**
- SSH brute force protection
- API authentication failure blocking
- DoS attack mitigation
- Custom filters for application logs

## What Cannot Be Fully Implemented in Docker

❌ **Limitations:**

1. **Privileged Operations:**
   - Fail2ban requires host-level iptables access
   - Wazuh agent needs privileged mode for full functionality
   - SSH brute force protection needs host SSH access

2. **Network-level Security:**
   - Port scanning detection requires host network access
   - Deep packet inspection needs network tap
   - Real-time traffic analysis requires host privileges

3. **System-level Monitoring:**
   - Full system call monitoring
   - Kernel-level security modules
   - Hardware-level security features

## Recommended Production Setup

For full security implementation as described in your documentation:

1. **Host-level Security:**
   ```bash
   # Install on host system
   sudo apt install fail2ban
   sudo systemctl enable fail2ban
   
   # Configure iptables rules
   sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
   sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
   ```

2. **Wazuh Manager Deployment:**
   - Deploy Wazuh Manager on separate server
   - Configure network monitoring rules
   - Setup custom rules for your API

3. **Network Security:**
   - Use WAF (Web Application Firewall)
   - Implement network segmentation
   - Use intrusion detection systems

## Testing the Security Features

1. **Test Rate Limiting:**
   ```bash
   # Test API flooding
   for i in {1..200}; do curl -X POST http://localhost:8000/upload-jurnal; done
   ```

2. **Test File Upload Security:**
   ```bash
   # Test malicious file upload
   curl -X POST -F "file=@malicious.php" http://localhost:8000/upload-jurnal
   ```

3. **Monitor Logs:**
   ```bash
   # Watch security logs
   docker logs -f mydj_server
   
   # Check Wazuh alerts
   docker exec -it wazuh-manager tail -f /var/ossec/logs/alerts/alerts.log
   ```

## Security Checklist

- [ ] Change default JWT secret key
- [ ] Configure proper CORS origins
- [ ] Set up SSL certificates
- [ ] Configure Wazuh Manager IP
- [ ] Review and adjust rate limits
- [ ] Set up log monitoring alerts
- [ ] Test backup and recovery procedures
- [ ] Implement regular security updates