#!/bin/bash
set -e

echo "Starting mydj_server with security components..."

# Start Wazuh Agent if environment variables are set
if [ ! -z "$WAZUH_MANAGER" ] && [ "$ENABLE_WAZUH" = "true" ]; then
    echo "Configuring Wazuh Agent..."
    # Configure Wazuh Manager IP and copy to proper location
    sed "s/MANAGER_IP/$WAZUH_MANAGER/g" /tmp/ossec.conf.template > /tmp/ossec.conf
    sudo cp /tmp/ossec.conf /var/ossec/etc/ossec.conf
    sudo chown root:wazuh /var/ossec/etc/ossec.conf
    sudo chmod 640 /var/ossec/etc/ossec.conf
    
    echo "Starting Wazuh Agent..."
    sudo /var/ossec/bin/wazuh-control start || echo "Warning: Could not start Wazuh agent. Continuing without it."
fi

# Create log directory if it doesn't exist
mkdir -p /app/logs

# Create log files that fail2ban expects
touch /app/logs/security.log
touch /app/logs/application.log
touch /app/logs/access.log

# Start Fail2ban if enabled
if [ "$ENABLE_FAIL2BAN" = "true" ]; then
    echo "Starting Fail2ban..."
    sudo service fail2ban start || echo "Warning: Could not start Fail2ban. Continuing without it."
fi

# Set up log rotation
if [ "$ENABLE_LOG_ROTATION" = "true" ]; then
    echo "Setting up log rotation..."
    cat > /tmp/mydj-logrotate << EOF
/app/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 appuser appuser
}
EOF
    sudo cp /tmp/mydj-logrotate /etc/logrotate.d/mydj
fi

echo "Security components configured. Starting FastAPI application..."

# Execute the main command
exec "$@"