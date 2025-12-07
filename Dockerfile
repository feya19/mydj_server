# Multi-stage build for security and efficiency
FROM python:3.11-slim AS base

# Security: Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y \
    # Basic dependencies
    curl \
    wget \
    gnupg \
    sudo \
    # Security tools
    fail2ban \
    iptables \
    # Wazuh agent dependencies
    apt-transport-https \
    lsb-release \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Wazuh Agent
FROM base AS wazuh-stage
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
RUN apt-get update && apt-get install -y wazuh-agent && apt-get clean && rm -rf /var/lib/apt/lists/*

# Application stage
FROM wazuh-stage AS app-stage

# Set working directory
WORKDIR /app

# Security: Set proper permissions for app directory
RUN chown -R appuser:appuser /app

# Create necessary directories with proper permissions
RUN mkdir -p /app/uploads /app/logs /var/log/mydj_server && \
    chown -R appuser:appuser /app/uploads /app/logs /var/log/mydj_server && \
    chmod 755 /app/uploads /app/logs /var/log/mydj_server

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies with security considerations
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    # Security: Remove pip cache and temporary files
    pip cache purge && \
    rm -rf /tmp/* /var/tmp/*

# Copy application code
COPY . .

# Security: Set proper file permissions
RUN chmod 644 main.py && \
    chmod +x docker-entrypoint.sh || true

# Configure Fail2ban
COPY config/jail.local /etc/fail2ban/jail.local
COPY config/filter.d/mydj-auth.conf /etc/fail2ban/filter.d/mydj-auth.conf
COPY config/filter.d/mydj-dos.conf /etc/fail2ban/filter.d/mydj-dos.conf

# Configure Wazuh Agent (keep as root for now, will be handled in entrypoint)
COPY config/wazuh/ossec.conf /tmp/ossec.conf.template
RUN chmod 644 /tmp/ossec.conf.template

# Security: Remove sensitive files and set immutable files
RUN find /app -name "*.pyc" -delete && \
    find /app -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Create startup script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Create sudoers file for appuser to manage services
RUN mkdir -p /etc/sudoers.d && \
    echo 'appuser ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/appuser && \
    chmod 440 /etc/sudoers.d/appuser

# Switch to non-root user
USER appuser

# Security: Expose only necessary port
EXPOSE 8000

# Health check for container monitoring
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

# Use startup script as entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Default command
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info", "--access-log"]