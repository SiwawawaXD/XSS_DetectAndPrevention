FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    apache2 \
    libapache2-mod-security2 \
    git \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Enable Apache modules
RUN a2enmod security2 \
    && a2enmod headers \
    && a2enmod proxy \
    && a2enmod proxy_http \
    && a2enmod rewrite

# Remove default ModSecurity includes
RUN rm -f /etc/apache2/mods-enabled/security2.conf \
    && rm -f /etc/apache2/mods-available/security2.conf

# Download LATEST OWASP CRS version (v3.3.5)
RUN rm -rf /etc/modsecurity/crs \
    && git clone https://github.com/coreruleset/coreruleset.git /etc/modsecurity/crs \
    && cd /etc/modsecurity/crs \
    && git checkout v3.3.5 \
    && cp crs-setup.conf.example crs-setup.conf

# Copy ModSecurity configuration
COPY modsecurity.conf /etc/modsecurity/modsecurity.conf

# Create Apache configuration with ModSecurity
RUN echo 'LoadModule security2_module /usr/lib/apache2/modules/mod_security2.so\n\
<IfModule security2_module>\n\
    SecDataDir /var/cache/modsecurity\n\
    Include /etc/modsecurity/modsecurity.conf\n\
    Include /etc/modsecurity/crs/crs-setup.conf\n\
    Include /etc/modsecurity/crs/rules/*.conf\n\
</IfModule>' > /etc/apache2/mods-available/security2.conf \
    && ln -s /etc/apache2/mods-available/security2.conf /etc/apache2/mods-enabled/security2.conf

# Create VirtualHost configuration
RUN echo '<VirtualHost *:80>\n\
    ServerName localhost\n\
    \n\
    # Proxy to bWAPP\n\
    ProxyPreserveHost On\n\
    ProxyPass / http://bwapp/ retry=0 timeout=300\n\
    ProxyPassReverse / http://bwapp/\n\
    \n\
    ErrorLog /var/log/apache2/error.log\n\
    CustomLog /var/log/apache2/access.log combined\n\
    SecAuditLog /var/log/apache2/modsec_audit.log\n\
    SecAuditLogType Serial\n\
</VirtualHost>' > /etc/apache2/sites-available/000-default.conf

# Create necessary directories
RUN mkdir -p /var/log/apache2 \
    && mkdir -p /var/cache/modsecurity \
    && chown -R www-data:www-data /var/cache/modsecurity

EXPOSE 80

CMD ["apache2ctl", "-D", "FOREGROUND"]