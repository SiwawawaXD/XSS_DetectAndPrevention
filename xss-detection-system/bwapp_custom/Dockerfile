FROM raesene/bwapp

# Install curl and mysql client for ML API communication and database setup
RUN apt-get update && \
    apt-get install -y curl mysql-client && \
    rm -rf /var/lib/apt/lists/*

# Fix database configuration to use Docker network hostname
RUN sed -i 's/\$db_server = "localhost"/\$db_server = "mysql"/' /var/www/html/admin/settings.php

# Fix install.php to use correct credentials
RUN sed -i 's/\$db_username = "root"/\$db_username = "bwapp"/' /var/www/html/install.php && \
    sed -i 's/\$db_password = ""/\$db_password = "bug"/' /var/www/html/install.php && \
    sed -i 's/\$db_server = "localhost"/\$db_server = "mysql"/' /var/www/html/install.php

# Create integration directory
RUN mkdir -p /var/www/html/integration

# Set proper permissions
RUN chown -R www-data:www-data /var/www/html/integration

# Copy auto-initialization script
COPY init-bwapp.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/init-bwapp.sh

EXPOSE 80

# Use initialization script as entrypoint
CMD ["/usr/local/bin/init-bwapp.sh"]
