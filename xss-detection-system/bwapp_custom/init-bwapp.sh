#!/bin/bash
set -e

echo "Starting bWAPP initialization..."

# Wait for MySQL to be ready
echo "Waiting for MySQL to be ready..."
while ! mysqladmin ping -h"mysql" -u"bwapp" -p"bug" --silent; do
    sleep 1
done
echo "MySQL is ready!"

# Check if database exists
DB_EXISTS=$(mysql -h mysql -u bwapp -pbug -e "SHOW DATABASES LIKE 'bWAPP';" | grep -c "bWAPP" || true)

if [ "$DB_EXISTS" -eq 0 ]; then
    echo "Database doesn't exist. Creating bWAPP database..."
    
    # Create database
    mysql -h mysql -u bwapp -pbug -e "CREATE DATABASE IF NOT EXISTS bWAPP;"
    
    # Import SQL schema
    mysql -h mysql -u bwapp -pbug bWAPP < /var/www/html/admin/bWAPP.sql
    
    echo "Database created and initialized successfully!"
else
    echo "Database already exists. Skipping initialization."
fi

# Start Apache in foreground
echo "Starting Apache..."
exec apache2ctl -D FOREGROUND