# ==========================
#  NeuraVult Affiliate Backend - PHP Dockerfile
# ==========================

# Use the official PHP 8.2 image with Apache
FROM php:8.2-apache

# Set working directory
WORKDIR /var/www/html

# Copy all backend files into the container
COPY . /var/www/html

# Enable Apache mod_rewrite (for clean API routes)
RUN a2enmod rewrite

# Install necessary PHP extensions
RUN docker-php-ext-install pdo pdo_mysql pdo_sqlite

# Optional: increase PHP upload/post limits
RUN echo "upload_max_filesize=20M\npost_max_size=25M" > /usr/local/etc/php/conf.d/uploads.ini

# Give proper file permissions
RUN chown -R www-data:www-data /var/www/html

# Expose port 80 for Render
EXPOSE 80

# Start Apache server
CMD ["apache2-foreground"]
