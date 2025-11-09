<?php
/**
 * Auto-prepend file - runs before EVERY PHP page
 * This includes the XSS detector automatically
 */
require_once '/var/www/html/integration/xss_detector.php';
?>