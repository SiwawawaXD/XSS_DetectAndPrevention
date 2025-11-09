<?php
/**
 * Integrated XSS Detection Middleware
 * Checks every request with both ML API and WAF patterns
 */

class IntegratedXSSDetector {
    private $ml_api_url = "http://xss_detection_api:5001/detect";
    private $log_file = "/tmp/xss_detections.log";
    
    // WAF XSS detection patterns (similar to ModSecurity)
    private $xss_patterns = [
        '/<script[\s\S]*?>/i',
        '/javascript:/i',
        '/on\w+\s*=\s*/i',  // Event handlers like onclick, onerror
        '/<iframe[\s\S]*?>/i',
        '/<embed[\s\S]*?>/i',
        '/<object[\s\S]*?>/i',
        '/document\.(cookie|write|location)/i',
        '/window\.location/i',
        '/eval\s*\(/i',
        '/<svg[\s\S]*?>/i',
        '/alert\s*\(/i',
        '/prompt\s*\(/i',
        '/confirm\s*\(/i',
    ];
    
    public function checkRequest() {
        // Get all input parameters
        $all_params = array_merge($_GET, $_POST, $_COOKIE);
        
        $detections = [];
        
        foreach ($all_params as $param_name => $param_value) {
            if (is_string($param_value) && !empty($param_value)) {
                // Check with WAF patterns
                $waf_result = $this->checkWithWAF($param_value);
                
                // Check with ML API
                $ml_result = $this->checkWithML($param_value);
                
                // If EITHER system detects XSS, block it
                if ($waf_result['detected'] || $ml_result['detected']) {
                    $detections[] = [
                        'parameter' => $param_name,
                        'payload' => $param_value,
                        'waf_detected' => $waf_result['detected'],
                        'waf_patterns' => $waf_result['patterns'],
                        'ml_detected' => $ml_result['detected'],
                        'ml_confidence' => $ml_result['confidence'],
                        'ml_impact' => $ml_result['impact'],
                        'timestamp' => date('Y-m-d H:i:s'),
                        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown',
                        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
                        'uri' => $_SERVER['REQUEST_URI'] ?? 'Unknown'
                    ];
                }
            }
        }
        
        // If any XSS detected, block and show alert page
        if (!empty($detections)) {
            $this->logDetection($detections);
            $this->showBlockPage($detections);
            exit();
        }
        
        return true;
    }
    
    private function checkWithWAF($payload) {
        $detected = false;
        $matched_patterns = [];
        
        foreach ($this->xss_patterns as $pattern) {
            if (preg_match($pattern, $payload)) {
                $detected = true;
                $matched_patterns[] = $pattern;
            }
        }
        
        return [
            'detected' => $detected,
            'patterns' => $matched_patterns
        ];
    }
    
    private function checkWithML($payload) {
        try {
            $data = json_encode([
                'payload' => $payload,
                'source' => 'bwapp_integrated'
            ]);
            
            $ch = curl_init($this->ml_api_url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Content-Type: application/json',
                'Content-Length: ' . strlen($data)
            ]);
            curl_setopt($ch, CURLOPT_TIMEOUT, 3);
            
            $response = curl_exec($ch);
            $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            
            if ($http_code === 200 && $response) {
                $result = json_decode($response, true);
                return [
                    'detected' => $result['ml_detection']['is_malicious'] ?? false,
                    'confidence' => $result['ml_detection']['confidence'] ?? 0,
                    'impact' => $result['impact_level'] ?? 'UNKNOWN'
                ];
            }
        } catch (Exception $e) {
            error_log("ML API Error: " . $e->getMessage());
        }
        
        return ['detected' => false, 'confidence' => 0, 'impact' => 'UNKNOWN'];
    }
    
    private function logDetection($detections) {
        $log_entry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'detections' => $detections
        ];
        
        file_put_contents(
            $this->log_file,
            json_encode($log_entry) . "\n",
            FILE_APPEND
        );
    }
    
    private function showBlockPage($detections) {
        header('HTTP/1.1 403 Forbidden');
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>🛡️ XSS Attack Detected - Request Blocked</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }
                .container {
                    background: white;
                    border-radius: 20px;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                    max-width: 900px;
                    width: 100%;
                    overflow: hidden;
                    animation: slideIn 0.5s ease-out;
                }
                @keyframes slideIn {
                    from { transform: translateY(-50px); opacity: 0; }
                    to { transform: translateY(0); opacity: 1; }
                }
                .header {
                    background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%);
                    color: white;
                    padding: 40px;
                    text-align: center;
                }
                .header h1 { font-size: 2.5em; margin-bottom: 10px; }
                .shield-icon { font-size: 4em; margin-bottom: 20px; animation: pulse 2s infinite; }
                @keyframes pulse {
                    0%, 100% { transform: scale(1); }
                    50% { transform: scale(1.1); }
                }
                .content { padding: 40px; }
                .alert-box {
                    background: #fff3cd;
                    border-left: 4px solid #ffc107;
                    padding: 20px;
                    margin-bottom: 30px;
                    border-radius: 5px;
                }
                .alert-box h2 { color: #856404; margin-bottom: 10px; }
                .detection-card {
                    background: #f8f9fa;
                    border-radius: 10px;
                    padding: 20px;
                    margin-bottom: 20px;
                    border-left: 4px solid #dc3545;
                }
                .detection-card h3 { color: #dc3545; margin-bottom: 15px; }
                .info-row {
                    display: flex;
                    padding: 10px 0;
                    border-bottom: 1px solid #dee2e6;
                }
                .info-row:last-child { border-bottom: none; }
                .info-label {
                    font-weight: 600;
                    min-width: 180px;
                    color: #495057;
                }
                .info-value {
                    color: #212529;
                    word-break: break-all;
                    flex: 1;
                }
                .payload-box {
                    background: #2d2d2d;
                    color: #f8f8f2;
                    border-radius: 5px;
                    padding: 15px;
                    font-family: 'Courier New', monospace;
                    font-size: 0.9em;
                    word-break: break-all;
                    max-height: 150px;
                    overflow-y: auto;
                    margin-top: 10px;
                }
                .detection-methods {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 20px;
                    margin-top: 20px;
                }
                .method-card {
                    padding: 20px;
                    background: white;
                    border-radius: 8px;
                    border: 2px solid #dee2e6;
                    text-align: center;
                }
                .method-card.detected {
                    border-color: #dc3545;
                    background: linear-gradient(135deg, #fff5f5 0%, #ffe5e5 100%);
                }
                .method-card h4 {
                    margin-bottom: 15px;
                    font-size: 1.3em;
                    color: #495057;
                }
                .method-card.detected h4 { color: #dc3545; }
                .status-icon {
                    font-size: 3em;
                    margin-bottom: 10px;
                }
                .badge {
                    display: inline-block;
                    padding: 8px 20px;
                    border-radius: 20px;
                    font-weight: 600;
                    font-size: 1em;
                    margin: 10px 0;
                }
                .badge-danger {
                    background: #dc3545;
                    color: white;
                }
                .badge-success {
                    background: #28a745;
                    color: white;
                }
                .confidence-bar {
                    background: #e9ecef;
                    border-radius: 10px;
                    height: 30px;
                    margin-top: 10px;
                    overflow: hidden;
                }
                .confidence-fill {
                    background: linear-gradient(90deg, #dc3545, #ff6b6b);
                    height: 100%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: white;
                    font-weight: 600;
                    transition: width 1s ease-out;
                }
                .footer {
                    background: #f8f9fa;
                    padding: 20px 40px;
                    text-align: center;
                    color: #6c757d;
                }
                .back-button {
                    display: inline-block;
                    margin-top: 20px;
                    padding: 12px 30px;
                    background: #667eea;
                    color: white;
                    text-decoration: none;
                    border-radius: 25px;
                    font-weight: 600;
                    transition: all 0.3s;
                }
                .back-button:hover {
                    background: #5568d3;
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="shield-icon">🛡️</div>
                    <h1>XSS Attack Detected!</h1>
                    <p>Your request has been blocked by our integrated security system</p>
                </div>
                
                <div class="content">
                    <div class="alert-box">
                        <h2>⚠️ Security Alert</h2>
                        <p>Our multi-layered XSS detection system has identified and blocked a potential Cross-Site Scripting (XSS) attack in your request. Both Web Application Firewall and Machine Learning models analyzed your input.</p>
                    </div>
                    
                    <?php foreach ($detections as $index => $detection): ?>
                    <div class="detection-card">
                        <h3>🚨 Detection #<?php echo $index + 1; ?></h3>
                        
                        <div class="info-row">
                            <div class="info-label">Parameter Name:</div>
                            <div class="info-value"><strong><?php echo htmlspecialchars($detection['parameter']); ?></strong></div>
                        </div>
                        
                        <div class="info-row">
                            <div class="info-label">Malicious Payload:</div>
                            <div class="info-value">
                                <div class="payload-box"><?php echo htmlspecialchars($detection['payload']); ?></div>
                            </div>
                        </div>
                        
                        <div class="info-row">
                            <div class="info-label">Detection Time:</div>
                            <div class="info-value"><?php echo $detection['timestamp']; ?></div>
                        </div>
                        
                        <div class="info-row">
                            <div class="info-label">Source IP Address:</div>
                            <div class="info-value"><?php echo htmlspecialchars($detection['ip']); ?></div>
                        </div>
                        
                        <div class="detection-methods">
                            <div class="method-card <?php echo $detection['waf_detected'] ? 'detected' : ''; ?>">
                                <div class="status-icon"><?php echo $detection['waf_detected'] ? '🔒' : '✓'; ?></div>
                                <h4>Web Application Firewall</h4>
                                <div class="badge <?php echo $detection['waf_detected'] ? 'badge-danger' : 'badge-success'; ?>">
                                    <?php echo $detection['waf_detected'] ? 'THREAT DETECTED' : 'SAFE'; ?>
                                </div>
                                <?php if ($detection['waf_detected']): ?>
                                    <p style="margin-top: 10px; font-size: 0.95em; color: #666;">
                                        Matched <strong><?php echo count($detection['waf_patterns']); ?></strong> malicious pattern(s)
                                    </p>
                                <?php endif; ?>
                            </div>
                            
                            <div class="method-card <?php echo $detection['ml_detected'] ? 'detected' : ''; ?>">
                                <div class="status-icon"><?php echo $detection['ml_detected'] ? '🤖' : '✓'; ?></div>
                                <h4>Machine Learning Model</h4>
                                <div class="badge <?php echo $detection['ml_detected'] ? 'badge-danger' : 'badge-success'; ?>">
                                    <?php echo $detection['ml_detected'] ? 'THREAT DETECTED' : 'SAFE'; ?>
                                </div>
                                <?php if ($detection['ml_detected']): ?>
                                    <p style="margin-top: 10px; font-size: 0.95em; color: #666;">
                                        <strong>Confidence:</strong> <?php echo number_format($detection['ml_confidence'] * 100, 2); ?>%<br>
                                        <strong>Impact Level:</strong> <?php echo $detection['ml_impact']; ?>
                                    </p>
                                    <div class="confidence-bar">
                                        <div class="confidence-fill" style="width: <?php echo ($detection['ml_confidence'] * 100); ?>%">
                                            <?php echo number_format($detection['ml_confidence'] * 100, 1); ?>%
                                        </div>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                    <?php endforeach; ?>
                    
                    <div style="text-align: center;">
                        <a href="javascript:history.back()" class="back-button">← Go Back</a>
                    </div>
                </div>
                
                <div class="footer">
                    <p><strong>🛡️ Integrated XSS Detection System</strong></p>
                    <p>Protected by Multi-Layered Security: WAF + Machine Learning</p>
                    <p style="margin-top: 10px; font-size: 0.9em;">Project Demonstration System</p>
                </div>
            </div>
        </body>
        </html>
        <?php
        exit();
    }
}

// Auto-run detection on every request
$detector = new IntegratedXSSDetector();
$detector->checkRequest();
?>