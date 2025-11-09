<?php
/**
 * XSS Detection Demo Page
 * Demonstrates integrated WAF + ML detection
 */

require_once 'xss_detector.php';

// Get input if submitted
$test_input = $_GET['input'] ?? '';
$test_submitted = !empty($test_input);

// Page title
$page_title = "Integrated XSS Detection System - Demo";
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $page_title; ?></title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .shield-icon {
            font-size: 4em;
            margin-bottom: 20px;
        }
        
        .content {
            padding: 40px;
        }
        
        .info-box {
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            padding: 20px;
            margin-bottom: 30px;
            border-radius: 5px;
        }
        
        .info-box h2 {
            color: #1976D2;
            margin-bottom: 10px;
        }
        
        .info-box ul {
            margin-left: 20px;
            line-height: 1.8;
        }
        
        .form-group {
            margin-bottom: 25px;
        }
        
        .form-group label {
            display: block;
            font-weight: 600;
            margin-bottom: 10px;
            color: #333;
            font-size: 1.1em;
        }
        
        .form-group input[type="text"] {
            width: 100%;
            padding: 15px;
            font-size: 1em;
            border: 2px solid #ddd;
            border-radius: 8px;
            transition: border-color 0.3s;
            font-family: 'Courier New', monospace;
        }
        
        .form-group input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .test-button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 40px;
            font-size: 1.1em;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: transform 0.2s;
            width: 100%;
        }
        
        .test-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        
        .payload-examples {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 10px;
            margin-top: 30px;
        }
        
        .payload-examples h3 {
            color: #333;
            margin-bottom: 15px;
        }
        
        .payload-list {
            display: grid;
            grid-template-columns: 1fr;
            gap: 10px;
        }
        
        .payload-item {
            background: white;
            padding: 12px;
            border-radius: 5px;
            border-left: 3px solid #667eea;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .payload-item:hover {
            background: #e7f3ff;
            border-left-color: #764ba2;
            transform: translateX(5px);
        }
        
        .payload-item .label {
            font-weight: 600;
            color: #667eea;
            display: block;
            margin-bottom: 5px;
            font-family: 'Segoe UI', sans-serif;
        }
        
        .result-box {
            margin-top: 30px;
            padding: 25px;
            background: #d4edda;
            border-left: 4px solid #28a745;
            border-radius: 8px;
        }
        
        .result-box h3 {
            color: #155724;
            margin-bottom: 15px;
        }
        
        .reflected-content {
            background: white;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
            border: 1px solid #c3e6cb;
        }
        
        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #6c757d;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="shield-icon">🛡️</div>
            <h1>XSS Detection System</h1>
            <p>Multi-Layered Security Demo: WAF + Machine Learning</p>
        </div>
        
        <div class="content">
            <div class="info-box">
                <h2>ℹ️ How It Works</h2>
                <p>This system uses <strong>two layers of protection</strong>:</p>
                <ul>
                    <li><strong>Web Application Firewall (WAF)</strong> - Pattern-based detection using regex rules</li>
                    <li><strong>Machine Learning Model</strong> - AI-powered detection with confidence scoring</li>
                </ul>
                <p style="margin-top: 10px;"><strong>If either system detects XSS, the request is blocked!</strong></p>
            </div>
            
            <form method="GET" action="">
                <div class="form-group">
                    <label for="input">🧪 Test Input (Try XSS Payloads Below):</label>
                    <input 
                        type="text" 
                        name="input" 
                        id="input" 
                        placeholder="Enter your test input here... e.g., <script>alert('XSS')</script>"
                        value="<?php echo htmlspecialchars($test_input); ?>"
                    >
                </div>
                
                <button type="submit" class="test-button">
                    🔍 Test for XSS Detection
                </button>
            </form>
            
            <?php if ($test_submitted): ?>
            <div class="result-box">
                <h3>✅ Input Passed Security Check</h3>
                <p>Your input was analyzed by both the WAF and ML model and deemed safe.</p>
                <p style="margin-top: 10px;"><strong>Reflected Input:</strong></p>
                <div class="reflected-content">
                    <?php echo $test_input; // Intentionally vulnerable for demo ?>
                </div>
            </div>
            <?php endif; ?>
            
            <div class="payload-examples">
                <h3>📋 XSS Payload Examples (Click to Test)</h3>
                <p style="margin-bottom: 15px; color: #666;">Click any payload below to test it:</p>
                <div class="payload-list">
                    <div class="payload-item" onclick="testPayload('<script>alert(1)</script>')">
                        <span class="label">Basic Script Tag:</span>
                        &lt;script&gt;alert(1)&lt;/script&gt;
                    </div>
                    <div class="payload-item" onclick="testPayload('<img src=x onerror=alert(1)>')">
                        <span class="label">Image Event Handler:</span>
                        &lt;img src=x onerror=alert(1)&gt;
                    </div>
                    <div class="payload-item" onclick="testPayload('<svg onload=alert(1)>')">
                        <span class="label">SVG Attack:</span>
                        &lt;svg onload=alert(1)&gt;
                    </div>
                    <div class="payload-item" onclick="testPayload('javascript:alert(document.cookie)')">
                        <span class="label">JavaScript Protocol:</span>
                        javascript:alert(document.cookie)
                    </div>
                    <div class="payload-item" onclick="testPayload('<body onload=alert(1)>')">
                        <span class="label">Body Onload:</span>
                        &lt;body onload=alert(1)&gt;
                    </div>
                    <div class="payload-item" onclick="testPayload('<iframe src=javascript:alert(1)>')">
                        <span class="label">IFrame Attack:</span>
                        &lt;iframe src=javascript:alert(1)&gt;
                    </div>
                    <div class="payload-item" onclick="testPayload('document.write(String.fromCharCode(88,83,83))')">
                        <span class="label">Obfuscated Attack:</span>
                        document.write(String.fromCharCode(88,83,83))
                    </div>
                    <div class="payload-item" onclick="testPayload('Hello World')">
                        <span class="label">✅ Safe Input:</span>
                        Hello World
                    </div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p><strong>Project Demonstration System</strong></p>
            <p>Integrated XSS Detection: WAF + Machine Learning</p>
        </div>
    </div>
    
    <script>
        function testPayload(payload) {
            document.getElementById('input').value = payload;
            document.querySelector('form').submit();
        }
    </script>
</body>
</html>