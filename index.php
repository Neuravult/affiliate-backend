<?php

// neuravult_affiliate_backend.php - Complete Advanced Affiliate System
// Enhanced with real-time tracking, security upgrades, and performance optimizations

// ==================== CONFIGURATION & SETUP ====================

class Config {
    // Database configuration - UPDATED FOR FLEXIBLE DEPLOYMENT
    public static $DB_DRIVER = 'mysql'; // 'mysql' or 'sqlite'
    public static $DB_HOST = 'localhost';
    public static $DB_NAME = 'neuravult_affiliate';
    public static $DB_USER = 'root';
    public static $DB_PASS = '';
    public static $SQLITE_PATH = __DIR__ . '/database.sqlite';

    // JWT Configuration
    public static $JWT_SECRET = 'neuravult_affiliate_secret_key_2024_advanced_secure';
    public static $JWT_ALGORITHM = 'HS256';

    // Application Settings
    public static $APP_URL = 'https://yourdomain.com';
    public static $APP_NAME = 'NeuraVult Affiliate';

    // CORS Configuration
    public static $ALLOWED_ORIGINS = [
        'http://localhost:3000',
        'https://neuravult.com',
        'https://www.neuravult.com'
    ];

    // Commission Structure
    public static $COMMISSION_RATES = [
        'click' => 0.10,
        'signup' => 0.00,
        'premium' => 30.00
    ];

    // Payout Settings
    public static $MIN_PAYOUT = 50.00;
    public static $PAYOUT_METHODS = ['paypal', 'bank_transfer', 'crypto'];

    // Security Settings
    public static $MAX_LOGIN_ATTEMPTS = 5;
    public static $LOGIN_TIMEOUT = 900; // 15 minutes
    public static $PASSWORD_MIN_LENGTH = 8;

    // WhatsApp Integration
    public static $WHATSAPP_NUMBER = '09161806424';
    public static $WHATSAPP_API_URL = 'https://api.whatsapp.com/send';

    // Initialize database connection with flexible driver support
    public static function getDBConnection() {
        static $db = null;
        
        if ($db === null) {
            try {
                if (self::$DB_DRIVER === 'sqlite') {
                    // SQLite connection
                    $dsn = "sqlite:" . self::$SQLITE_PATH;
                    $options = [
                        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                        PDO::ATTR_EMULATE_PREPARES => false
                    ];
                    $db = new PDO($dsn, null, null, $options);
                    
                    // Enable foreign keys for SQLite
                    $db->exec("PRAGMA foreign_keys = ON");
                } else {
                    // MySQL connection
                    $dsn = "mysql:host=" . self::$DB_HOST . ";dbname=" . self::$DB_NAME . ";charset=utf8mb4";
                    $options = [
                        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                        PDO::ATTR_EMULATE_PREPARES => false,
                        PDO::ATTR_PERSISTENT => true,
                        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
                    ];
                    $db = new PDO($dsn, self::$DB_USER, self::$DB_PASS, $options);
                }
            } catch (PDOException $e) {
                error_log("Database connection failed: " . $e->getMessage());
                throw new Exception("Database connection error: " . $e->getMessage());
            }
        }
        return $db;
    }

    // Rate limiting configuration
    public static function getRateLimit($endpoint) {
        $limits = [
            'auth/login' => ['requests' => 5, 'window' => 300],
            'auth/register' => ['requests' => 3, 'window' => 600],
            'user/stats' => ['requests' => 60, 'window' => 60],
            'admin/' => ['requests' => 100, 'window' => 60]
        ];

        foreach ($limits as $key => $value) {
            if (strpos($endpoint, $key) === 0) {
                return $value;
            }
        }
        return ['requests' => 100, 'window' => 60]; // Default
    }
}

// ==================== SECURITY & CORS HEADERS ====================

header('Access-Control-Allow-Origin: ' . implode(',', Config::$ALLOWED_ORIGINS));
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, PATCH');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-API-Key');
header('Access-Control-Allow-Credentials: true');
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit();
}

// ==================== ADVANCED JWT AUTHENTICATION ====================

class AdvancedJWT {
    private static function base64UrlEncode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode($data) {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }

    public static function encode($payload) {
        $header = [
            'typ' => 'JWT',
            'alg' => Config::$JWT_ALGORITHM,
            'iat' => time()
        ];

        $payload = array_merge([
            'iss' => Config::$APP_URL,
            'aud' => Config::$APP_NAME,
            'iat' => time(),
            'exp' => time() + (24 * 60 * 60), // 24 hours
            'jti' => bin2hex(random_bytes(16)) // Unique token ID
        ], $payload);

        $encodedHeader = self::base64UrlEncode(json_encode($header));
        $encodedPayload = self::base64UrlEncode(json_encode($payload));
        $signature = hash_hmac('sha256', $encodedHeader . "." . $encodedPayload, Config::$JWT_SECRET, true);
        $encodedSignature = self::base64UrlEncode($signature);

        return $encodedHeader . "." . $encodedPayload . "." . $encodedSignature;
    }

    public static function decode($jwt) {
        $tokenParts = explode('.', $jwt);
        if (count($tokenParts) != 3) {
            throw new Exception("Invalid token format");
        }

        list($encodedHeader, $encodedPayload, $encodedSignature) = $tokenParts;

        // Verify signature
        $signature = self::base64UrlDecode($encodedSignature);
        $expectedSignature = hash_hmac('sha256', $encodedHeader . "." . $encodedPayload, Config::$JWT_SECRET, true);

        if (!hash_equals($signature, $expectedSignature)) {
            throw new Exception("Invalid signature");
        }

        $payload = json_decode(self::base64UrlDecode($encodedPayload), true);

        // Validate claims
        $currentTime = time();
        if (isset($payload['exp']) && $payload['exp'] < $currentTime) {
            throw new Exception("Token expired");
        }

        if (isset($payload['nbf']) && $payload['nbf'] > $currentTime) {
            throw new Exception("Token not yet valid");
        }

        if (isset($payload['iss']) && $payload['iss'] !== Config::$APP_URL) {
            throw new Exception("Invalid issuer");
        }

        return $payload;
    }

    public static function validateToken($token) {
        try {
            // Check token blacklist
            self::checkTokenBlacklist($token);
            $decoded = self::decode($token);
            return $decoded;
        } catch (Exception $e) {
            throw new Exception("Token validation failed: " . $e->getMessage());
        }
    }

    private static function checkTokenBlacklist($token) {
        $db = Config::getDBConnection();
        $stmt = $db->prepare("SELECT id FROM jwt_blacklist WHERE token = ? AND expires_at > NOW()");
        $stmt->execute([hash('sha256', $token)]);
        
        if ($stmt->fetch()) {
            throw new Exception("Token revoked");
        }
    }

    public static function revokeToken($token) {
        $decoded = self::decode($token);
        $db = Config::getDBConnection();
        $stmt = $db->prepare("INSERT INTO jwt_blacklist (token, expires_at) VALUES (?, FROM_UNIXTIME(?))");
        $stmt->execute([hash('sha256', $token), $decoded['exp']]);
    }
}

// ==================== SECURITY MIDDLEWARE ====================

class SecurityMiddleware {
    public static function rateLimit($endpoint, $identifier) {
        $limitConfig = Config::getRateLimit($endpoint);
        $window = $limitConfig['window'];
        $maxRequests = $limitConfig['requests'];

        $db = Config::getDBConnection();
        $windowStart = time() - $window;

        // Clean old records
        $db->prepare("DELETE FROM rate_limits WHERE timestamp < ?")->execute([$windowStart]);

        // Count recent requests
        $stmt = $db->prepare("SELECT COUNT(*) as count FROM rate_limits WHERE identifier = ? AND endpoint = ? AND timestamp >= ?");
        $stmt->execute([$identifier, $endpoint, $windowStart]);
        $count = $stmt->fetch()['count'];

        if ($count >= $maxRequests) {
            http_response_code(429);
            echo json_encode(['success' => false, 'message' => 'Rate limit exceeded']);
            exit();
        }

        // Log this request
        $db->prepare("INSERT INTO rate_limits (identifier, endpoint, timestamp) VALUES (?, ?, ?)")
            ->execute([$identifier, $endpoint, time()]);
    }

    public static function sanitizeInput($data) {
        if (is_array($data)) {
            return array_map([self::class, 'sanitizeInput'], $data);
        }
        $data = trim($data);
        $data = stripslashes($data);
        $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
        return $data;
    }

    public static function validateEmail($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    public static function validateURL($url) {
        return filter_var($url, FILTER_VALIDATE_URL) !== false;
    }

    public static function generateCSRFToken() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }

    public static function verifyCSRFToken($token) {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
    }
}

// ==================== AUTHENTICATION MIDDLEWARE ====================

function authenticate() {
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? ($headers['authorization'] ?? null);

    if (!$authHeader) {
        http_response_code(401);
        echo json_encode(['success' => false, 'message' => 'Authorization header required']);
        exit();
    }

    $token = str_replace('Bearer ', '', $authHeader);

    try {
        $decoded = AdvancedJWT::validateToken($token);
        return $decoded;
    } catch (Exception $e) {
        http_response_code(401);
        echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        exit();
    }
}

function authorizeAdmin($user) {
    if ($user['role'] !== 'admin') {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Admin access required']);
        exit();
    }
}

function authorizeUser($user, $userId) {
    if ($user['role'] !== 'admin' && $user['user_id'] != $userId) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Access denied']);
        exit();
    }
}

// ==================== UTILITY FUNCTIONS ====================

function getJsonInput() {
    $input = json_decode(file_get_contents('php://input'), true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('Invalid JSON input: ' . json_last_error_msg());
    }
    return SecurityMiddleware::sanitizeInput($input);
}

function generateAffiliateId() {
    $prefix = 'NV';
    $timestamp = substr(time(), -4);
    $random = strtoupper(bin2hex(random_bytes(3)));
    return $prefix . $timestamp . $random;
}

function generateReferralCode() {
    return substr(md5(uniqid() . microtime()), 0, 12);
}

function formatCurrency($amount) {
    return '$' . number_format($amount, 2);
}

function logActivity($userId, $action, $details = '') {
    $db = Config::getDBConnection();
    $stmt = $db->prepare("INSERT INTO activity_logs (user_id, action, details, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)");
    $stmt->execute([$userId, $action, $details, $_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT'] ?? '']);
}

// ==================== AUTHENTICATION CONTROLLER ====================

class AuthController {
    public static function login() {
        SecurityMiddleware::rateLimit('auth/login', $_SERVER['REMOTE_ADDR']);

        try {
            $data = getJsonInput();
            $email = $data['email'] ?? '';
            $password = $data['password'] ?? '';
            $remember = $data['remember'] ?? false;

            // Input validation
            if (!SecurityMiddleware::validateEmail($email) || empty($password)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'Valid email and password required']);
                return;
            }

            $db = Config::getDBConnection();

            // Check login attempts
            $stmt = $db->prepare("SELECT COUNT(*) as attempts FROM login_attempts WHERE email = ? AND timestamp > DATE_SUB(NOW(), INTERVAL 15 MINUTE)");
            $stmt->execute([$email]);
            $attempts = $stmt->fetch()['attempts'];

            if ($attempts >= Config::$MAX_LOGIN_ATTEMPTS) {
                http_response_code(429);
                echo json_encode(['success' => false, 'message' => 'Too many login attempts. Try again in 15 minutes.']);
                return;
            }

            // Get user
            $stmt = $db->prepare("SELECT * FROM users WHERE email = ?");
            $stmt->execute([$email]);
            $user = $stmt->fetch();

            if (!$user || !password_verify($password, $user['password_hash'])) {
                // Log failed attempt
                $db->prepare("INSERT INTO login_attempts (email, ip_address, user_agent) VALUES (?, ?, ?)")
                    ->execute([$email, $_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT'] ?? '']);

                http_response_code(401);
                echo json_encode(['success' => false, 'message' => 'Invalid credentials']);
                return;
            }

            if ($user['status'] !== 'active') {
                http_response_code(403);
                echo json_encode(['success' => false, 'message' => 'Account pending approval. Please contact administrator.']);
                return;
            }

            // Clear login attempts
            $db->prepare("DELETE FROM login_attempts WHERE email = ?")->execute([$email]);

            // Generate tokens
            $tokenPayload = [
                'user_id' => $user['id'],
                'email' => $user['email'],
                'role' => $user['role'],
                'affiliate_id' => $user['affiliate_id']
            ];

            $accessToken = AdvancedJWT::encode($tokenPayload);

            if ($remember) {
                $refreshToken = AdvancedJWT::encode(array_merge($tokenPayload, ['type' => 'refresh']));
            }

            // Update last login
            $db->prepare("UPDATE users SET last_login = NOW() WHERE id = ?")->execute([$user['id']]);

            // Log activity
            logActivity($user['id'], 'login', 'User logged in successfully');

            echo json_encode([
                'success' => true,
                'message' => 'Login successful',
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken ?? $accessToken,
                'expires_in' => 24 * 60 * 60,
                'user' => [
                    'id' => $user['id'],
                    'name' => $user['name'],
                    'email' => $user['email'],
                    'role' => $user['role'],
                    'affiliateId' => $user['affiliate_id'],
                    'status' => $user['status'],
                    'company' => $user['company'],
                    'website' => $user['website']
                ]
            ]);

        } catch (Exception $e) {
            error_log("Login error: " . $e->getMessage());
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Login failed: ' . $e->getMessage()]);
        }
    }

    public static function register() {
        SecurityMiddleware::rateLimit('auth/register', $_SERVER['REMOTE_ADDR']);

        try {
            $data = getJsonInput();
            $name = trim($data['name'] ?? '');
            $email = $data['email'] ?? '';
            $password = $data['password'] ?? '';
            $confirmPassword = $data['confirm_password'] ?? '';
            $website = $data['website'] ?? '';
            $company = trim($data['company'] ?? '');

            // Validation
            if (empty($name) || !SecurityMiddleware::validateEmail($email) || empty($password)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'Name, valid email, and password are required']);
                return;
            }

            if ($password !== $confirmPassword) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'Passwords do not match']);
                return;
            }

            if (strlen($password) < Config::$PASSWORD_MIN_LENGTH) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'Password must be at least ' . Config::$PASSWORD_MIN_LENGTH . ' characters']);
                return;
            }

            if ($website && !SecurityMiddleware::validateURL($website)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'Invalid website URL']);
                return;
            }

            $db = Config::getDBConnection();

            // Check if email exists
            $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
            $stmt->execute([$email]);
            if ($stmt->fetch()) {
                http_response_code(409);
                echo json_encode(['success' => false, 'message' => 'Email already registered']);
                return;
            }

            // Generate affiliate ID
            $affiliateId = generateAffiliateId();
            $passwordHash = password_hash($password, PASSWORD_DEFAULT);

            // Start transaction
            $db->beginTransaction();

            try {
                // Create user
                $stmt = $db->prepare("INSERT INTO users (name, email, password_hash, affiliate_id, company, website) VALUES (?, ?, ?, ?, ?, ?)");
                $stmt->execute([$name, $email, $passwordHash, $affiliateId, $company, $website]);
                $userId = $db->lastInsertId();

                // Create user stats
                $stmt = $db->prepare("INSERT INTO user_stats (user_id) VALUES (?)");
                $stmt->execute([$userId]);

                // Create default referral link
                $referralCode = generateReferralCode();
                $stmt = $db->prepare("INSERT INTO referral_links (user_id, name, description, url, unique_code) VALUES (?, 'Default Link', 'Main referral link', ?, ?)");
                $stmt->execute([$userId, Config::$APP_URL, $referralCode]);

                $db->commit();

                // Get created user
                $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
                $stmt->execute([$userId]);
                $user = $stmt->fetch();

                // Generate token
                $tokenPayload = [
                    'user_id' => $user['id'],
                    'email' => $user['email'],
                    'role' => $user['role'],
                    'affiliate_id' => $user['affiliate_id']
                ];

                $token = AdvancedJWT::encode($tokenPayload);

                // Log activity
                logActivity($userId, 'register', 'New user registration');

                http_response_code(201);
                echo json_encode([
                    'success' => true,
                    'message' => 'Registration successful - pending approval',
                    'access_token' => $token,
                    'user' => [
                        'id' => $user['id'],
                        'name' => $user['name'],
                        'email' => $user['email'],
                        'role' => $user['role'],
                        'affiliateId' => $user['affiliate_id'],
                        'status' => $user['status']
                    ]
                ]);

            } catch (Exception $e) {
                $db->rollBack();
                throw $e;
            }

        } catch (Exception $e) {
            error_log("Registration error: " . $e->getMessage());
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Registration failed: ' . $e->getMessage()]);
        }
    }

    public static function logout() {
        try {
            $user = authenticate();
            $data = getJsonInput();
            $token = str_replace('Bearer ', '', getallheaders()['Authorization'] ?? '');

            // Revoke token
            AdvancedJWT::revokeToken($token);

            // Log activity
            logActivity($user['user_id'], 'logout', 'User logged out');

            echo json_encode(['success' => true, 'message' => 'Logout successful']);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Logout failed']);
        }
    }

    public static function refreshToken() {
        try {
            $data = getJsonInput();
            $refreshToken = $data['refresh_token'] ?? '';

            if (!$refreshToken) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'Refresh token required']);
                return;
            }

            $decoded = AdvancedJWT::validateToken($refreshToken);

            if ($decoded['type'] !== 'refresh') {
                throw new Exception("Invalid token type");
            }

            $db = Config::getDBConnection();
            $stmt = $db->prepare("SELECT * FROM users WHERE id = ? AND status = 'active'");
            $stmt->execute([$decoded['user_id']]);
            $user = $stmt->fetch();

            if (!$user) {
                http_response_code(401);
                echo json_encode(['success' => false, 'message' => 'User not found or inactive']);
                return;
            }

            $tokenPayload = [
                'user_id' => $user['id'],
                'email' => $user['email'],
                'role' => $user['role'],
                'affiliate_id' => $user['affiliate_id']
            ];

            $newAccessToken = AdvancedJWT::encode($tokenPayload);

            echo json_encode([
                'success' => true,
                'access_token' => $newAccessToken,
                'expires_in' => 24 * 60 * 60
            ]);

        } catch (Exception $e) {
            http_response_code(401);
            echo json_encode(['success' => false, 'message' => 'Token refresh failed: ' . $e->getMessage()]);
        }
    }

    public static function forgotPassword() {
        SecurityMiddleware::rateLimit('auth/forgot-password', $_SERVER['REMOTE_ADDR']);

        try {
            $data = getJsonInput();
            $email = $data['email'] ?? '';

            if (!SecurityMiddleware::validateEmail($email)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'Valid email required']);
                return;
            }

            $db = Config::getDBConnection();
            $stmt = $db->prepare("SELECT id, name FROM users WHERE email = ? AND status = 'active'");
            $stmt->execute([$email]);
            $user = $stmt->fetch();

            if ($user) {
                // Generate reset token (in real implementation, send email)
                $resetToken = bin2hex(random_bytes(32));
                $expires = time() + (60 * 60); // 1 hour

                $stmt = $db->prepare("INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)");
                $stmt->execute([$email, hash('sha256', $resetToken), date('Y-m-d H:i:s', $expires)]);

                // In production, send email with reset link
                logActivity($user['id'], 'forgot_password', 'Password reset requested');
            }

            // Always return success to prevent email enumeration
            echo json_encode(['success' => true, 'message' => 'If the email exists, a reset link has been sent']);

        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Password reset failed']);
        }
    }
}

// ==================== USER CONTROLLER ====================

class UserController {
    public static function getProfile() {
        try {
            $user = authenticate();
            SecurityMiddleware::rateLimit('user/profile', $user['user_id']);

            $db = Config::getDBConnection();
            $stmt = $db->prepare("
                SELECT id, name, email, affiliate_id, role, status, company, website,
                created_at, last_login, updated_at
                FROM users
                WHERE id = ?
            ");
            $stmt->execute([$user['user_id']]);
            $profile = $stmt->fetch();

            if (!$profile) {
                http_response_code(404);
                echo json_encode(['success' => false, 'message' => 'User not found']);
                return;
            }

            echo json_encode(['success' => true, 'data' => $profile]);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
    }

    public static function updateProfile() {
        try {
            $user = authenticate();
            $data = getJsonInput();
            $name = trim($data['name'] ?? '');
            $company = trim($data['company'] ?? '');
            $website = $data['website'] ?? '';

            if (empty($name)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'Name is required']);
                return;
            }

            if ($website && !SecurityMiddleware::validateURL($website)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'Invalid website URL']);
                return;
            }

            $db = Config::getDBConnection();
            $stmt = $db->prepare("UPDATE users SET name = ?, company = ?, website = ? WHERE id = ?");
            $stmt->execute([$name, $company, $website, $user['user_id']]);

            logActivity($user['user_id'], 'update_profile', 'Profile updated');

            echo json_encode(['success' => true, 'message' => 'Profile updated successfully']);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
    }

    public static function getStats() {
        try {
            $user = authenticate();
            SecurityMiddleware::rateLimit('user/stats', $user['user_id']);

            $db = Config::getDBConnection();

            // Basic stats
            $stmt = $db->prepare("SELECT * FROM user_stats WHERE user_id = ?");
            $stmt->execute([$user['user_id']]);
            $stats = $stmt->fetch();

            if (!$stats) {
                http_response_code(404);
                echo json_encode(['success' => false, 'message' => 'Stats not found']);
                return;
            }

            // Recent activity (30 days)
            $stmt = $db->prepare("
                SELECT type, status, COUNT(*) as count, DATE(referral_date) as date
                FROM referrals
                WHERE referrer_id = ? AND referral_date >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                GROUP BY type, status, DATE(referral_date)
                ORDER BY date DESC
            ");
            $stmt->execute([$user['user_id']]);
            $recentActivity = $stmt->fetchAll();

            // Performance metrics
            $stmt = $db->prepare("
                SELECT
                COUNT(*) as total_clicks,
                SUM(CASE WHEN type = 'signup' THEN 1 ELSE 0 END) as signups,
                SUM(CASE WHEN type = 'premium' THEN 1 ELSE 0 END) as premium_conversions,
                SUM(earnings) as total_earnings
                FROM referrals
                WHERE referrer_id = ? AND status != 'pending'
            ");
            $stmt->execute([$user['user_id']]);
            $performance = $stmt->fetch();

            echo json_encode([
                'success' => true,
                'data' => $stats,
                'performance' => $performance,
                'recent_activity' => $recentActivity
            ]);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
    }

    public static function getReferralLinks() {
        try {
            $user = authenticate();
            $db = Config::getDBConnection();

            $stmt = $db->prepare("
                SELECT id, name, description, url, unique_code, click_count, conversion_count, created_at
                FROM referral_links
                WHERE user_id = ?
                ORDER BY created_at DESC
            ");
            $stmt->execute([$user['user_id']]);
            $links = $stmt->fetchAll();

            // Generate full URLs with tracking
            foreach ($links as &$link) {
                $link['full_url'] = Config::$APP_URL . "/?ref=" . $link['unique_code'];
                $link['short_url'] = self::generateShortUrl($link['unique_code']);
            }

            echo json_encode(['success' => true, 'data' => $links]);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
    }

    public static function createReferralLink() {
        try {
            $user = authenticate();
            $data = getJsonInput();
            $name = trim($data['name'] ?? '');
            $description = trim($data['description'] ?? '');
            $customCode = trim($data['custom_code'] ?? '');

            if (empty($name)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'Link name is required']);
                return;
            }

            $db = Config::getDBConnection();

            // Check if custom code is available
            if ($customCode) {
                $stmt = $db->prepare("SELECT id FROM referral_links WHERE unique_code = ?");
                $stmt->execute([$customCode]);
                if ($stmt->fetch()) {
                    http_response_code(409);
                    echo json_encode(['success' => false, 'message' => 'Custom code already taken']);
                    return;
                }
                $uniqueCode = $customCode;
            } else {
                $uniqueCode = generateReferralCode();
            }

            $stmt = $db->prepare("
                INSERT INTO referral_links (user_id, name, description, url, unique_code)
                VALUES (?, ?, ?, ?, ?)
            ");
            $stmt->execute([$user['user_id'], $name, $description, Config::$APP_URL, $uniqueCode]);
            $linkId = $db->lastInsertId();

            // Get created link
            $stmt = $db->prepare("SELECT * FROM referral_links WHERE id = ?");
            $stmt->execute([$linkId]);
            $link = $stmt->fetch();

            $link['full_url'] = Config::$APP_URL . "/?ref=" . $link['unique_code'];
            $link['short_url'] = self::generateShortUrl($link['unique_code']);

            logActivity($user['user_id'], 'create_referral_link', 'Created new referral link: ' . $name);

            http_response_code(201);
            echo json_encode(['success' => true, 'message' => 'Referral link created', 'data' => $link]);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
    }

    public static function getReferrals() {
        try {
            $user = authenticate();
            $page = max(1, intval($_GET['page'] ?? 1));
            $limit = min(100, max(10, intval($_GET['limit'] ?? 20)));
            $offset = ($page - 1) * $limit;

            $db = Config::getDBConnection();

            // Get referrals with pagination
            $stmt = $db->prepare("
                SELECT r.*, rl.name as link_name
                FROM referrals r
                LEFT JOIN referral_links rl ON r.referral_link_id = rl.id
                WHERE r.referrer_id = ?
                ORDER BY r.referral_date DESC
                LIMIT ? OFFSET ?
            ");
            $stmt->execute([$user['user_id'], $limit, $offset]);
            $referrals = $stmt->fetchAll();

            // Get total count
            $stmt = $db->prepare("SELECT COUNT(*) as total FROM referrals WHERE referrer_id = ?");
            $stmt->execute([$user['user_id']]);
            $total = $stmt->fetch()['total'];

            echo json_encode([
                'success' => true,
                'data' => $referrals,
                'pagination' => [
                    'page' => $page,
                    'limit' => $limit,
                    'total' => $total,
                    'pages' => ceil($total / $limit)
                ]
            ]);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
    }

    public static function getPayouts() {
        try {
            $user = authenticate();
            $db = Config::getDBConnection();

            $stmt = $db->prepare("
                SELECT id, amount, method, status, requested_at, processed_at
                FROM payouts
                WHERE user_id = ?
                ORDER BY requested_at DESC
            ");
            $stmt->execute([$user['user_id']]);
            $payouts = $stmt->fetchAll();

            echo json_encode(['success' => true, 'data' => $payouts]);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
    }

    public static function requestPayout() {
        try {
            $user = authenticate();
            $data = getJsonInput();
            $amount = floatval($data['amount'] ?? 0);
            $method = $data['method'] ?? '';
            $accountName = trim($data['account_name'] ?? '');
            $accountNumber = trim($data['account_number'] ?? '');

            // Validation
            if ($amount < Config::$MIN_PAYOUT) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'Minimum payout amount is ' . formatCurrency(Config::$MIN_PAYOUT)]);
                return;
            }

            if (!in_array($method, Config::$PAYOUT_METHODS)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'Invalid payment method']);
                return;
            }

            if (empty($accountName) || empty($accountNumber)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'Account details are required']);
                return;
            }

            $db = Config::getDBConnection();

            // Check available balance
            $stmt = $db->prepare("SELECT available_balance FROM user_stats WHERE user_id = ?");
            $stmt->execute([$user['user_id']]);
            $stats = $stmt->fetch();

            if (!$stats || $stats['available_balance'] < $amount) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'Insufficient balance']);
                return;
            }

            // Check pending payouts
            $stmt = $db->prepare("SELECT COUNT(*) as pending FROM payouts WHERE user_id = ? AND status = 'pending'");
            $stmt->execute([$user['user_id']]);
            if ($stmt->fetch()['pending'] > 0) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'You already have a pending payout request']);
                return;
            }

            // Create payout request
            $stmt = $db->prepare("
                INSERT INTO payouts (user_id, amount, method, account_name, account_number)
                VALUES (?, ?, ?, ?, ?)
            ");
            $stmt->execute([$user['user_id'], $amount, $method, $accountName, $accountNumber]);

            // Update available balance
            $stmt = $db->prepare("UPDATE user_stats SET available_balance = available_balance - ? WHERE user_id = ?");
            $stmt->execute([$amount, $user['user_id']]);

            // Generate WhatsApp message
            $whatsappMessage = self::generateWhatsAppMessage($user, $data);

            logActivity($user['user_id'], 'request_payout', 'Payout requested: ' . formatCurrency($amount));

            http_response_code(201);
            echo json_encode([
                'success' => true,
                'message' => 'Payout request submitted',
                'whatsapp_message' => $whatsappMessage
            ]);

        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
    }

    private static function generateShortUrl($code) {
        // In production, integrate with URL shortener service
        return Config::$APP_URL . "/r/" . $code;
    }

    private static function generateWhatsAppMessage($user, $payoutData) {
        $message = "Withdrawal Request%0A%0A";
        $message .= "User: " . urlencode($user['name']) . "%0A";
        $message .= "Email: " . urlencode($user['email']) . "%0A";
        $message .= "Affiliate ID: " . urlencode($user['affiliate_id']) . "%0A";
        $message .= "Amount: " . urlencode(formatCurrency($payoutData['amount'])) . "%0A";
        $message .= "Method: " . urlencode($payoutData['method']) . "%0A";
        $message .= "Account Name: " . urlencode($payoutData['account_name']) . "%0A";
        $message .= "Account Number: " . urlencode($payoutData['account_number']) . "%0A%0A";
        $message .= "Please process this payout request.";

        return Config::$WHATSAPP_API_URL . "?phone=" . Config::$WHATSAPP_NUMBER . "&text=" . $message;
    }
}

// ==================== ADMIN CONTROLLER ====================

class AdminController {
    public static function getDashboardStats() {
        try {
            $user = authenticate();
            authorizeAdmin($user);
            SecurityMiddleware::rateLimit('admin/dashboard', $user['user_id']);

            $db = Config::getDBConnection();

            // Overall stats
            $stats = [
                'total_affiliates' => 0,
                'active_affiliates' => 0,
                'pending_affiliates' => 0,
                'total_referrals' => 0,
                'premium_referrals' => 0,
                'total_payouts' => 0,
                'pending_payouts' => 0,
                'total_revenue' => 0
            ];

            // Affiliate counts
            $stmt = $db->prepare("SELECT status, COUNT(*) as count FROM users WHERE role = 'user' GROUP BY status");
            $stmt->execute();
            $affiliateStats = $stmt->fetchAll();

            foreach ($affiliateStats as $stat) {
                $stats['total_affiliates'] += $stat['count'];
                if ($stat['status'] === 'active') $stats['active_affiliates'] = $stat['count'];
                if ($stat['status'] === 'pending') $stats['pending_affiliates'] = $stat['count'];
            }

            // Referral stats
            $stmt = $db->prepare("SELECT COUNT(*) as total, SUM(CASE WHEN type = 'premium' THEN 1 ELSE 0 END) as premium FROM referrals");
            $stmt->execute();
            $referralStats = $stmt->fetch();
            $stats['total_referrals'] = $referralStats['total'];
            $stats['premium_referrals'] = $referralStats['premium'];

            // Payout stats
            $stmt = $db->prepare("SELECT status, SUM(amount) as total FROM payouts GROUP BY status");
            $stmt->execute();
            $payoutStats = $stmt->fetchAll();

            foreach ($payoutStats as $stat) {
                $stats['total_payouts'] += $stat['total'];
                if ($stat['status'] === 'pending') $stats['pending_payouts'] = $stat['total'];
            }

            // Revenue estimation
            $stats['total_revenue'] = $stats['premium_referrals'] * 100; // Assuming $100 per premium

            // Recent activity
            $stmt = $db->prepare("
                SELECT a.*, u.name as user_name
                FROM activity_logs a
                JOIN users u ON a.user_id = u.id
                ORDER BY a.timestamp DESC
                LIMIT 10
            ");
            $stmt->execute();
            $recentActivity = $stmt->fetchAll();

            echo json_encode([
                'success' => true,
                'stats' => $stats,
                'recent_activity' => $recentActivity
            ]);

        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
    }

    public static function getUsers() {
        try {
            $user = authenticate();
            authorizeAdmin($user);

            $page = max(1, intval($_GET['page'] ?? 1));
            $limit = min(100, max(10, intval($_GET['limit'] ?? 20)));
            $offset = ($page - 1) * $limit;
            $status = $_GET['status'] ?? '';
            $search = $_GET['search'] ?? '';

            $db = Config::getDBConnection();

            $whereConditions = ["u.role = 'user'"];
            $params = [];

            if ($status && in_array($status, ['active', 'pending', 'suspended'])) {
                $whereConditions[] = "u.status = ?";
                $params[] = $status;
            }

            if ($search) {
                $whereConditions[] = "(u.name LIKE ? OR u.email LIKE ? OR u.affiliate_id LIKE ?)";
                $searchTerm = "%$search%";
                $params[] = $searchTerm;
                $params[] = $searchTerm;
                $params[] = $searchTerm;
            }

            $whereClause = implode(' AND ', $whereConditions);

            // Get users
            $stmt = $db->prepare("
                SELECT u.*, us.total_earnings, us.available_balance, us.total_referrals
                FROM users u
                LEFT JOIN user_stats us ON u.id = us.user_id
                WHERE $whereClause
                ORDER BY u.created_at DESC
                LIMIT ? OFFSET ?
            ");
            $stmt->execute(array_merge($params, [$limit, $offset]));
            $users = $stmt->fetchAll();

            // Get total count
            $stmt = $db->prepare("SELECT COUNT(*) as total FROM users u WHERE $whereClause");
            $stmt->execute($params);
            $total = $stmt->fetch()['total'];

            echo json_encode([
                'success' => true,
                'data' => $users,
                'pagination' => [
                    'page' => $page,
                    'limit' => $limit,
                    'total' => $total,
                    'pages' => ceil($total / $limit)
                ]
            ]);

        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
    }

    public static function updateUserStatus() {
        try {
            $user = authenticate();
            authorizeAdmin($user);
            $data = getJsonInput();
            $userId = intval($data['user_id'] ?? 0);
            $status = $data['status'] ?? '';
            $notes = trim($data['notes'] ?? '');

            if (!$userId || !in_array($status, ['active', 'suspended', 'pending'])) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'Invalid user ID or status']);
                return;
            }

            $db = Config::getDBConnection();
            $stmt = $db->prepare("UPDATE users SET status = ? WHERE id = ?");
            $stmt->execute([$status, $userId]);

            // Log status change
            logActivity($user['user_id'], 'update_user_status', "User $userId status changed to $status");

            echo json_encode(['success' => true, 'message' => 'User status updated successfully']);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
    }

    public static function getPayoutRequests() {
        try {
            $user = authenticate();
            authorizeAdmin($user);
            $status = $_GET['status'] ?? '';

            $db = Config::getDBConnection();

            $whereConditions = ["1=1"];
            $params = [];

            if ($status && in_array($status, ['pending', 'approved', 'paid', 'rejected'])) {
                $whereConditions[] = "p.status = ?";
                $params[] = $status;
            }

            $whereClause = implode(' AND ', $whereConditions);

            $stmt = $db->prepare("
                SELECT p.*, u.name as user_name, u.email, u.affiliate_id
                FROM payouts p
                JOIN users u ON p.user_id = u.id
                WHERE $whereClause
                ORDER BY p.requested_at DESC
            ");
            $stmt->execute($params);
            $payouts = $stmt->fetchAll();

            echo json_encode(['success' => true, 'data' => $payouts]);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
    }

    public static function updatePayoutStatus() {
        try {
            $user = authenticate();
            authorizeAdmin($user);
            $data = getJsonInput();
            $payoutId = intval($data['payout_id'] ?? 0);
            $status = $data['status'] ?? '';
            $notes = trim($data['notes'] ?? '');

            if (!$payoutId || !in_array($status, ['approved', 'paid', 'rejected'])) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'Invalid payout ID or status']);
                return;
            }

            $db = Config::getDBConnection();

            if ($status === 'rejected') {
                // Return amount to user's available balance
                $stmt = $db->prepare("
                    UPDATE user_stats us
                    JOIN payouts p ON us.user_id = p.user_id
                    SET us.available_balance = us.available_balance + p.amount
                    WHERE p.id = ?
                ");
                $stmt->execute([$payoutId]);
            }

            $stmt = $db->prepare("UPDATE payouts SET status = ?, processed_at = NOW() WHERE id = ?");
            $stmt->execute([$status, $payoutId]);

            logActivity($user['user_id'], 'update_payout_status', "Payout $payoutId status changed to $status");

            echo json_encode(['success' => true, 'message' => 'Payout status updated successfully']);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
    }
}

// ==================== CHALLENGE CONTROLLER ====================

class ChallengeController {
    public static function getChallenges() {
        try {
            $user = authenticate();
            $db = Config::getDBConnection();

            $stmt = $db->prepare("
                SELECT c.*, u.name as created_by_name,
                (SELECT COUNT(*) FROM challenge_submissions WHERE challenge_id = c.id) as participant_count,
                (SELECT COUNT(*) FROM challenge_submissions WHERE challenge_id = c.id AND user_id = ?) as user_participation
                FROM challenges c
                JOIN users u ON c.created_by = u.id
                WHERE c.status = 'active' AND c.deadline >= CURDATE()
                ORDER BY c.created_at DESC
            ");
            $stmt->execute([$user['user_id']]);
            $challenges = $stmt->fetchAll();

            echo json_encode(['success' => true, 'data' => $challenges]);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
    }

    public static function acceptChallenge($challengeId) {
        try {
            $user = authenticate();
            $challengeId = intval($challengeId);

            $db = Config::getDBConnection();

            // Check if challenge exists and is active
            $stmt = $db->prepare("SELECT id FROM challenges WHERE id = ? AND status = 'active' AND deadline >= CURDATE()");
            $stmt->execute([$challengeId]);
            if (!$stmt->fetch()) {
                http_response_code(404);
                echo json_encode(['success' => false, 'message' => 'Challenge not available']);
                return;
            }

            // Check if already accepted
            $stmt = $db->prepare("SELECT id FROM challenge_submissions WHERE challenge_id = ? AND user_id = ?");
            $stmt->execute([$challengeId, $user['user_id']]);
            if ($stmt->fetch()) {
                http_response_code(409);
                echo json_encode(['success' => false, 'message' => 'Challenge already accepted']);
                return;
            }

            // Create submission
            $stmt = $db->prepare("INSERT INTO challenge_submissions (challenge_id, user_id, status) VALUES (?, ?, 'accepted')");
            $stmt->execute([$challengeId, $user['user_id']]);

            logActivity($user['user_id'], 'accept_challenge', "Accepted challenge $challengeId");

            echo json_encode(['success' => true, 'message' => 'Challenge accepted successfully']);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
    }

    public static function submitChallenge($challengeId) {
        try {
            $user = authenticate();
            $data = getJsonInput();
            $challengeId = intval($challengeId);
            $proof = trim($data['proof'] ?? '');
            $notes = trim($data['notes'] ?? '');

            if (empty($proof)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'Proof of completion is required']);
                return;
            }

            $db = Config::getDBConnection();

            // Update submission
            $stmt = $db->prepare("
                UPDATE challenge_submissions
                SET proof = ?, notes = ?, status = 'pending', submitted_at = NOW()
                WHERE challenge_id = ? AND user_id = ?
            ");
            $stmt->execute([$proof, $notes, $challengeId, $user['user_id']]);

            if ($stmt->rowCount() === 0) {
                http_response_code(404);
                echo json_encode(['success' => false, 'message' => 'Challenge submission not found']);
                return;
            }

            logActivity($user['user_id'], 'submit_challenge', "Submitted challenge $challengeId");

            echo json_encode(['success' => true, 'message' => 'Challenge submitted for review']);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
    }
}

// ==================== TRACKING CONTROLLER ====================

class TrackingController {
    public static function trackReferral() {
        try {
            $referralCode = $_GET['ref'] ?? '';
            $source = $_GET['source'] ?? 'direct';
            $campaign = $_GET['campaign'] ?? '';

            if (empty($referralCode)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'Referral code required']);
                return;
            }

            $db = Config::getDBConnection();

            // Get referral link
            $stmt = $db->prepare("
                SELECT rl.*, u.id as user_id, u.status as user_status
                FROM referral_links rl
                JOIN users u ON rl.user_id = u.id
                WHERE rl.unique_code = ? AND u.status = 'active'
            ");
            $stmt->execute([$referralCode]);
            $link = $stmt->fetch();

            if (!$link) {
                http_response_code(404);
                echo json_encode(['success' => false, 'message' => 'Invalid referral code']);
                return;
            }

            // Record the click
            $stmt = $db->prepare("
                INSERT INTO referrals (referrer_id, referral_link_id, type, status, ip_address, user_agent, source, campaign)
                VALUES (?, ?, 'click', 'active', ?, ?, ?, ?)
            ");
            $stmt->execute([
                $link['user_id'],
                $link['id'],
                $_SERVER['REMOTE_ADDR'],
                $_SERVER['HTTP_USER_AGENT'] ?? '',
                $source,
                $campaign
            ]);

            // Update click count
            $db->prepare("UPDATE referral_links SET click_count = click_count + 1 WHERE id = ?")->execute([$link['id']]);
            $db->prepare("UPDATE user_stats SET total_clicks = total_clicks + 1 WHERE user_id = ?")->execute([$link['user_id']]);

            // Add commission for click
            $commission = Config::$COMMISSION_RATES['click'];
            $db->prepare("
                UPDATE user_stats
                SET total_earnings = total_earnings + ?, available_balance = available_balance + ?
                WHERE user_id = ?
            ")->execute([$commission, $commission, $link['user_id']]);

            // Return success with redirect URL
            echo json_encode([
                'success' => true,
                'message' => 'Referral tracked successfully',
                'redirect_url' => Config::$APP_URL,
                'affiliate_id' => $link['user_id']
            ]);

        } catch (Exception $e) {
            error_log("Tracking error: " . $e->getMessage());
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Tracking failed']);
        }
    }
}

// ==================== API ROUTER ====================

class APIRouter {
    private static $routes = [];

    public static function addRoute($method, $path, $callback) {
        self::$routes[] = [
            'method' => strtoupper($method),
            'path' => $path,
            'callback' => $callback
        ];
    }

    public static function handleRequest() {
        $method = $_SERVER['REQUEST_METHOD'];
        $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $path = str_replace('/api', '', $path); // Remove /api prefix

        foreach (self::$routes as $route) {
            if ($route['method'] === $method && self::matchPath($route['path'], $path, $params)) {
                try {
                    call_user_func($route['callback'], $params);
                    return;
                } catch (Exception $e) {
                    error_log("Route error: " . $e->getMessage());
                    http_response_code(500);
                    echo json_encode(['success' => false, 'message' => 'Internal server error']);
                    return;
                }
            }
        }

        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'Endpoint not found']);
    }

    private static function matchPath($routePath, $requestPath, &$params) {
        $params = [];
        $routeParts = explode('/', trim($routePath, '/'));
        $requestParts = explode('/', trim($requestPath, '/'));

        if (count($routeParts) !== count($requestParts)) {
            return false;
        }

        foreach ($routeParts as $index => $routePart) {
            $requestPart = $requestParts[$index];
            if (strpos($routePart, ':') === 0) {
                $paramName = substr($routePart, 1);
                $params[$paramName] = $requestPart;
            } elseif ($routePart !== $requestPart) {
                return false;
            }
        }
        return true;
    }
}

// ==================== ROUTE DEFINITIONS ====================

// Authentication routes
APIRouter::addRoute('POST', '/auth/login', function() { AuthController::login(); });
APIRouter::addRoute('POST', '/auth/register', function() { AuthController::register(); });
APIRouter::addRoute('POST', '/auth/logout', function() { AuthController::logout(); });
APIRouter::addRoute('POST', '/auth/refresh-token', function() { AuthController::refreshToken(); });
APIRouter::addRoute('POST', '/auth/forgot-password', function() { AuthController::forgotPassword(); });

// User routes
APIRouter::addRoute('GET', '/user/profile', function() { UserController::getProfile(); });
APIRouter::addRoute('PUT', '/user/profile', function() { UserController::updateProfile(); });
APIRouter::addRoute('GET', '/user/stats', function() { UserController::getStats(); });
APIRouter::addRoute('GET', '/user/referral-links', function() { UserController::getReferralLinks(); });
APIRouter::addRoute('POST', '/user/referral-links', function() { UserController::createReferralLink(); });
APIRouter::addRoute('GET', '/user/referrals', function() { UserController::getReferrals(); });
APIRouter::addRoute('GET', '/user/payouts', function() { UserController::getPayouts(); });
APIRouter::addRoute('POST', '/user/payouts', function() { UserController::requestPayout(); });

// Admin routes
APIRouter::addRoute('GET', '/admin/dashboard-stats', function() { AdminController::getDashboardStats(); });
APIRouter::addRoute('GET', '/admin/users', function() { AdminController::getUsers(); });
APIRouter::addRoute('PUT', '/admin/users/status', function() { AdminController::updateUserStatus(); });
APIRouter::addRoute('GET', '/admin/payout-requests', function() { AdminController::getPayoutRequests(); });
APIRouter::addRoute('PUT', '/admin/payout-requests/status', function() { AdminController::updatePayoutStatus(); });

// Challenge routes
APIRouter::addRoute('GET', '/challenges', function() { ChallengeController::getChallenges(); });
APIRouter::addRoute('POST', '/challenges/:id/accept', function($params) {
    ChallengeController::acceptChallenge($params['id']);
});
APIRouter::addRoute('POST', '/challenges/:id/submit', function($params) {
    ChallengeController::submitChallenge($params['id']);
});

// Tracking routes
APIRouter::addRoute('GET', '/track', function() { TrackingController::trackReferral(); });

// ==================== DATABASE SCHEMA ====================

class DatabaseSetup {
    public static function createTables() {
        $db = Config::getDBConnection();
        
        // Dynamic schema based on database driver
        if (Config::$DB_DRIVER === 'sqlite') {
            $tables = self::getSQLiteSchema();
        } else {
            $tables = self::getMySQLSchema();
        }

        foreach ($tables as $tableSQL) {
            try {
                $db->exec($tableSQL);
            } catch (PDOException $e) {
                error_log("Table creation error: " . $e->getMessage());
            }
        }

        // Create default admin user if not exists
        $stmt = $db->prepare("SELECT id FROM users WHERE role = 'admin' LIMIT 1");
        $stmt->execute();
        if (!$stmt->fetch()) {
            $adminPassword = password_hash('admin123', PASSWORD_DEFAULT);
            $affiliateId = generateAffiliateId();
            $stmt = $db->prepare("
                INSERT INTO users (name, email, password_hash, role, affiliate_id, status)
                VALUES ('Administrator', 'admin@neuravult.com', ?, 'admin', ?, 'active')
            ");
            $stmt->execute([$adminPassword, $affiliateId]);
            $adminId = $db->lastInsertId();
            $db->prepare("INSERT INTO user_stats (user_id) VALUES (?)")->execute([$adminId]);
        }
    }

    private static function getMySQLSchema() {
        return [
            "CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(150) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role ENUM('user', 'admin') DEFAULT 'user',
                affiliate_id VARCHAR(20) UNIQUE NOT NULL,
                company VARCHAR(100),
                website VARCHAR(200),
                status ENUM('pending', 'active', 'suspended') DEFAULT 'pending',
                last_login DATETIME,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_status (status),
                INDEX idx_affiliate_id (affiliate_id)
            )",

            "CREATE TABLE IF NOT EXISTS user_stats (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                total_clicks INT DEFAULT 0,
                total_referrals INT DEFAULT 0,
                premium_referrals INT DEFAULT 0,
                total_earnings DECIMAL(10,2) DEFAULT 0.00,
                available_balance DECIMAL(10,2) DEFAULT 0.00,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE KEY unique_user (user_id)
            )",

            "CREATE TABLE IF NOT EXISTS referral_links (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                name VARCHAR(100) NOT NULL,
                description TEXT,
                url VARCHAR(500) NOT NULL,
                unique_code VARCHAR(50) UNIQUE NOT NULL,
                click_count INT DEFAULT 0,
                conversion_count INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_unique_code (unique_code)
            )",

            "CREATE TABLE IF NOT EXISTS referrals (
                id INT PRIMARY KEY AUTO_INCREMENT,
                referrer_id INT NOT NULL,
                referral_link_id INT,
                user_name VARCHAR(100),
                user_email VARCHAR(150),
                type ENUM('click', 'signup', 'premium') DEFAULT 'click',
                status ENUM('pending', 'active', 'converted') DEFAULT 'pending',
                earnings DECIMAL(10,2) DEFAULT 0.00,
                ip_address VARCHAR(45),
                user_agent TEXT,
                source VARCHAR(50),
                campaign VARCHAR(100),
                referral_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (referrer_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (referral_link_id) REFERENCES referral_links(id) ON DELETE SET NULL,
                INDEX idx_referrer_date (referrer_id, referral_date),
                INDEX idx_type_status (type, status)
            )",

            "CREATE TABLE IF NOT EXISTS payouts (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                amount DECIMAL(10,2) NOT NULL,
                method ENUM('paypal', 'bank_transfer', 'crypto') NOT NULL,
                account_name VARCHAR(100) NOT NULL,
                account_number VARCHAR(200) NOT NULL,
                status ENUM('pending', 'approved', 'paid', 'rejected') DEFAULT 'pending',
                notes TEXT,
                requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processed_at TIMESTAMP NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_status (status),
                INDEX idx_user_status (user_id, status)
            )",

            "CREATE TABLE IF NOT EXISTS challenges (
                id INT PRIMARY KEY AUTO_INCREMENT,
                title VARCHAR(200) NOT NULL,
                description TEXT NOT NULL,
                reward DECIMAL(10,2) NOT NULL,
                target INT NOT NULL,
                deadline DATE NOT NULL,
                status ENUM('active', 'inactive', 'completed') DEFAULT 'active',
                created_by INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_status_deadline (status, deadline)
            )",

            "CREATE TABLE IF NOT EXISTS challenge_submissions (
                id INT PRIMARY KEY AUTO_INCREMENT,
                challenge_id INT NOT NULL,
                user_id INT NOT NULL,
                proof TEXT NOT NULL,
                notes TEXT,
                status ENUM('accepted', 'pending', 'approved', 'rejected') DEFAULT 'accepted',
                submitted_at TIMESTAMP NULL,
                reviewed_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (challenge_id) REFERENCES challenges(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE KEY unique_challenge_user (challenge_id, user_id)
            )",

            "CREATE TABLE IF NOT EXISTS program_settings (
                id INT PRIMARY KEY AUTO_INCREMENT,
                commission_rate DECIMAL(5,2) DEFAULT 30.00,
                min_payout DECIMAL(10,2) DEFAULT 50.00,
                payout_schedule ENUM('weekly', 'biweekly', 'monthly') DEFAULT 'biweekly',
                updated_by INT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE CASCADE
            )",

            "CREATE TABLE IF NOT EXISTS jwt_blacklist (
                id INT PRIMARY KEY AUTO_INCREMENT,
                token VARCHAR(64) NOT NULL,
                expires_at DATETIME NOT NULL,
                blacklisted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_token (token),
                INDEX idx_expires (expires_at)
            )",

            "CREATE TABLE IF NOT EXISTS login_attempts (
                id INT PRIMARY KEY AUTO_INCREMENT,
                email VARCHAR(150) NOT NULL,
                ip_address VARCHAR(45) NOT NULL,
                user_agent TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_email_time (email, timestamp),
                INDEX idx_ip_time (ip_address, timestamp)
            )",

            "CREATE TABLE IF NOT EXISTS rate_limits (
                id INT PRIMARY KEY AUTO_INCREMENT,
                identifier VARCHAR(100) NOT NULL,
                endpoint VARCHAR(200) NOT NULL,
                timestamp INT NOT NULL,
                INDEX idx_identifier_endpoint (identifier, endpoint),
                INDEX idx_timestamp (timestamp)
            )",

            "CREATE TABLE IF NOT EXISTS activity_logs (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                action VARCHAR(100) NOT NULL,
                details TEXT,
                ip_address VARCHAR(45),
                user_agent TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_action (user_id, action),
                INDEX idx_timestamp (timestamp)
            )",

            "CREATE TABLE IF NOT EXISTS password_resets (
                id INT PRIMARY KEY AUTO_INCREMENT,
                email VARCHAR(150) NOT NULL,
                token VARCHAR(64) NOT NULL,
                expires_at DATETIME NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_token (token),
                INDEX idx_email (email)
            )"
        ];
    }

    private static function getSQLiteSchema() {
        return [
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                affiliate_id TEXT UNIQUE NOT NULL,
                company TEXT,
                website TEXT,
                status TEXT DEFAULT 'pending',
                last_login DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",

            "CREATE TABLE IF NOT EXISTS user_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                total_clicks INTEGER DEFAULT 0,
                total_referrals INTEGER DEFAULT 0,
                premium_referrals INTEGER DEFAULT 0,
                total_earnings REAL DEFAULT 0.00,
                available_balance REAL DEFAULT 0.00,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE (user_id)
            )",

            "CREATE TABLE IF NOT EXISTS referral_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                url TEXT NOT NULL,
                unique_code TEXT UNIQUE NOT NULL,
                click_count INTEGER DEFAULT 0,
                conversion_count INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )",

            "CREATE TABLE IF NOT EXISTS referrals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                referrer_id INTEGER NOT NULL,
                referral_link_id INTEGER,
                user_name TEXT,
                user_email TEXT,
                type TEXT DEFAULT 'click',
                status TEXT DEFAULT 'pending',
                earnings REAL DEFAULT 0.00,
                ip_address TEXT,
                user_agent TEXT,
                source TEXT,
                campaign TEXT,
                referral_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (referrer_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (referral_link_id) REFERENCES referral_links(id) ON DELETE SET NULL
            )",

            "CREATE TABLE IF NOT EXISTS payouts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                method TEXT NOT NULL,
                account_name TEXT NOT NULL,
                account_number TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                notes TEXT,
                requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                processed_at DATETIME NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )",

            "CREATE TABLE IF NOT EXISTS challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                reward REAL NOT NULL,
                target INTEGER NOT NULL,
                deadline DATE NOT NULL,
                status TEXT DEFAULT 'active',
                created_by INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
            )",

            "CREATE TABLE IF NOT EXISTS challenge_submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                challenge_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                proof TEXT NOT NULL,
                notes TEXT,
                status TEXT DEFAULT 'accepted',
                submitted_at DATETIME NULL,
                reviewed_at DATETIME NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (challenge_id) REFERENCES challenges(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE (challenge_id, user_id)
            )",

            "CREATE TABLE IF NOT EXISTS program_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                commission_rate REAL DEFAULT 30.00,
                min_payout REAL DEFAULT 50.00,
                payout_schedule TEXT DEFAULT 'biweekly',
                updated_by INTEGER NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE CASCADE
            )",

            "CREATE TABLE IF NOT EXISTS jwt_blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                blacklisted_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",

            "CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                user_agent TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )",

            "CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            )",

            "CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                user_agent TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )",

            "CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                token TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )"
        ];
    }
}

// ==================== INITIALIZATION ====================

// Initialize database tables
DatabaseSetup::createTables();

// Handle API request
try {
    APIRouter::handleRequest();
} catch (Exception $e) {
    error_log("API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Internal server error']);
}

?>

