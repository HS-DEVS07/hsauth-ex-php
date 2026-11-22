<?php
require_once __DIR__ . '/hsauth.php';

$auth = new \HSAUTH\api(
    "MyApp",
    "your_app_identifier_here",
    "your_app_secret_here",
    "1.0",
    "https://auth.hsdevs.pro/api/1.3/"
);

$init = $auth->init();
if (empty($init['success'])) {
    die("Init failed: " . ($init['message'] ?? 'Unknown error'));
}

echo "HS DEVS AUTH Initialized successfully!\n";
echo "Version: " . ($auth->app_data['version'] ?? '1.0') . "\n";

// Example license check
$lic = "HSAUTH-XXXX-XXXX-XXXX-XXXX";
$login = $auth->license($lic);

if (!empty($login['success'])) {
    echo "Authenticated successfully!\n";
    echo "HWID: " . $auth->user_data['hwid'] . "\n";
} else {
    echo "Authentication failed: " . ($login['message'] ?? 'Invalid key') . "\n";
}
