<?php

/**
 * BluSafe TechScanner
 *
 * Open Source Website Technology & Vulnerability Scanner
 *
 * Version : 1.2.0
 * Author  : Aadil (Dface)
 * GitHub  : https://github.com/sudo-dface/Bluesafe
 * License : GPL-3.0
 * Website : dface.site
 * Copyright (c) 2026 Dface
 */

session_set_cookie_params([
    "lifetime" => 0,
    "path" => "/",
    "httponly" => true,
    "secure" => !empty($_SERVER["HTTPS"]),
                          "samesite" => "Strict",
]);

session_start();

if (empty($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}

define("TECHSCANNER", true);
/* ==========================================
 *   TechScanner
 *   Version 1.0
 * ========================================== */
$dataFile = __DIR__ . "/.techscanner-data.php";
$scanFile = __DIR__ . "/.techscanner-scan.php";
$isInstalled = file_exists($dataFile);
$errors = [];
/* ==========================================
 *   Configuration
 * ========================================== */
$config = [];

if ($isInstalled) {
    $config = require $dataFile;
}
$isLoggedIn = $_SESSION["logged_in"] ?? false;
$page = $_GET["page"] ?? "dashboard";

$baseUrl =
(!empty($_SERVER["HTTPS"]) ? "https" : "http") .
"://" .
$_SERVER["HTTP_HOST"];

$scanResult = null;
/* ==========================================
 *   Helper Functions
 * ========================================== */
function escape($value)
{
    return htmlspecialchars($value, ENT_QUOTES, "UTF-8");
}
function verifyCsrf()
{
    if (
        empty($_POST["csrf"]) ||
        empty($_SESSION["csrf_token"]) ||
        !hash_equals($_SESSION["csrf_token"], $_POST["csrf"])
    ) {
        die("Invalid CSRF Token.");
    }
}
function writeConfigFile($file, array $config)
{
    $content = "<?php\n\n";
    $content .= "defined('TECHSCANNER') or exit;\n\n";
    $content .= "return ";
    $content .= var_export($config, true);
    $content .= ";\n";

    return file_put_contents($file, $content, LOCK_EX) !== false;
}
function detectWordPress()
{
    return is_dir(__DIR__ . "/wp-admin") &&
    is_dir(__DIR__ . "/wp-content") &&
    is_dir(__DIR__ . "/wp-includes");
}

function detectWordPressVersion()
{
    if (!detectWordPress()) {
        return null;
    }

    $versionFile = __DIR__ . "/wp-includes/version.php";

    if (!file_exists($versionFile)) {
        return null;
    }

    include $versionFile;

    return $wp_version ?? null;
}

function detectWordPressTheme()
{
    if (!detectWordPress()) {
        return null;
    }

    require_once __DIR__ . "/wp-load.php";

    if (!function_exists("wp_get_theme")) {
        return null;
    }

    $theme = wp_get_theme();

    if (!$theme->exists()) {
        return null;
    }

    return [
        "name" => $theme->get("Name"),
        "slug" => $theme->get_stylesheet(),
        "version" => $theme->get("Version"),
    ];
}

function detectWordPressPlugins()
{
    if (!detectWordPress()) {
        return [];
    }

    $plugins = [];

    $pluginsDir = __DIR__ . "/wp-content/plugins";

    if (!is_dir($pluginsDir)) {
        return [];
    }

    foreach (glob($pluginsDir . "/*", GLOB_ONLYDIR) as $pluginDir) {
        $pluginData = [
            "name" => basename($pluginDir),
            "slug" => basename($pluginDir),
            "version" => "Unknown",
        ];

        foreach (glob($pluginDir . "/*.php") as $phpFile) {
            $contents = file_get_contents($phpFile);

            if (
                preg_match("/Plugin Name:\s*(.+)/i", $contents, $nameMatch) &&
                preg_match("/Version:\s*(.+)/i", $contents, $versionMatch)
            ) {
                $pluginData["name"] = trim($nameMatch[1]);
                $pluginData["version"] = trim($versionMatch[1]);

                break;
            }
        }

        $plugins[] = $pluginData;
    }

    usort($plugins, function ($a, $b) {
        return strcmp($a["name"], $b["name"]);
    });

    return $plugins;
}

function detectPHPVersion()
{
    return PHP_VERSION;
}

function detectWebServer()
{
    return $_SERVER["SERVER_SOFTWARE"] ?? "Unknown";
}

function detectComposer()
{
    return [
        "composer_json" => file_exists(__DIR__ . "/composer.json"),
        "composer_lock" => file_exists(__DIR__ . "/composer.lock"),
        "vendor" => is_dir(__DIR__ . "/vendor"),
    ];
}

function detectLaravel()
{
    $artisan = __DIR__ . "/artisan";

    if (!file_exists($artisan)) {
        return null;
    }

    return [
        "detected" => true,
        "version" => null,
    ];
}

function detectNode()
{
    $packageJson = __DIR__ . "/package.json";

    if (!file_exists($packageJson)) {
        return null;
    }

    $json = json_decode(file_get_contents($packageJson), true);

    if (!is_array($json)) {
        return null;
    }

    $dependencies = array_merge(
        $json["dependencies"] ?? [],
        $json["devDependencies"] ?? []
    );

    return [
        "node" => true,
        "react" => $dependencies["react"] ?? null,
        "vue" => $dependencies["vue"] ?? null,
        "next" => $dependencies["next"] ?? null,
    ];
}

function buildScanPayload(array $scanResult, array $config, string $baseUrl)
{
    $payload = [
        "license_key" => $config["license_key"],
        "environment" => parse_url($baseUrl, PHP_URL_HOST),
        "scan_generated" => gmdate("c"),
        "components" => [],
    ];

    // WordPress Core
    if (!empty($scanResult["cms"]) && !empty($scanResult["version"])) {
        $payload["components"][] = [
            "name" => strtolower($scanResult["cms"]),
            "slug" => "",
            "version" => $scanResult["version"],
            "ecosystem" => "WordPress",
        ];
    }

    // Theme
    if (!empty($scanResult["theme"])) {
        $payload["components"][] = [
            "name" => $scanResult["theme"]["name"],
            "slug" => $scanResult["theme"]["slug"],
            "version" => $scanResult["theme"]["version"],
            "ecosystem" => "WordPress Theme",
        ];
    }

    // Plugins
    foreach ($scanResult["plugins"] as $plugin) {
        $payload["components"][] = [
            "name" => $plugin["name"],
            "slug" => $plugin["slug"],
            "version" => $plugin["version"],
            "ecosystem" => "WordPress Plugin",
        ];
    }

    // React
    if (!empty($scanResult["node"]["react"])) {
        $payload["components"][] = [
            "name" => "react",
            "slug" => "",
            "version" => ltrim($scanResult["node"]["react"], "^~"),
            "ecosystem" => "npm",
        ];
    }

    // Vue
    if (!empty($scanResult["node"]["vue"])) {
        $payload["components"][] = [
            "name" => "vue",
            "slug" => "",
            "version" => ltrim($scanResult["node"]["vue"], "^~"),
            "ecosystem" => "npm",
        ];
    }

    // Next.js
    if (!empty($scanResult["node"]["next"])) {
        $payload["components"][] = [
            "name" => "next",
            "slug" => "",
            "version" => ltrim($scanResult["node"]["next"], "^~"),
            "ecosystem" => "npm",
        ];
    }

    return $payload;
}

function sendScanToBackend(array $payload, string $backendUrl)
{
    $ch = curl_init();

    curl_setopt($ch, CURLOPT_URL, rtrim($backendUrl, "/") . "/scan");
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);

    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Content-Type: application/json",
        "Accept: application/json",
        "ngrok-skip-browser-warning: true",
    ]);

    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));

    $response = curl_exec($ch);

    if ($response === false) {
        $error = curl_error($ch);

        curl_close($ch);

        return [
            "success" => false,
            "error" => $error,
        ];
    }

    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    curl_close($ch);

    return [
        "success" => $status >= 200 && $status < 300,
        "status" => $status,
        "body" => json_decode($response, true),
    ];
}

function getLatestWordPressVersion()
{
    $url = "https://api.wordpress.org/core/version-check/1.7/";

    $json = @file_get_contents($url);

    if ($json === false) {
        return null;
    }

    $data = json_decode($json, true);

    if (!isset($data["offers"][0]["version"])) {
        return null;
    }

    return $data["offers"][0]["version"];
}

function getLatestPluginVersion($slug)
{
    if (empty($slug)) {
        return null;
    }

    $url =
    "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&slug=" .
    urlencode($slug);

    $json = @file_get_contents($url);

    if ($json === false) {
        return null;
    }

    $data = json_decode($json, true);

    return $data["version"] ?? null;
}

function getLatestThemeVersion($slug)
{
    if (empty($slug)) {
        return null;
    }

    $url =
    "https://api.wordpress.org/themes/info/1.2/?action=theme_information&slug=" .
    urlencode($slug);

    $json = @file_get_contents($url);

    if ($json === false) {
        return null;
    }

    $data = json_decode($json, true);

    return $data["version"] ?? null;
}
/* ==========================================
 *   Installer
 * ========================================== */
if (!$isInstalled && $_SERVER["REQUEST_METHOD"] === "POST") {
    verifyCsrf();

    $backendUrl = trim($_POST["backend_url"] ?? "");
    $licenseKey = trim($_POST["license_key"] ?? "");
    $adminPassword = $_POST["admin_password"] ?? "";
    $confirmPassword = $_POST["confirm_password"] ?? "";

    if ($backendUrl === "") {
        $errors[] = "Backend URL is required.";
    } elseif (!filter_var($backendUrl, FILTER_VALIDATE_URL)) {
        $errors[] = "Please enter a valid Backend URL.";
    }

    if ($licenseKey === "") {
        $errors[] = "License Key is required.";
    }

    if ($adminPassword === "") {
        $errors[] = "Admin Password is required.";
    } elseif (strlen($adminPassword) < 12) {
        $errors[] = "Admin Password must be at least 12 characters.";
    }

    if ($confirmPassword !== "" && $adminPassword !== $confirmPassword) {
        $errors[] = "Passwords do not match.";
    }

    if (empty($errors)) {
        $config = [
            "backend_url" => $backendUrl,
            "license_key" => $licenseKey,
            "password_hash" => password_hash($adminPassword, PASSWORD_DEFAULT),
            "scanner_version" => "1.0",
            "installed_at" => date("c"),
            "last_login" => null,
        ];
        if (writeConfigFile($dataFile, $config)) {
            header("Location: " . $_SERVER["PHP_SELF"]);
            exit();
        } else {
            $errors[] =
            "Unable to create the configuration file. Please check directory permissions.";
        }
    }
}

/* ==========================================
 *   Authentication
 * ========================================== */
if (
    $isLoggedIn &&
    $_SERVER["REQUEST_METHOD"] === "POST" &&
    ($_POST["action"] ?? "") === "refresh_scan"
) {
    verifyCsrf();

    $scanResult = [
        "cms" => detectWordPress() ? "WordPress" : null,
        "version" => detectWordPressVersion(),
        "theme" => detectWordPressTheme(),
        "plugins" => detectWordPressPlugins(),

        "php" => detectPHPVersion(),
        "server" => detectWebServer(),

        "composer" => detectComposer(),
        "laravel" => detectLaravel(),
        "node" => detectNode(),
    ];

    $payload = buildScanPayload($scanResult, $config, $baseUrl);

    writeConfigFile($scanFile, $payload);

    header("Location: ?page=scan&refresh=1");
    exit();
}

if (
    $isInstalled &&
    $_SERVER["REQUEST_METHOD"] === "POST" &&
    !isset($_POST["action"])
) {
    verifyCsrf();
    $password = $_POST["password"] ?? "";

    if (!password_verify($password, $config["password_hash"])) {
        $errors[] = "Invalid password.";
    } else {
        session_regenerate_id(true);

        $_SESSION["logged_in"] = true;

        /* Generate a fresh CSRF token after login */
        $_SESSION["csrf_token"] = bin2hex(random_bytes(32));

        $config["last_login"] = date("c");

        writeConfigFile($dataFile, $config);

        header("Location: " . $_SERVER["PHP_SELF"]);
        exit();
    }
}

/* ==========================================
 *   Logout
 * ========================================== */
if (isset($_GET["logout"])) {
    unset($_SESSION["csrf_token"]);

    $_SESSION = [];

    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();

        setcookie(
            session_name(),
                  "",
                  time() - 42000,
                  $params["path"],
                  $params["domain"],
                  $params["secure"],
                  $params["httponly"]
        );
    }

    session_destroy();

    session_start();

    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));

    header("Location: " . $_SERVER["PHP_SELF"]);
    exit();
}

/* ==========================================
 *   Website Scanner
 * ========================================== */

if (
    $isLoggedIn &&
    $_SERVER["REQUEST_METHOD"] === "POST" &&
    ($_POST["action"] ?? "") === "scan"
) {
    verifyCsrf();
    if (!file_exists($scanFile)) {
        die("Technology list not found. Please refresh technologies first.");
    }

    $payload = require $scanFile;

    $scanResult = sendScanToBackend($payload, $config["backend_url"]);
    $backendResults = [];

    if ($scanResult["success"] && !empty($scanResult["body"]["results"])) {
        foreach ($scanResult["body"]["results"] as $result) {
            $backendResults[$result["name"]] = $result;
        }
    }
    $totalComponents = count($payload["components"]);
    $safeComponents = 0;
    $vulnerableComponents = 0;

    foreach ($payload["components"] as $component) {
        $backendComponent = $backendResults[$component["name"]] ?? null;

        if (
            $backendComponent !== null &&
            !empty($backendComponent["vulnerabilities"])
        ) {
            $vulnerableComponents++;
        } else {
            $safeComponents++;
        }
    }

    $latestVersions = [];

    foreach ($payload["components"] as $component) {
        $key = $component["ecosystem"] . ":" . $component["slug"];

        switch ($component["ecosystem"]) {
            case "WordPress":
                $latestVersions[$key] = getLatestWordPressVersion();
                break;

            case "WordPress Plugin":
                $latestVersions[$key] = getLatestPluginVersion(
                    $component["slug"]
                );
                break;

            case "WordPress Theme":
                $latestVersions[$key] = getLatestThemeVersion(
                    $component["slug"]
                );
                break;
        }
    }
}

$backendStatus = null;

if (
    $isLoggedIn &&
    $_SERVER["REQUEST_METHOD"] === "POST" &&
    ($_POST["action"] ?? "") === "check_backend"
) {
    verifyCsrf();
    $ch = curl_init();

    curl_setopt($ch, CURLOPT_URL, rtrim($config["backend_url"], "/") . "/docs");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_NOBODY, true);

    curl_exec($ch);

    if (!curl_errno($ch)) {
        $backendStatus = "Online";
    } else {
        $backendStatus = "Offline";
    }

    curl_close($ch);
}

$apiTestResult = null;

if (
    $isLoggedIn &&
    $_SERVER["REQUEST_METHOD"] === "POST" &&
    ($_POST["action"] ?? "") === "test_api"
) {
    verifyCsrf();
    $licenseKey = trim($_POST["test_license_key"] ?? "");

    if ($licenseKey === "") {
        $apiTestResult = "Please enter a license key.";
    } else {
        $payload = [
            "license_key" => $licenseKey,
            "environment" => "api-test.local",
            "scan_generated" => gmdate("c"),
            "components" => [
                [
                    "name" => "Hello Dolly",
                    "slug" => "hello-dolly",
                    "version" => "1.7.2",
                    "ecosystem" => "WordPress Plugin",
                ],
            ],
        ];

        $response = sendScanToBackend($payload, $config["backend_url"]);

        if (!$response["success"]) {
            $apiTestResult = "❌ Backend Unreachable or Wrong Key";
        } elseif (
            !empty($response["body"]["status"]) &&
            $response["body"]["status"] === "completed"
        ) {
            $apiTestResult = "✅ API Working";
        } else {
            $apiTestResult = "❌ API Error";
        }
    }
}

/* ==========================================
 *   Dashboard
 * ========================================== */
?>
<!DOCTYPE html>
<html>

<head>
<meta charset="UTF-8">
<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>TechScanner</title>

<style>
:root{

    --bg: #f5f7fb;
    --card: #ffffff;
    --text: #222;
    --text-light: #666;

    --border: #d9dde7;

    --primary: #2f63e0;
    --primary-hover: #214fb8;

    --success: #1d8f43;
    --danger: #d93a3a;

    --shadow: 0 8px 20px rgba(0,0,0,.08);

}

body.dark{

    --bg: #111827;

    --card: #1f2937;

    --text: #f3f4f6;

    --text-light: #cbd5e1;

    --border: #374151;

    --primary: #3b82f6;

    --primary-hover: #2563eb;

    --success: #22c55e;

    --danger: #ef4444;

    --shadow: 0 10px 25px rgba(0,0,0,.45);

}
body{
    margin:0;
    padding:40px;
    background:var(--bg);
    font-family:Arial,Helvetica,sans-serif;
    color:var(--text);
}

.container{
    max-width:1100px;
    margin:auto;
}

h1{
    margin-top:0;
}

h2{
    margin-top:35px;
}

hr{
    border:none;
    border-top:1px solid var(--border);
    margin:25px 0;
}

button{
    background:var(--primary);
    color:#fff;
    border:none;
    border-radius:8px;
    padding:10px 18px;
    cursor:pointer;
    font-size:15px;
}

button:hover{
    background:var(--primary-hover);
}

input{
    padding:10px;

    border-radius:6px;

    background:var(--card);

    color:var(--text);

    border:1px solid var(--border);
}

.component-card{
    background:var(--card);
    color:var(--text);
    border:1px solid var(--border);
    padding:20px;
    margin-bottom:25px;
    border-radius:12px;
    box-shadow:var(--shadow);
}

.summary{

    display:flex;

    gap:20px;

    margin:30px 0;
}

.summary-card{

    flex:1;

    background:var(--card);

    color:var(--text);

    padding:20px;

    border-radius:12px;

    box-shadow:var(--shadow);

    border:1px solid var(--border);

    text-align:center;

}

.vuln-card{

    background:var(--card);

    border-left:5px solid var(--danger);

    color:var(--text);

    padding:16px;

    margin:15px 0;

    border-radius:8px;

}

.vuln-card h4{
    margin:0 0 10px;
}

.vuln-meta{
    display:flex;
    gap:20px;
    flex-wrap:wrap;
    margin-bottom:12px;
}

.vuln-meta span{
    font-size:14px;
}

.button{
    display:inline-flex;
    align-items:center;
    justify-content:center;
    padding:12px 20px;
    background:var(--primary);
    color:#fff;
    text-decoration:none;
    border-radius:8px;
    font-size:15px;
    font-weight:500;
}

.button:hover{
    background:var(--primary-hover);
}

.topbar{

    display:flex;

    justify-content:space-between;

    align-items:center;

    padding:15px 20px;

    margin-bottom:20px;

    background:var(--card);

    border:1px solid var(--border);

    border-radius:12px;

    box-shadow:var(--shadow);

}

.topbar-right{

    display:flex;

    gap:12px;

    align-items:center;

}

@media (max-width:768px){

    body{
        padding:15px;
    }

    .container{
        width:100%;
        max-width:100%;
    }

    .topbar{
        flex-direction:column;
        align-items:stretch;
        gap:15px;
    }

    .topbar-right{
        display:flex;
        flex-direction:column;
        gap:12px;
    }

    .button,
    .topbar button{
        width:100%;
        box-sizing:border-box;
        text-align:center;
    }

    form[style]{
        flex-direction:column !important;
    }

    form[style] button,
        form[style] .button{
            width:100%;
            box-sizing:border-box;
        }

        .summary{
            flex-direction:column;
        }

        .summary-card{
            width:100%;
            box-sizing:border-box;
        }

        .component-card{
            padding:15px;
        }

        .vuln-meta{
            flex-direction:column;
            gap:8px;
        }

        input[type="text"],
        input[type="url"],
        input[type="password"]{
            width:100% !important;
            box-sizing:border-box;
        }

        p{
            overflow-wrap:anywhere;
        }

        h1{
            font-size:38px;
        }

        h2{
            font-size:28px;
        }

}
</style>

</head>

<body>

<?php if ($isInstalled && $isLoggedIn): ?>

<div class="topbar">

<a href="?page=dashboard" class="button">
Dashboard
</a>

<div class="topbar-right">

<button
type="button"
id="themeToggle">
Dark Mode
</button>

<a href="?logout=1" class="button">
Logout
</a>

</div>

</div>

<?php endif; ?>

<div class="container">

<?php if (!$isInstalled): ?>

<h1>TechScanner Installation</h1>

<p>Welcome! Complete the setup below to initialize TechScanner.</p>
<?php if (!empty($errors)): ?>
<div style="color:var(--danger);">
<ul>
<?php foreach ($errors as $error): ?>
<li><?= escape($error) ?></li>
<?php endforeach; ?>
</ul>
</div>
<?php endif; ?>
<form method="post">

<input
type="hidden"
name="csrf"
value="<?= escape($_SESSION["csrf_token"]) ?>">


<p>
<label>Backend URL</label><br>
<input
type="url"
name="backend_url"
value="<?= escape($backendUrl ?? "") ?>"
required
style="width:350px;">
</p>

<p>
<label>License Key</label><br>
<input
type="password"
name="license_key"
required
style="width:350px;">
</p>

<p>
<label>Admin Password</label><br>
<input type="password" name="admin_password" required style="width:350px;">
</p>

<p>
<label>Confirm Password</label><br>
<input type="password" name="confirm_password" required style="width:350px;">
</p>

<p>
<button type="submit">
Install TechScanner
</button>
</p>

</form>
<?php else: ?>

<?php if (!$isLoggedIn): ?>

<h1>TechScanner Login</h1>

<?php if (!empty($errors)): ?>
<div style="color:var(--danger);">
<ul>
<?php foreach ($errors as $error): ?>
<li><?= escape($error) ?></li>
<?php endforeach; ?>
</ul>
</div>
<?php endif; ?>

<p>Please enter your administrator password.</p>

<form method="post">

<input
type="hidden"
name="csrf"
value="<?= escape($_SESSION["csrf_token"]) ?>">


<p>
<label>Password</label><br>
<input
type="password"
name="password"
required
style="width:350px;">
</p>

<p>
<button type="submit">
Login
</button>
</p>

</form>

<?php else: ?>
<?php if ($page === "dashboard"): ?>

<h1>TechScanner Dashboard</h1>

<p><strong>Backend:</strong><br>
<?= escape($config["backend_url"]) ?></p>

<p><strong>License Key:</strong><br>
<?= escape($config["license_key"]) ?></p>

<p><strong>Scanner Version:</strong><br>
<?= escape($config["scanner_version"]) ?></p>

<p><strong>Last Login:</strong><br>
<?= escape($config["last_login"]) ?></p>

<hr>

<p>
<a href="?page=scan" class="button">
Scan Website
</a>
</p>

<p>
<a href="?page=settings" class="button">
Settings
</a>
</p>
<?php endif; ?>

<?php if ($page === "settings"): ?>

<h1>TechScanner Settings</h1>

<hr>

<h2>Backend Status</h2>

<form method="post">

<input
type="hidden"
name="csrf"
value="<?= escape($_SESSION["csrf_token"]) ?>">


<input
type="hidden"
name="action"
value="check_backend">

<p>
Status:
<?= escape($backendStatus ?? "Unknown") ?>
</p>

<button type="submit">
Check Backend
</button>

</form>

<hr>

<h2>API Test</h2>

<form method="post">

<input
type="hidden"
name="csrf"
value="<?= escape($_SESSION["csrf_token"]) ?>">


<input
type="hidden"
name="action"
value="test_api">

<p>
License Key
</p>

<input
type="text"
name="test_license_key"
style="width:350px;"
placeholder="Enter a license key"
value="<?= escape($_POST["test_license_key"] ?? "") ?>">

<p>
<button type="submit">
Test API
</button>
</p>

<?php if (isset($apiTestResult)): ?>

<p>
<strong><?= escape($apiTestResult) ?></strong>
</p>

<?php endif; ?>

</form>

<hr>

<h2>Plugin Information</h2>

<p>
<strong>Plugin Version:</strong>
<?= escape($config["scanner_version"]) ?>
</p>

<p>
<strong>WordPress Version:</strong>
<?= escape(detectWordPressVersion() ?: "Not Detected") ?>
</p>

<p>
<strong>PHP Version:</strong>
<?= escape(PHP_VERSION) ?>
</p>

<p>
<strong>Last Scan:</strong>
<?php if (file_exists($scanFile)) {
    $lastScan = require $scanFile;
    echo escape($lastScan["scan_generated"] ?? "Never");
} else {
    echo "Never";
} ?>
</p>
<hr>

<h2>About TechScanner</h2>

<p>
<strong>Version:</strong><br>
<?= escape($config["scanner_version"]) ?>
</p>

<p>
<strong>Author: </strong>
Aadil (DFace)
</p>

<p>
<strong>License:</strong>
GPL-3.0
</p>

<p>
<strong>GitHub:</strong>
<a
href="https://github.com/dface1221/blusafe"
target="_blank"
rel="noopener noreferrer">
github.com/dface1221/blusafe
</a>
</p>

<p>
<strong>Description:</strong>
TechScanner is an open-source website technology and
vulnerability scanner built for developers,
system administrators, and security researchers.
</p>

<p>
<strong>Built With:</strong><br>
• PHP<br>
• WordPress APIs<br>
• OSV.dev<br>
• FastAPI Backend
</p>

<p style="color:var(--text-light);">
© 2026 Aadil (DFace)
</p>
<p>
<a href="?page=dashboard">
<button type="button">
Back
</button>
</a>
</p>

<?php endif; ?>
<?php if ($page === "scan"): ?>
<h1>Scan Website</h1>

<p>
Current Website:
</p>

<p>
<strong><?= escape($baseUrl) ?></strong>
</p>

<p>
This website will be scanned for supported technologies.
</p>

<form method="post" style="display:flex;gap:15px;">

<input
type="hidden"
name="csrf"
value="<?= escape($_SESSION["csrf_token"]) ?>">

<button
type="submit"
name="action"
value="scan">
Start Vulnerability Scan
</button>

<button
type="submit"
name="action"
value="refresh_scan">
Refresh Technology List
</button>
<a href="?page=dashboard" class="button">
Back
</a>

</form>
<?php if (file_exists($scanFile)) {
    $savedScan = require $scanFile;
    echo "<p>";
    echo "<strong>Detected Technologies:</strong> ";
    echo count($savedScan["components"]);
    echo "</p>";
} ?>

<?php if (isset($_GET["refresh"])): ?>

<p style="color:var(--success);">
Technology list updated successfully.
</p>

<?php endif; ?>
<?php if ($scanResult !== null): ?>

<hr>

<h2>Scan Summary</h2>

<div class="summary">

<div class="summary-card">

<h3>Components</h3>

<h1><?= $totalComponents ?></h1>

</div>

<div class="summary-card">

<h3>Safe</h3>

<h1><?= $safeComponents ?></h1>

</div>

<div class="summary-card">

<h3>Vulnerable</h3>

<h1><?= $vulnerableComponents ?></h1>

</div>

</div>

<hr>

<?php if (!empty($payload["components"])): ?>

<?php foreach ($payload["components"] as $component): ?>

<?php $backendComponent = $backendResults[$component["name"]] ?? null; ?>
<?php
$installedVersion = $component["version"];
$key = $component["ecosystem"] . ":" . $component["slug"];
$latestVersion = $latestVersions[$key] ?? null;
?>
<div class="component-card">

<h3><?= escape($component["name"]) ?></h3>

<p>
<strong>Installed Version:</strong>
<?= escape($component["version"] ?: "Unknown") ?>
</p>

<p>
<strong>Latest Version:</strong>

<?= escape($latestVersion ?? "Unavailable") ?>
</p>


<?php if ($latestVersion === null): ?>

<p>
Latest version could not be determined.
</p>

<?php elseif (version_compare($installedVersion, $latestVersion, "<")): ?>

<p style="color:orange;">
⚠ Update Available
</p>

<?php else: ?>

<p style="color:var(--success);">
✓ Up to Date
</p>

<?php endif; ?>

<?php if ($backendComponent === null): ?>

<p style="color:orange;">
⚠ Unable to contact the vulnerability server.
</p>

<?php elseif (empty($backendComponent["vulnerabilities"])): ?>

<p style="color:var(--success);">
✓ No known vulnerabilities found.
</p>

<?php else: ?>

<p style="color:var(--danger);">
<?= count($backendComponent["vulnerabilities"]) ?>
vulnerabilit<?= count($backendComponent["vulnerabilities"]) == 1
? "y"
: "ies" ?> found.
</p>

<button
type="button"
class="toggle-vulns">
Show Vulnerabilities
</button>

<div class="vuln-list" style="display:none;">

<?php foreach ($backendComponent["vulnerabilities"] as $vulnerability): ?>

<div class="vuln-card">

<h4>
<?= escape($vulnerability["id"] ?: $vulnerability["title"]) ?>
</h4>

<div class="vuln-meta">

<span>
<strong>Severity:</strong>
<?= escape($vulnerability["severity"] ?: "Unknown") ?>
</span>

<span>
<strong>CVSS:</strong>
<?= escape($vulnerability["score"] ?: "N/A") ?>
</span>

<span>
<strong>Published:</strong>
<?= escape($vulnerability["date"] ?: "Unknown") ?>
</span>

</div>

<p>
<?= nl2br(
    escape($vulnerability["description"] ?: "No description available.")
) ?>
</p>

</div>

<?php endforeach; ?>

</div>

<?php endif; ?>
</div>

<?php endforeach; ?>

<?php endif; ?>
<?php endif; ?>
<?php endif; ?>
<?php endif; ?>
<?php endif; ?>
</div>

<script>

const savedTheme = localStorage.getItem("theme");

if (savedTheme === "dark") {
    document.body.classList.add("dark");
}

const button = document.getElementById("themeToggle");

if (button) {

    button.textContent =
    document.body.classList.contains("dark")
    ? "Light Mode"
    : "Dark Mode";

    button.addEventListener("click", function () {

        document.body.classList.toggle("dark");

        if (document.body.classList.contains("dark")) {
            localStorage.setItem("theme", "dark");
            button.textContent = "Light Mode";
        } else {
            localStorage.setItem("theme", "light");
            button.textContent = "Dark Mode";
        }

    });

}
document.querySelectorAll(".toggle-vulns").forEach(function(button){

    button.addEventListener("click", function(){

        const list = button.nextElementSibling;

        if(list.style.display === "none"){

            list.style.display = "block";
            button.textContent = "Hide Vulnerabilities";

        }else{

            list.style.display = "none";
            button.textContent = "Show Vulnerabilities";

        }

    });

});
</script>

</body>
</html>
