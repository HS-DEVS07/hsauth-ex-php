<?php
/**
 * Official HS DEVS AUTH PHP SDK
 * Zero external libraries required.
 */

namespace HSAUTH;

class api {
    public $name;
    public $ownerid;
    public $secret;
    public $version;
    public $apiUrl;
    public $sessionid;
    public $initialized = false;
    public $response = [];
    public $user_data = [];
    public $app_data = [];

    public function __construct($name, $ownerid, $secret, $version = "1.0", $apiUrl = "https://auth.hsdevs.pro/api/1.3/") {
        if (empty($name) || empty($ownerid) || empty($secret)) {
            throw new \InvalidArgumentException("Application name, ownerid, and secret are all required.");
        }
        $this->name = $name;
        $this->ownerid = $ownerid;
        $this->secret = $secret;
        $this->version = $version;
        $this->apiUrl = rtrim($apiUrl, '/') . '/';
    }

    private function get_hwid() {
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        }
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'CLI_PHP';
        return hash('sha256', $ip . $ua);
    }

    private function req($data) {
        if (empty($this->secret)) {
            return ['success' => false, 'message' => 'Application secret is required'];
        }
        $data['name'] = $this->name;
        $data['ownerid'] = $this->ownerid;
        $data['secret'] = $this->secret;

        $postfields = http_build_query($data);

        if (function_exists('curl_init')) {
            $ch = curl_init($this->apiUrl);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $postfields);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_TIMEOUT, 15);
            $res = curl_exec($ch);
            curl_close($ch);
        } else {
            $options = [
                'http' => [
                    'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
                    'method'  => 'POST',
                    'content' => $postfields,
                    'timeout' => 15
                ]
            ];
            $context = stream_context_create($options);
            $res = @file_get_contents($this->apiUrl, false, $context);
        }

        $decoded = json_decode($res, true);
        return is_array($decoded) ? $decoded : ['success' => false, 'message' => $res];
    }

    public function init() {
        $res = $this->req([
            'type' => 'init',
            'ver'  => $this->version
        ]);

        $this->response = $res;
        if (!empty($res['success'])) {
            $this->sessionid = $res['sessionid'] ?? null;
            $this->app_data = $res['appinfo'] ?? [];
            $this->initialized = true;
        }
        return $res;
    }

    public function login($username, $password) {
        $res = $this->req([
            'type'      => 'login',
            'username'  => $username,
            'pass'      => $password,
            'hwid'      => $this->get_hwid(),
            'sessionid' => $this->sessionid
        ]);

        $this->response = $res;
        if (!empty($res['success'])) {
            $this->user_data = $res['info'] ?? [];
            if (!empty($res['sessionid'])) $this->sessionid = $res['sessionid'];
        }
        return $res;
    }

    public function register($username, $password, $key, $email = "") {
        $res = $this->req([
            'type'      => 'register',
            'username'  => $username,
            'pass'      => $password,
            'key'       => $key,
            'email'     => $email,
            'hwid'      => $this->get_hwid(),
            'sessionid' => $this->sessionid
        ]);

        $this->response = $res;
        if (!empty($res['success'])) {
            $this->user_data = $res['info'] ?? [];
            if (!empty($res['sessionid'])) $this->sessionid = $res['sessionid'];
        }
        return $res;
    }

    public function license($key) {
        $res = $this->req([
            'type'      => 'license',
            'key'       => $key,
            'hwid'      => $this->get_hwid(),
            'sessionid' => $this->sessionid
        ]);

        $this->response = $res;
        if (!empty($res['success'])) {
            $this->user_data = $res['info'] ?? [];
            if (!empty($res['sessionid'])) $this->sessionid = $res['sessionid'];
        }
        return $res;
    }

    public function check() {
        return $this->req([
            'type'      => 'check',
            'sessionid' => $this->sessionid
        ]);
    }

    public function var($varid) {
        $res = $this->req([
            'type'      => 'var',
            'varid'     => $varid,
            'sessionid' => $this->sessionid
        ]);
        return (!empty($res['success'])) ? ($res['message'] ?? $res['response']) : null;
    }

    public function log($message) {
        return $this->req([
            'type'      => 'log',
            'message'   => $message,
            'sessionid' => $this->sessionid
        ]);
    }

    public function logout() {
        $res = $this->req([
            'type'      => 'logout',
            'sessionid' => $this->sessionid
        ]);
        $this->sessionid = null;
        return $res;
    }
}
