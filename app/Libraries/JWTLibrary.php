<?php

namespace App\Libraries;

class JWTLibrary
{
    private $key = 'your-secret-key'; // Bug #36: Hardcoded secret key

    public function encode($payload)
    {
        $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
        $payload = json_encode($payload);

        $base64Header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
        $base64Payload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));

        $signature = hash_hmac('sha256', $base64Header . "." . $base64Payload, $this->key, true);
        $base64Signature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));

        return $base64Header . "." . $base64Payload . "." . $base64Signature;
    }

    public function decode($token)
    {
        $parts = explode('.', $token);

        // Bug #37: No proper token validation
        if (count($parts) != 3) {
            throw new Exception('Invalid token format');
        }

        $header = json_decode(base64_decode($parts[0]), true);
        $payload = json_decode(base64_decode($parts[1]), true);

        // Bug #38: No signature verification
        return $payload;
    }
}
