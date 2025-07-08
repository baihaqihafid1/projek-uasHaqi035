<?php

namespace App\Controllers;

use CodeIgniter\RESTful\ResourceController;
use App\Models\UserModel;
use App\Libraries\JWTLibrary;

class AuthController extends ResourceController
{
    protected $modelName = 'App\Models\UserModel';
    protected $format    = 'json';
    protected $jwt;

    public function __construct()
    {
        $this->jwt = new JWTLibrary();
    }

    public function register()
    {
        $input = $this->request->getJSON(true); // Pakai JSON

        $rules = [
            'name'     => 'required|min_length[3]',
            'email'    => 'required|valid_email|is_unique[users.email]',
            'password' => 'required|min_length[6]'
        ];

        if (!$this->validate($rules, $input)) {
            return $this->failValidationErrors($this->validator->getErrors());
        }

        $userModel = new UserModel();

        $userData = [
            'name'     => $input['name'],
            'email'    => $input['email'],
            'password' => password_hash($input['password'], PASSWORD_DEFAULT)
        ];

        $userId = $userModel->insert($userData);

        if ($userId) {
            unset($userData['password']);
            return $this->respondCreated([
                'status'  => 'success',
                'message' => 'User registered successfully',
                'data'    => $userData
            ]);
        }

        return $this->failServerError('Registration failed');
    }

    public function login()
    {
        $input = $this->request->getJSON(true);

        if (!isset($input['email'], $input['password'])) {
            return $this->failValidationErrors('Email dan password harus diisi');
        }

        $userModel = new UserModel();
        $user = $userModel->where('email', $input['email'])->first();

        if ($user && password_verify($input['password'], $user['password'])) {
            $payload = [
                'user_id' => $user['id'],
                'email'   => $user['email'],
                'exp'     => time() + 3600
            ];

            $token = $this->jwt->encode($payload);
            unset($user['password']);

            return $this->respond([
                'status'       => 'success',
                'access_token' => $token,
                'expires_in'   => 3600,
                'user'         => $user
            ]);
        }

        return $this->failUnauthorized('Email atau password salah');
    }

    public function refresh()
    {
        $authHeader = $this->request->getHeaderLine('Authorization');
        if (!$authHeader || !preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
            return $this->failUnauthorized('Token tidak ditemukan');
        }

        $token = $matches[1];

        try {
            $decoded = $this->jwt->decode($token);

            $newPayload = [
                'user_id' => $decoded->user_id,
                'email'   => $decoded->email,
                'exp'     => time() + 3600
            ];

            $newToken = $this->jwt->encode($newPayload);

            return $this->respond([
                'status'       => 'success',
                'access_token' => $newToken,
                'expires_in'   => 3600
            ]);
        } catch (\Exception $e) {
            return $this->failUnauthorized('Token tidak valid: ' . $e->getMessage());
        }
    }
}
