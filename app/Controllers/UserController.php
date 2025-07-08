<?php

namespace App\Controllers;

use CodeIgniter\RESTful\ResourceController;
use App\Models\UserModel;

class UserController extends ResourceController
{
    protected $modelName = 'App\Models\UserModel';
    protected $format = 'json';

    public function index()
    {
        // Bug #12: No pagination
        $users = $this->model->findAll();
        return $this->respond($users);
    }

    public function show($id = null)
    {
        // Bug #13: No input validation for ID
        $user = $this->model->find($id);

        if (!$user) {
            return $this->failNotFound('User not found');
        }

        // Bug #14: Returning sensitive data
        return $this->respond($user);
    }

    public function update($id = null)
    {
        // Bug #15: No authorization check (user can update other users)
        $data = $this->request->getRawInput();

        if (!$this->model->find($id)) {
            return $this->failNotFound('User not found');
        }

        // Bug #16: No input validation
        if ($this->model->update($id, $data)) {
            return $this->respond([
                'status' => 'success',
                'message' => 'User updated successfully'
            ]);
        }

        return $this->failServerError('Update failed');
    }

    public function delete($id = null)
    {
        // Bug #17: No authorization check
        if (!$this->model->find($id)) {
            return $this->failNotFound('User not found');
        }

        if ($this->model->delete($id)) {
            return $this->respond([
                'status' => 'success',
                'message' => 'User deleted successfully'
            ]);
        }

        return $this->failServerError('Delete failed');
    }
}
