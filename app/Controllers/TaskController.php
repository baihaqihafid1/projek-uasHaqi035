<?php

namespace App\Controllers;

use CodeIgniter\RESTful\ResourceController;
use App\Models\TaskModel;

class TaskController extends ResourceController
{
    protected $modelName = 'App\Models\TaskModel';
    protected $format = 'json';

    public function index()
    {
        // Bug #24: No filtering by project or user
        $tasks = $this->model->findAll();
        return $this->respond($tasks);
    }

    public function create()
    {
        $data = $this->request->getPost();

        // Bug #25: No validation for required fields
        // Bug #26: Not validating project ownership
        $taskId = $this->model->insert($data);

        if ($taskId) {
            return $this->respond([
                'status' => 'success',
                'message' => 'Task created successfully',
                'id' => $taskId
            ]);
        }

        return $this->failServerError('Creation failed');
    }

    public function show($id = null)
    {
        // Bug #27: No access control
        $task = $this->model->find($id);

        if (!$task) {
            return $this->failNotFound('Task not found');
        }

        return $this->respond($task);
    }

    public function update($id = null)
    {
        $data = $this->request->getRawInput();

        if (!$this->model->find($id)) {
            return $this->failNotFound('Task not found');
        }

        // Bug #28: No validation for status updates
        if ($this->model->update($id, $data)) {
            return $this->respond([
                'status' => 'success',
                'message' => 'Task updated successfully'
            ]);
        }

        return $this->failServerError('Update failed');
    }

    public function delete($id = null)
    {
        if (!$this->model->find($id)) {
            return $this->failNotFound('Task not found');
        }

        if ($this->model->delete($id)) {
            return $this->respond([
                'status' => 'success',
                'message' => 'Task deleted successfully'
            ]);
        }

        return $this->failServerError('Delete failed');
    }
}
