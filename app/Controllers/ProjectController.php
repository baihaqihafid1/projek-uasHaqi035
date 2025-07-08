<?php

namespace App\Controllers;

use CodeIgniter\RESTful\ResourceController;
use App\Models\ProjectModel;

class ProjectController extends ResourceController
{
    protected $modelName = 'App\Models\ProjectModel';
    protected $format = 'json';

    public function index()
    {
        // Bug #18: Shows all projects instead of user's projects only
        $projects = $this->model->findAll();
        return $this->respond($projects);
    }

    public function create()
    {
        $data = $this->request->getPost();

        // Bug #19: No input validation
        // Bug #20: Not setting user_id from JWT token
        $projectId = $this->model->insert($data);

        if ($projectId) {
            return $this->respond([
                'status' => 'success',
                'message' => 'Project created successfully',
                'id' => $projectId
            ]);
        }

        return $this->failServerError('Creation failed');
    }

    public function show($id = null)
    {
        // Bug #21: No ownership check
        $project = $this->model->find($id);

        if (!$project) {
            return $this->failNotFound('Project not found');
        }

        return $this->respond($project);
    }

    public function update($id = null)
    {
        $data = $this->request->getRawInput();

        // Bug #22: No ownership validation
        if (!$this->model->find($id)) {
            return $this->failNotFound('Project not found');
        }

        if ($this->model->update($id, $data)) {
            return $this->respond([
                'status' => 'success',
                'message' => 'Project updated successfully'
            ]);
        }

        return $this->failServerError('Update failed');
    }

    public function delete($id = null)
    {
        // Bug #23: No ownership check
        if (!$this->model->find($id)) {
            return $this->failNotFound('Project not found');
        }

        if ($this->model->delete($id)) {
            return $this->respond([
                'status' => 'success',
                'message' => 'Project deleted successfully'
            ]);
        }

        return $this->failServerError('Delete failed');
    }
}
