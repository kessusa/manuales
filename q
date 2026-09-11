# # Verify policy package (async) : launches the verification and
    # # returns the task id immediately, without waiting. Meant for the
    # # dashboard : the task id is stored and polled later with get_task_status
    def verify_policy_package_async(self, url, name, package):
        self.auth_credentials['domain'] = name
        sid = self.login(url)

        connection_args = {
            'headers': {'Content-Type': 'application/json', 'X-chkp-sid': sid},
            'json': {'policy-package': package},
            'verify': False
        }

        response = requests.post(f'{url}/verify-policy', **connection_args)

        task_id = response.json().get('task-id', None) if response.status_code == 200 else None

        self.logout(url, sid)

        return task_id

    # # Get task status : single non blocking check of a task. Returns the
    # # status, the progress and the task details. A task can be polled from
    # # a different session than the one that launched it, so the dashboard
    # # can store the task id and check it later
    def get_task_status(self, url, name, task_id):
        self.auth_credentials['domain'] = name
        sid = self.login(url)

        connection_args = {
            'headers': {'Content-Type': 'application/json', 'X-chkp-sid': sid},
            'json': {'task-id': task_id, 'details-level': 'full'},
            'verify': False
        }

        response = requests.post(f'{url}/show-task', **connection_args)

        task = response.json().get('tasks', [{}])[0] if response.status_code == 200 else {}

        self.logout(url, sid)

        return {
            'task_id': task_id,
            'status': task.get('status', None),
            'progress': task.get('progress-percentage', None),
            'finished': task.get('status', None) != 'in progress',
            'details': task.get('task-details', [])
        }
