# Add to API_cnx/checkpoint.py (class CheckPoint). Requires `import time` at module level.
# Headers: reuse exactly the same headers/connection_args pattern as your existing methods.

    def verify_policy_package(self, sid, url, policy_name):
        # Starts verify-policy and returns the task-id (the result is read with show-task)
        payload = {'policy-package': policy_name}
        try:
            response = requests.post(f'{url}/verify-policy', json=payload,
                                     headers={'Content-Type': 'application/json', 'X-chkp-sid': sid},
                                     **self.connection_args)
            response.raise_for_status()
            return response.json().get('task-id')
        except Exception as error:
            logger.error(f'Check Point verify-policy error ({policy_name}): {error}')
            return None

    def show_task(self, sid, url, task_id):
        payload = {'task-id': task_id, 'details-level': 'full'}
        try:
            response = requests.post(f'{url}/show-task', json=payload,
                                     headers={'Content-Type': 'application/json', 'X-chkp-sid': sid},
                                     **self.connection_args)
            response.raise_for_status()
            return response.json()
        except Exception as error:
            logger.error(f'Check Point show-task error ({task_id}): {error}')
            return None

    def wait_for_task(self, sid, url, task_id, timeout=300, interval=5):
        # Returns the finished task, the last 'in progress' task on timeout, or None on API error
        deadline = time.monotonic() + timeout
        task = None
        while time.monotonic() < deadline:
            response = self.show_task(sid, url, task_id)
            if not response:
                return None
            task = (response.get('tasks') or [{}])[0]
            if task.get('status') != 'in progress':
                return task
            time.sleep(interval)
        return task

    def preview_policy_package(self, sid, url, policy_name):
        # Same contract as FortiManagerAPI.preview_policy_package: returns (message, transaction_id)
        task_id = self.verify_policy_package(sid, url, policy_name)
        if not task_id:
            return None, None

        message = {
            'verify': self.wait_for_task(sid, url, task_id),
            'changes': self.get_pending_changes(sid, url, policy_name),
        }
        return message, task_id
