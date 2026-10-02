# New methods for class CheckPoint in API_cnx/checkpoint.py.
# Existing (validated) methods are NOT modified. `time`, `requests` and `logger` are already imported there.
# Same argument order as the existing methods: (url, sid, ...).

    def login_domain(self, url, domain):
        # logout() overwrites connection_args['json'] with the sid, so restore the credentials first
        self.auth_credentials['domain'] = domain
        self.connection_args['json'] = self.auth_credentials
        return self.login(url)

    def session_args(self, sid, payload=None):
        # Same shape as the connection_args built in get_domain / get_vpn
        return {
            'headers': {'Content-Type': 'application/json', 'X-chkp-sid': sid},
            'json': payload or {},
            'verify': False,
        }

    def verify_policy_package(self, url, sid, policy_name):
        # Starts verify-policy and returns the task-id (the result is read with show-task)
        try:
            response = requests.post(f'{url}/verify-policy', **self.session_args(sid, {'policy-package': policy_name}))
            if response.status_code != 200:
                logger.error(f'Check Point verify-policy error ({policy_name}): {response.status_code} {response.text}')
                return None
            return response.json().get('task-id')
        except Exception as error:
            logger.error(f'Check Point verify-policy error ({policy_name}): {error}')
            return None

    def show_task(self, url, sid, task_id):
        try:
            response = requests.post(f'{url}/show-task', **self.session_args(sid, {'task-id': task_id, 'details-level': 'full'}))
            if response.status_code != 200:
                logger.error(f'Check Point show-task error ({task_id}): {response.status_code} {response.text}')
                return None
            return response.json()
        except Exception as error:
            logger.error(f'Check Point show-task error ({task_id}): {error}')
            return None

    def wait_for_task(self, url, sid, task_id, timeout=300, interval=5):
        # Returns the finished task, the last 'in progress' task on timeout, or None on API error
        deadline = time.monotonic() + timeout
        task = None
        while time.monotonic() < deadline:
            response = self.show_task(url, sid, task_id)
            if not response:
                return None
            task = (response.get('tasks') or [{}])[0]
            if task.get('status') != 'in progress':
                return task
            time.sleep(interval)
        return task
