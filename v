# get_published_changes for the CheckPoint class (paste it inside the class).
# It manages its own session like get_vpn : login on the domain, run the
# command, logout before returning.
# show-changes is asynchronous : it returns a task-id and the changes are
# returned inside the task details once the task is finished.


    # # Get published changes : returns the changes published on the domain
    # # in a date range, grouped by session, without installing anything.
    # # This is the closest equivalent to the FortiManager preview : the
    # # pending changes of a package are the published changes since its
    # # last installation, so pass the last install date as from_date.
    # # Dates in ISO format (e.g. '2026-08-01' or '2026-08-01T00:00:00')
    def get_published_changes(self, url, name, from_date=None, to_date=None, limit=100):
        result = []

        # # Connect to MDS on the given domain
        self.auth_credentials['domain'] = name
        sid = self.login(url)

        payload = {
            'limit': limit,
            'details-level': 'standard'
        }

        # both dates are optional, Check Point defaults to the recent history
        if from_date:
            payload['from-date'] = from_date

        if to_date:
            payload['to-date'] = to_date

        connection_args = {
            'headers': {'Content-Type': 'application/json', 'X-chkp-sid': sid},
            'json': payload,
            'verify': False
        }

        response = requests.post(f'{url}/show-changes', **connection_args)

        if response.status_code == 200:
            # show-changes only returns a task-id, the changes come inside
            # the task once it is finished
            task_id = response.json().get('task-id', None)

            if task_id:
                task = self.wait_for_task(url, sid, task_id)

                for detail in task.get('task-details', []):

                    # one entry per published session, each with its operations
                    for change in detail.get('changes', []):
                        session = change.get('session', {})
                        operations = change.get('operations', {})

                        result_dict = {
                            'session_name': session.get('name', None),
                            'user': session.get('user-name', None),
                            'publish_time': session.get('publish-time', {}).get('iso-8601', None) if isinstance(session.get('publish-time', None), dict) else session.get('publish-time', None),
                            'added': [obj.get('name', None) for obj in operations.get('added-objects', [])],
                            'modified': [obj.get('name', None) for obj in operations.get('modified-objects', [])],
                            'deleted': [obj.get('name', None) for obj in operations.get('deleted-objects', [])]
                        }
                        result.append(result_dict)

        # Logout
        self.logout(url, sid)

        return result
