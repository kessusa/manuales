# Final get_published_changes for the CheckPoint class, with human readable
# output (paste inside the class; it uses wait_for_task, get_object_details
# and get_layer_packages, plus the describe_object helper below).
#
# Output : one entry per published session, with the full detail of every
# added / modified object (resolved from its uid) and the type + uid of the
# deleted ones. Deleted objects no longer exist on the management server,
# so their definition cannot be rebuilt through the API : only what
# show-changes returns (uid + type) is available for them. For modified
# objects the API does not expose a before / after diff either : the detail
# shown is the object as it is now (after the change).


    # # Describe object : turns the full object returned by
    # # get_object_details into a compact human readable summary
    def describe_object(self, detail):
        result = None

        if detail:
            result = {
                'type': detail.get('type', None),
                'name': detail.get('name', None)
            }

            # access rules : show the fields a human needs to understand
            # the rule. With details-level full the members come as objects,
            # so we extract their names
            if detail.get('type') == 'access-rule':
                result['source'] = [x.get('name', None) if isinstance(x, dict) else x for x in detail.get('source', [])]
                result['destination'] = [x.get('name', None) if isinstance(x, dict) else x for x in detail.get('destination', [])]
                result['service'] = [x.get('name', None) if isinstance(x, dict) else x for x in detail.get('service', [])]
                result['action'] = detail.get('action', {}).get('name', None) if isinstance(detail.get('action', None), dict) else detail.get('action', None)
                result['enabled'] = detail.get('enabled', None)
                result['policy_packages'] = detail.get('policy_packages', [])

            # network objects : add the addressing fields when present
            else:
                if detail.get('ipv4-address', None):
                    result['ipv4_address'] = detail.get('ipv4-address')

                if detail.get('subnet4', None):
                    result['subnet'] = f"{detail.get('subnet4')}/{detail.get('mask-length4', '')}"

                if detail.get('members', None):
                    result['members'] = [x.get('name', None) if isinstance(x, dict) else x for x in detail.get('members', [])]

        return result

    # # Get published changes : returns the changes published on the domain
    # # in a date range, grouped by session, without installing anything.
    # # Every added / modified object is resolved to a human readable
    # # summary (for rules : sources, destinations, services, action and
    # # the policy packages of its layer)
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

                        added = []
                        modified = []
                        deleted = []

                        # added / modified objects still exist : rebuild
                        # their full definition from the uid
                        for obj in operations.get('added-objects', []):
                            object_detail = self.get_object_details(url, sid, obj.get('uid', None))
                            added.append(self.describe_object(object_detail))

                        for obj in operations.get('modified-objects', []):
                            object_detail = self.get_object_details(url, sid, obj.get('uid', None))
                            modified.append(self.describe_object(object_detail))

                        # deleted objects no longer exist, only the type
                        # and uid returned by show-changes are available
                        for obj in operations.get('deleted-objects', []):
                            deleted.append(
                                {
                                    'type': obj.get('type', None),
                                    'uid': obj.get('uid', None)
                                }
                            )

                        result_dict = {
                            'session_name': session.get('session-name', None),
                            'description': session.get('session-description', None),
                            'user': session.get('user-name', None),
                            'publish_time': session.get('publish-time', {}).get('iso-8601', None) if isinstance(session.get('publish-time', None), dict) else session.get('publish-time', None),
                            'added': added,
                            'modified': modified,
                            'deleted': deleted
                        }
                        result.append(result_dict)

        # Logout
        self.logout(url, sid)

        return result
