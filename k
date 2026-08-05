# Check Point MDS connector : published changes flow.
# The Check Point Management API exposes one endpoint per command : every
# call is a POST request to <url>/<command>. Login is domain-scoped on the
# MDS (the domain travels inside the auth credentials) and after login every
# request must carry the session token in the 'X-chkp-sid' header.
#
# The published changes flow is the closest equivalent to the FortiManager
# install preview : the pending changes of a domain are the sessions
# published since the last installation. show-changes returns them, and the
# methods below turn every added / modified / deleted object into a human
# readable summary (rules with their sources, destinations, services and
# action, groups expanded to their real networks / IPs / services).
import time

import requests
import urllib3

from bookmark.settings import (
    MDS_URL_V1,
    MDS_URL_V2,
    BNP_HEADERS,
    get_bnp_proxies_extra,
    get_mds_auth_credentials,
)

# We connect with 'verify': False (internal self-signed certificate),
# this disables the InsecureRequestWarning printed on every request
urllib3.disable_warnings()


class CheckPoint:
    def __init__(self):
        # # Base URL
        self.base_url_v1 = MDS_URL_V1
        self.base_url_v2 = MDS_URL_V2

        # Headers
        self.headers = BNP_HEADERS

        # Proxy
        self.bnp_proxies = get_bnp_proxies_extra()['https']

        # auth credentials
        self.auth_credentials = get_mds_auth_credentials()

        self.connection_args = {
            'headers': self.headers,
            'json': self.auth_credentials,
            'verify': False
        }

    # # Login : opens a session on the domain set in the auth credentials
    # # and returns the session token (sid). The credentials are restored
    # # in connection_args because other methods may overwrite the json
    def login(self, url=None):
        self.connection_args['json'] = self.auth_credentials

        return requests.post(f'{url}/login', **self.connection_args).json()['sid']

    # # Logout : closes the session so it does not stay open on the server.
    # # Check Point expects the sid in the X-chkp-sid header, and a local
    # # connection_args is used to avoid mutating the shared one
    def logout(self, url, sid):
        connection_args = {
            'headers': {'Content-Type': 'application/json', 'X-chkp-sid': sid},
            'json': {},
            'verify': False
        }

        requests.post(f'{url}/logout', **connection_args)

    # # Wait for task : show-changes (like verify-policy and install-policy)
    # # is asynchronous, it returns a task-id. This polls show-task every
    # # 2 seconds until the task is no longer in progress or the timeout is
    # # exceeded, and returns the task data
    def wait_for_task(self, url, sid, task_id, timeout=300):
        task = {}
        elapsed = 0

        connection_args = {
            'headers': {'Content-Type': 'application/json', 'X-chkp-sid': sid},
            'json': {'task-id': task_id, 'details-level': 'full'},
            'verify': False
        }

        while elapsed < timeout:
            response = requests.post(f'{url}/show-task', **connection_args)

            if response.status_code == 200:
                # show-task returns a list of tasks, we always ask for one
                task = response.json().get('tasks', [{}])[0]

                if task.get('status') != 'in progress':
                    break

            time.sleep(2)
            elapsed += 2

        return task

    # # Get object details : returns the full definition of an object from
    # # its uid, used to rebuild what was created / modified in a published
    # # session. For access rules it also resolves the layer and the policy
    # # packages that contain it. The sid must belong to a session on the domain
    def get_object_details(self, url, sid, uid):
        result = None

        connection_args = {
            'headers': {'Content-Type': 'application/json', 'X-chkp-sid': sid},
            'json': {'uid': uid, 'details-level': 'full'},
            'verify': False
        }

        # generic lookup by uid, works for any object type
        response = requests.post(f'{url}/show-object', **connection_args)

        if response.status_code == 200:
            result = response.json().get('object', {})

            # access rules have a dedicated command that returns the
            # complete rule (source, destination, service, action, position
            # in the layer, ...). The layer comes in the object
            if result.get('type') == 'access-rule' and result.get('layer', None):
                layer = result.get('layer')

                connection_args['json'] = {
                    'uid': uid,
                    'layer': layer,
                    'details-level': 'full',
                    # resolve source / destination / service uids to names
                    'show-as-ranges': False
                }

                rule_response = requests.post(f'{url}/show-access-rule', **connection_args)

                if rule_response.status_code == 200:
                    result = rule_response.json()

                # resolve the policy packages that contain the layer of the
                # rule, so the change can be traced back to its package
                result['policy_packages'] = self.get_layer_packages(url, sid, layer)

            # nat rules belong to the NAT rulebase of a policy package :
            # show-nat-rule needs the package, which show-object does not
            # return, so we try every package of the domain until found
            if result.get('type') == 'nat-rule':
                packages_args = {
                    'headers': {'Content-Type': 'application/json', 'X-chkp-sid': sid},
                    'json': {'limit': 500},
                    'verify': False
                }
                packages_response = requests.post(f'{url}/show-packages', **packages_args)

                if packages_response.status_code == 200:

                    for package in packages_response.json().get('packages', []):
                        package_name = package.get('name', None)

                        connection_args['json'] = {
                            'uid': uid,
                            'package': package_name,
                            'details-level': 'full'
                        }

                        rule_response = requests.post(f'{url}/show-nat-rule', **connection_args)

                        if rule_response.status_code == 200:
                            result = rule_response.json()
                            result['policy_packages'] = [package_name]
                            break

        return result

    # # Get layer packages : returns the policy packages that contain the
    # # given access layer. A layer can be shared by several packages, so
    # # a list is returned. The sid must belong to a session on the domain
    def get_layer_packages(self, url, sid, layer):
        result = []

        connection_args = {
            'headers': {'Content-Type': 'application/json', 'X-chkp-sid': sid},
            'json': {'details-level': 'full', 'limit': 500},
            'verify': False
        }

        response = requests.post(f'{url}/show-packages', **connection_args)

        if response.status_code == 200:

            for package in response.json().get('packages', []):

                # the layer of a rule can come as a uid or as a name,
                # match against both
                for access_layer in package.get('access-layers', []):

                    if layer in (access_layer.get('uid', None), access_layer.get('name', None)):
                        result.append(package.get('name', None))
                        break

        return result

    # # Resolve member : resolves one member of a group to a readable
    # # summary. The member can come as a uid string or as an object; nested
    # # groups are expanded recursively
    def resolve_member(self, url, sid, member):
        result = None

        # members can come as plain uid strings : fetch the full object
        if isinstance(member, str):
            member = self.get_object_details(url, sid, member)

        if member:
            result = {
                'name': member.get('name', None),
                'type': member.get('type', None)
            }

            # addressing information of the member
            if member.get('ipv4-address', None):
                result['ipv4_address'] = member.get('ipv4-address')

            if member.get('subnet4', None):
                result['subnet'] = f"{member.get('subnet4')}/{member.get('mask-length4', '')}"

            if member.get('port', None):
                result['port'] = member.get('port')

            # nested groups : expand their members recursively. The members
            # of an inline group can be uid strings, so they are resolved too
            if member.get('members', None):
                result['members'] = [
                    self.resolve_member(url, sid, x) for x in member.get('members', [])
                ]

        return result

    # # Describe reference : turns one source / destination / service entry
    # # of a rule into a readable summary, expanding groups to their members
    def describe_reference(self, url, sid, ref):
        result = None

        # references can come as plain uid strings : fetch the full object
        if isinstance(ref, str):
            ref = self.get_object_details(url, sid, ref)

        if ref:
            result = {
                'name': ref.get('name', None),
                'type': ref.get('type', None)
            }

            # groups (network groups, service groups...) : expand their
            # members so the real networks / IPs / services are visible
            if ref.get('members', None) or 'group' in (ref.get('type', '') or ''):

                members = ref.get('members', None)

                # inline objects sometimes come without the members list :
                # fetch the full group from its uid
                if not members and ref.get('uid', None):
                    full_group = self.get_object_details(url, sid, ref.get('uid'))
                    members = full_group.get('members', []) if full_group else []

                result['members'] = [
                    self.resolve_member(url, sid, x) for x in members or []
                ]

        return result

    # # Describe object : turns the full object returned by
    # # get_object_details into a compact human readable summary. Rule
    # # references (sources, destinations, services) are expanded : groups
    # # show the real networks / IPs / services of their members
    def describe_object(self, url, sid, detail):
        result = None

        if detail:
            result = {
                'type': detail.get('type', None),
                'uid': detail.get('uid', None),
                'name': detail.get('name', None)
            }

            # access rules : show the fields a human needs to understand
            # the rule, expanding the groups referenced in each column
            if detail.get('type') == 'access-rule':
                result['source'] = [self.describe_reference(url, sid, x) for x in detail.get('source', [])]
                result['destination'] = [self.describe_reference(url, sid, x) for x in detail.get('destination', [])]
                result['service'] = [self.describe_reference(url, sid, x) for x in detail.get('service', [])]
                result['action'] = detail.get('action', {}).get('name', None) if isinstance(detail.get('action', None), dict) else detail.get('action', None)
                result['enabled'] = detail.get('enabled', None)
                result['policy_packages'] = detail.get('policy_packages', [])

            # nat rules : original / translated columns hold a single
            # object each (not a list like access rules)
            elif detail.get('type') == 'nat-rule':
                result['original_source'] = self.describe_reference(url, sid, detail.get('original-source', None))
                result['original_destination'] = self.describe_reference(url, sid, detail.get('original-destination', None))
                result['original_service'] = self.describe_reference(url, sid, detail.get('original-service', None))
                result['translated_source'] = self.describe_reference(url, sid, detail.get('translated-source', None))
                result['translated_destination'] = self.describe_reference(url, sid, detail.get('translated-destination', None))
                result['translated_service'] = self.describe_reference(url, sid, detail.get('translated-service', None))
                result['method'] = detail.get('method', None)
                result['enabled'] = detail.get('enabled', None)
                result['comments'] = detail.get('comments', None)
                result['policy_packages'] = detail.get('policy_packages', [])

            # network objects : add the addressing fields when present
            else:
                if detail.get('ipv4-address', None):
                    result['ipv4_address'] = detail.get('ipv4-address')

                if detail.get('subnet4', None):
                    result['subnet'] = f"{detail.get('subnet4')}/{detail.get('mask-length4', '')}"

                if detail.get('members', None):
                    result['members'] = [
                        self.resolve_member(url, sid, x) for x in detail.get('members', [])
                    ]

        return result

    # # Resolve inline packages : when an object is described from its
    # # inline definition (deleted, or added / modified and later deleted),
    # # the policy packages are resolved from the layer (access rules) or
    # # from the package uid (nat rules)
    def resolve_inline_packages(self, url, sid, obj):
        result = []

        if obj.get('type') == 'access-rule' and obj.get('layer', None):
            result = self.get_layer_packages(url, sid, obj.get('layer'))

        elif obj.get('type') == 'nat-rule' and obj.get('package', None):
            package_detail = self.get_object_details(url, sid, obj.get('package'))
            result = [package_detail.get('name', None)] if package_detail else []

        return result

    # # Get published changes : returns the changes published on the domain
    # # in a date range, grouped by session, without installing anything.
    # # This is the closest equivalent to the FortiManager install preview.
    # # Every object is resolved to a human readable summary. With
    # # details-level full :
    # #   - added / modified objects still exist : their current definition
    # #     is rebuilt from the uid
    # #   - the old-object of a modified entry brings its full previous
    # #     definition inline : returned as 'previous'
    # #   - deleted objects come with their full definition inline, so they
    # #     can be described even though they no longer exist.
    # # Dates in ISO format (e.g. '2026-08-01')
    def get_published_changes(self, url, name, from_date=None, to_date=None, limit=100):
        result = []

        # # Connect to MDS on the given domain
        self.auth_credentials['domain'] = name
        sid = self.login(url)

        payload = {
            'limit': limit,
            # full is required : it returns the complete definition of the
            # deleted objects and of the old-object of the modified ones
            'details-level': 'full'
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

                        # added objects : rebuild from the uid; if the
                        # object was deleted in a later session the lookup
                        # fails, fall back to the inline definition
                        for obj in operations.get('added-objects', []):
                            object_detail = self.get_object_details(url, sid, obj.get('uid', None))

                            if not object_detail:
                                object_detail = obj

                            described = self.describe_object(url, sid, object_detail)

                            if described and object_detail is obj:
                                described['policy_packages'] = self.resolve_inline_packages(url, sid, obj)

                            added.append(described)

                        # modified entries wrap the object in new-object /
                        # old-object. The current state is rebuilt from the
                        # uid with the same inline fallback, the old-object
                        # brings the previous state inline
                        for obj in operations.get('modified-objects', []):
                            new_object = obj.get('new-object', obj)

                            object_detail = self.get_object_details(url, sid, new_object.get('uid', None))

                            if not object_detail:
                                object_detail = new_object

                            described = self.describe_object(url, sid, object_detail)

                            if described and object_detail is new_object:
                                described['policy_packages'] = self.resolve_inline_packages(url, sid, new_object)

                            if described and obj.get('old-object', None):
                                described['previous'] = self.describe_object(url, sid, obj.get('old-object'))

                            modified.append(described)

                        # deleted objects no longer exist : always described
                        # from the inline definition (complete with
                        # details-level full)
                        for obj in operations.get('deleted-objects', []):
                            old_object = obj.get('old-object', obj)

                            described = self.describe_object(url, sid, old_object)

                            if described:
                                described['policy_packages'] = self.resolve_inline_packages(url, sid, old_object)

                            deleted.append(described)

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

    # # Get names : turns a list of references (objects or uid strings)
    # # into a plain list of names, resolving uids when needed
    def get_names(self, url, sid, values):
        result = []

        for value in values or []:

            if isinstance(value, dict):
                result.append(value.get('name', None) or value.get('uid', None))

            elif isinstance(value, str):
                # plain uid : resolve it to get the name
                detail = self.get_object_details(url, sid, value)
                result.append(detail.get('name', None) if detail else value)

        return result

    # # Summarize object : compact representation of an object with only
    # # the fields needed to understand it (names only, no metadata).
    # # Designed for the pending changes output stored in the database
    def summarize_object(self, url, sid, detail):
        result = None

        if detail:
            result = {
                'type': detail.get('type', None),
                'uid': detail.get('uid', None),
                'name': detail.get('name', None)
            }

            if detail.get('type') == 'access-rule':
                result['position'] = detail.get('position', None)
                result['source'] = self.get_names(url, sid, detail.get('source', []))
                result['destination'] = self.get_names(url, sid, detail.get('destination', []))
                result['service'] = self.get_names(url, sid, detail.get('service', []))
                result['action'] = detail.get('action', {}).get('name', None) if isinstance(detail.get('action', None), dict) else detail.get('action', None)
                result['enabled'] = detail.get('enabled', None)

            elif detail.get('type') == 'nat-rule':
                result['position'] = detail.get('position', None)
                result['method'] = detail.get('method', None)
                result['original_source'] = self.get_names(url, sid, [detail.get('original-source', None)])[0] if detail.get('original-source', None) else None
                result['original_destination'] = self.get_names(url, sid, [detail.get('original-destination', None)])[0] if detail.get('original-destination', None) else None
                result['original_service'] = self.get_names(url, sid, [detail.get('original-service', None)])[0] if detail.get('original-service', None) else None
                result['translated_source'] = self.get_names(url, sid, [detail.get('translated-source', None)])[0] if detail.get('translated-source', None) else None
                result['translated_destination'] = self.get_names(url, sid, [detail.get('translated-destination', None)])[0] if detail.get('translated-destination', None) else None
                result['translated_service'] = self.get_names(url, sid, [detail.get('translated-service', None)])[0] if detail.get('translated-service', None) else None
                result['enabled'] = detail.get('enabled', None)

            # groups : the members are needed to understand what the
            # group contains and to compute the membership changes
            elif detail.get('members', None) is not None:
                result['members'] = self.get_names(url, sid, detail.get('members', []))

            # plain network objects : only the addressing
            else:
                if detail.get('ipv4-address', None):
                    result['ipv4_address'] = detail.get('ipv4-address')

                if detail.get('subnet4', None):
                    result['subnet'] = f"{detail.get('subnet4')}/{detail.get('mask-length4', '')}"

        return result

    # # Diff summaries : compares the previous and current summary of an
    # # object and returns human readable sentences describing the changes
    def diff_summaries(self, previous, current):
        result = []

        if not previous or not current:
            return result

        # list fields : report what was added / removed on each column.
        # For groups the field name is omitted ("'x' added"), for rule
        # columns it is included ("'x' added to source")
        list_fields = ['source', 'destination', 'service', 'members']

        for field in list_fields:
            old_values = set(previous.get(field, []) or [])
            new_values = set(current.get(field, []) or [])

            suffix = '' if field == 'members' else f' to {field}'

            for value in sorted(new_values - old_values):
                result.append(f"'{value}' added{suffix}")

            for value in sorted(old_values - new_values):
                result.append(f"'{value}' removed{suffix.replace(' to ', ' from ')}")

        # scalar fields : report old -> new
        scalar_fields = [
            'name', 'action', 'method', 'position',
            'original_source', 'original_destination', 'original_service',
            'translated_source', 'translated_destination', 'translated_service'
        ]

        for field in scalar_fields:
            old_value = previous.get(field, None)
            new_value = current.get(field, None)

            if field in previous and field in current and old_value != new_value:
                result.append(f"{field} changed from '{old_value}' to '{new_value}'")

        # enabled : disabling / enabling a rule deserves a clear sentence
        if previous.get('enabled', None) != current.get('enabled', None) and 'enabled' in current:
            result.append('rule disabled' if current.get('enabled') is False else 'rule enabled')

        return result

    # # Get affected rules : returns the rules that use the given object
    # # (directly or through nested groups), so a change on a group / host
    # # / network can be traced to the rules it impacts
    def get_affected_rules(self, url, sid, uid):
        result = []

        connection_args = {
            'headers': {'Content-Type': 'application/json', 'X-chkp-sid': sid},
            'json': {'uid': uid, 'details-level': 'standard'},
            'verify': False
        }

        response = requests.post(f'{url}/where-used', **connection_args)

        if response.status_code == 200:

            # direct usage : the object is referenced by the rule itself.
            # indirect usage : the object is inside a group used by the rule
            for usage, entries in [('direct', response.json().get('used-directly', {})),
                                   ('indirect', response.json().get('used-indirectly', {}))]:

                for rule_entry in (entries or {}).get('access-control-rules', []):
                    rule = rule_entry.get('rule', {})

                    result_dict = {
                        'rule_uid': rule.get('uid', None),
                        'rule_name': rule.get('name', None),
                        'position': rule_entry.get('position', None),
                        'layer': rule_entry.get('layer', {}).get('name', None),
                        'package': rule_entry.get('package', {}).get('name', None),
                        'usage': usage
                    }
                    result.append(result_dict)

                for rule_entry in (entries or {}).get('nat-rules', []):
                    rule = rule_entry.get('rule', {})

                    result_dict = {
                        'rule_uid': rule.get('uid', None),
                        'rule_name': rule.get('name', None),
                        'position': rule_entry.get('position', None),
                        'layer': None,
                        'package': rule_entry.get('package', {}).get('name', None),
                        'usage': usage
                    }
                    result.append(result_dict)

        return result

    # # Get pending changes : returns the net changes of the domain that
    # # will actually be installed on the next policy push, collapsing all
    # # the published sessions of the range per object :
    # #   - added and later deleted        -> nothing (never installed)
    # #   - added (and maybe modified)     -> one 'added' with final state
    # #   - modified one or several times  -> one 'modified' with the final
    # #     state and 'changes' comparing it with the installed state
    # #   - modified and later deleted     -> one 'deleted'
    # # Output : compact summary per object plus human readable 'changes'
    # # sentences, ready to be stored in a database. Changes on groups /
    # # hosts / networks include the rules that use them ('affected_rules').
    # # Dates in ISO format (e.g. '2026-08-01')
    def get_pending_changes(self, url, name, from_date=None, to_date=None, limit=100):
        result = []

        # # Connect to MDS on the given domain
        self.auth_credentials['domain'] = name
        sid = self.login(url)

        payload = {
            'limit': limit,
            # full is required : it returns the complete inline definition
            # of the deleted objects and of the old-object of the modified
            'details-level': 'full'
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

                # flatten every operation of every session with its publish
                # time, so they can be replayed in chronological order
                timeline = []

                for detail in task.get('task-details', []):

                    for change in detail.get('changes', []):
                        session = change.get('session', {})
                        operations = change.get('operations', {})

                        publish_time = session.get('publish-time', {}).get('posix', 0) if isinstance(session.get('publish-time', None), dict) else 0

                        for obj in operations.get('added-objects', []):
                            timeline.append((publish_time, 'added', obj))

                        for obj in operations.get('modified-objects', []):
                            timeline.append((publish_time, 'modified', obj))

                        for obj in operations.get('deleted-objects', []):
                            timeline.append((publish_time, 'deleted', obj))

                timeline.sort(key=lambda x: x[0])

                # replay the timeline per object uid to compute the net
                # effect of all the sessions
                pending = {}

                for publish_time, operation, obj in timeline:

                    if operation == 'added':
                        uid = obj.get('uid', None)

                        if uid:
                            pending[uid] = {
                                'added': True,
                                'modified': False,
                                'deleted': False,
                                'first_previous': None,
                                'last_definition': obj
                            }

                    elif operation == 'modified':
                        new_object = obj.get('new-object', obj)
                        uid = new_object.get('uid', None)

                        if uid:
                            entry = pending.get(uid, None)

                            if entry:
                                entry['modified'] = True
                                entry['last_definition'] = new_object

                            else:
                                pending[uid] = {
                                    'added': False,
                                    'modified': True,
                                    'deleted': False,
                                    # state before the first change : this
                                    # is what is installed on the firewall
                                    'first_previous': obj.get('old-object', None),
                                    'last_definition': new_object
                                }

                    elif operation == 'deleted':
                        old_object = obj.get('old-object', obj)
                        uid = old_object.get('uid', None)

                        if uid:
                            entry = pending.get(uid, None)

                            if entry:
                                entry['deleted'] = True
                                entry['last_definition'] = old_object

                            else:
                                pending[uid] = {
                                    'added': False,
                                    'modified': False,
                                    'deleted': True,
                                    'first_previous': None,
                                    'last_definition': old_object
                                }

                # build the net summarized output
                for uid, entry in pending.items():

                    if entry['deleted']:

                        # created and removed within the range : it never
                        # reaches the firewall, nothing will be installed
                        if entry['added']:
                            continue

                        summary = self.summarize_object(url, sid, entry['last_definition'])

                        if summary:
                            summary['operation'] = 'deleted'
                            summary['changes'] = ['object deleted']
                            summary['policy_packages'] = self.resolve_inline_packages(url, sid, entry['last_definition'])
                            result.append(summary)

                    else:
                        # final state : resolve by uid, fall back to the
                        # last inline definition
                        object_detail = self.get_object_details(url, sid, uid)

                        if not object_detail:
                            object_detail = entry['last_definition']

                        summary = self.summarize_object(url, sid, object_detail)

                        if summary:
                            if object_detail is entry['last_definition']:
                                summary['policy_packages'] = self.resolve_inline_packages(url, sid, entry['last_definition'])

                            else:
                                summary['policy_packages'] = object_detail.get('policy_packages', [])

                            if entry['added']:
                                summary['operation'] = 'added'
                                summary['changes'] = ['object created']

                            else:
                                summary['operation'] = 'modified'

                                # human readable sentences comparing the
                                # installed state with the final state
                                previous_summary = self.summarize_object(url, sid, entry['first_previous'])
                                summary['changes'] = self.diff_summaries(previous_summary, summary)

                                # changes on groups / hosts / networks : add
                                # the rules that use the object, so the real
                                # impact of the change is visible
                                if summary.get('type') not in ('access-rule', 'nat-rule'):
                                    summary['affected_rules'] = self.get_affected_rules(url, sid, uid)

                            result.append(summary)

        # Logout
        self.logout(url, sid)

        return result


if __name__ == '__main__':
    obj_mds = CheckPoint()

    domain = 'ETS-UK'

    # net pending changes : what will actually be installed on the next
    # push (compact summaries + human readable change sentences)
    results = obj_mds.get_pending_changes(
        obj_mds.base_url_v1, domain, from_date='2026-08-05'
    )

    print("===== Pending changes to install =====")

    for item in results:
        print(f"{item['operation'].upper()}: [{item['type']}] "
              f"{item['name'] or item['uid']} "
              f"(packages: {item.get('policy_packages', [])})")

        for change in item['changes']:
            print(f"  - {change}")

        for rule in item.get('affected_rules', []):
            print(f"  used by rule {rule['rule_uid']} "
                  f"(position {rule['position']}, package {rule['package']}, "
                  f"{rule['usage']})")

    # session by session history with full detail (audit view) :
    # history = obj_mds.get_published_changes(
    #     obj_mds.base_url_v1, domain, from_date='2026-08-05'
    # )
