import time

import requests
import urllib3

from bookmark.settings import (
    FORTIMANAGER_BASE_URL,
    get_fortimanager_auth_credentials,
    BNP_HEADERS,
)

urllib3.disable_warnings()


class FortiManagerAPI:
    def __init__(self):

        self.base_url = FORTIMANAGER_BASE_URL
        self.auth_credentials = get_fortimanager_auth_credentials()

        # Headers
        self.headers = BNP_HEADERS

        self.connection_args = {
            'proxies': {'https': None},
            'headers': self.headers,
            'verify': False
        }

    # # Login
    def login(self):
        payload = {
            'id': 1,
            'method': 'exec',
            'params': [
                {
                    'url': '/sys/login/user',
                    'data': {
                        'user': self.auth_credentials[0],
                        'passwd': self.auth_credentials[1]
                    }
                }
            ],
            'session': None
        }
        self.connection_args['json'] = payload

        response = requests.post(self.base_url, **self.connection_args).json()

        return response.get('session', None)

    # # Logout
    def logout(self, sid):
        payload = {
            'id': 1,
            'method': 'exec',
            'params': [
                {
                    'url': '/sys/logout'
                }
            ],
            'session': sid
        }
        self.connection_args['json'] = payload

        requests.post(self.base_url, **self.connection_args)

    # # Get data : returns rules details with IPS profiles
    def get_data(self, sid, adom, package):
        payload = {
            'id': 1,
            'method': 'get',
            'params': [
                {
                    'url': f'/pm/config/adom/{adom}/pkg/{package}/firewall/policy',
                    'fields': [
                        'policyid', 'name', 'srcintf', 'dstintf', 'srcaddr',
                        'dstaddr', 'service', 'action', 'status', 'utm-status',
                        'ips-sensor', 'comments'
                    ]
                }
            ],
            'session': sid
        }
        self.connection_args['json'] = payload

        response = requests.post(self.base_url, **self.connection_args).json()

        result = []

        status = response.get('result', [{}])[0].get('status', {})

        if status.get('code') == 0:
            for item in response['result'][0].get('data', []):
                if item.get('policyid'):

                    ips_profile = item['ips-sensor'][0] if item.get('ips-sensor', None) else None

                    source = item['srcaddr'] if item.get('srcaddr', None) else None

                    destination = item['dstaddr'] if item.get('dstaddr', None) else None

                    service = item['service'] if item.get('service', None) else None

                    result_dict = {
                        'rule_id': item.get('policyid'),
                        'rule_name': item.get('name', None),
                        'source': source,
                        'destination': destination,
                        'service': service,
                        'action': item.get('action', None),
                        'status': item.get('status', None),
                        'utm_status': item.get('utm-status', None),
                        'ips_profile': ips_profile,
                        'comments': item.get('comments', None)
                    }
                    result.append(result_dict)

        return result

    # # Lock ADOM : locks the ADOM workspace before making changes
    def lock_adom(self, sid, adom):
        payload = {
            'id': 1,
            'method': 'exec',
            'params': [
                {
                    'url': f'/dvmdb/adom/{adom}/workspace/lock'
                }
            ],
            'session': sid
        }
        self.connection_args['json'] = payload

        response = requests.post(self.base_url, **self.connection_args).json()

        return response.get('result', [{}])[0].get('status', {}).get('code', None)

    # # Commit ADOM : commits the pending changes of the ADOM workspace
    def commit_adom(self, sid, adom):
        payload = {
            'id': 1,
            'method': 'exec',
            'params': [
                {
                    'url': f'/dvmdb/adom/{adom}/workspace/commit'
                }
            ],
            'session': sid
        }
        self.connection_args['json'] = payload

        requests.post(self.base_url, **self.connection_args)

    # # Unlock ADOM : unlocks the ADOM workspace
    def unlock_adom(self, sid, adom):
        payload = {
            'id': 1,
            'method': 'exec',
            'params': [
                {
                    'url': f'/dvmdb/adom/{adom}/workspace/unlock'
                }
            ],
            'session': sid
        }
        self.connection_args['json'] = payload

        requests.post(self.base_url, **self.connection_args)

    # # Find package : searches a policy package across all ADOMs and returns
    # # its adom, vdom and installation targets. Packages without installation
    # # targets are skipped because the package may have been moved to another ADOM
    def find_policy_package(self, sid, package_name):
        result = None

        payload = {
            'id': 1,
            'method': 'get',
            'params': [
                {
                    'url': '/dvmdb/adom',
                    'fields': ['name']
                }
            ],
            'session': sid
        }
        self.connection_args['json'] = payload

        response = requests.post(self.base_url, **self.connection_args).json()

        adoms = response.get('result', [{}])[0].get('data', [])

        for adom_item in adoms:
            adom = adom_item.get('name', None)

            if adom:
                payload = {
                    'id': 1,
                    'method': 'get',
                    'params': [
                        {
                            'url': f'/pm/pkg/adom/{adom}'
                        }
                    ],
                    'session': sid
                }
                self.connection_args['json'] = payload

                response = requests.post(self.base_url, **self.connection_args).json()

                items = response.get('result', [{}])[0].get('data', [])

                package = self.search_package_in_tree(items, package_name)

                if package:
                    installation_targets = []

                    for target in package.get('scope member', []):
                        result_dict = {
                            'device': target.get('name', None),
                            'vdom': target.get('vdom', None)
                        }
                        installation_targets.append(result_dict)

                    # skip packages without installation targets and keep
                    # searching in the remaining ADOMs
                    if installation_targets:
                        result = {
                            'adom': adom,
                            'package': package.get('name', None),
                            'installation_targets': installation_targets
                        }
                        break

        return result

    # # Search package in tree : packages can be nested inside folders (subobj)
    def search_package_in_tree(self, nodes, package_name):
        found = None

        for item in nodes or []:

            if item.get('type') == 'pkg' and item.get('name') == package_name:
                found = item
                break

            if item.get('subobj', None) or item.get('type') == 'folder':
                found = self.search_package_in_tree(item.get('subobj', []), package_name)

                if found:
                    break

        return found

    # # Resolve devices : installation targets can be devices or device groups,
    # # device groups are expanded to their member devices
    def resolve_devices(self, sid, adom, scope_member):
        devices = []

        for target in scope_member:
            name = target.get('name', None)
            vdom = target.get('vdom', None)

            if name:
                payload = {
                    'id': 1,
                    'method': 'get',
                    'params': [
                        {
                            'url': f'/dvmdb/adom/{adom}/device/{name}'
                        }
                    ],
                    'session': sid
                }
                self.connection_args['json'] = payload

                response = requests.post(self.base_url, **self.connection_args).json()

                status_code = response.get('result', [{}])[0].get('status', {}).get('code', None)

                if status_code == 0:
                    result_dict = {
                        'name': name,
                        'oid': response.get('result', [{}])[0].get('data', {}).get('oid', None),
                        'vdom': vdom
                    }
                    devices.append(result_dict)

                else:
                    # the target is not a device, expand it as a device group
                    payload = {
                        'id': 1,
                        'method': 'get',
                        'params': [
                            {
                                'url': f'/dvmdb/adom/{adom}/group/{name}'
                            }
                        ],
                        'session': sid
                    }
                    self.connection_args['json'] = payload

                    response = requests.post(self.base_url, **self.connection_args).json()

                    members = response.get('result', [{}])[0].get('data', {}).get('object member', [])

                    for member in members:
                        member_name = member.get('name', None)

                        payload = {
                            'id': 1,
                            'method': 'get',
                            'params': [
                                {
                                    'url': f'/dvmdb/adom/{adom}/device/{member_name}'
                                }
                            ],
                            'session': sid
                        }
                        self.connection_args['json'] = payload

                        response_member = requests.post(self.base_url, **self.connection_args).json()

                        result_dict = {
                            'name': member_name,
                            'oid': response_member.get('result', [{}])[0].get('data', {}).get('oid', None),
                            'vdom': member.get('vdom', None)
                        }
                        devices.append(result_dict)

        return devices

    # # Preview : generates the install preview of a policy package
    def preview_policy_package(self, sid, adom, package, timeout=120):
        result = []

        self.lock_adom(sid, adom)

        try:
            # get the installation targets of the package to pass them
            # explicitly as scope member
            payload = {
                'id': 1,
                'method': 'get',
                'params': [
                    {
                        'url': f'/pm/pkg/adom/{adom}/{package}'
                    }
                ],
                'session': sid
            }
            self.connection_args['json'] = payload

            response = requests.post(self.base_url, **self.connection_args).json()

            scope_member = response.get('result', [{}])[0].get('data', {}).get('scope member', [])

            # expand device groups into real devices
            devices = self.resolve_devices(sid, adom, scope_member)

            scope = []

            for target in devices:
                scope_dict = {
                    'name': target.get('name', None),
                    'vdom': target.get('vdom', None)
                }
                scope.append(scope_dict)

            # step 1 : install the package in preview mode to generate
            # the preview cache
            payload = {
                'id': 1,
                'method': 'exec',
                'params': [
                    {
                        'url': '/securityconsole/install/package',
                        'data': {
                            'adom': adom,
                            'pkg': package,
                            'scope': scope,
                            'flags': ['preview']
                        }
                    }
                ],
                'session': sid
            }
            self.connection_args['json'] = payload

            response = requests.post(self.base_url, **self.connection_args).json()

            task_id = response.get('result', [{}])[0].get('data', {}).get('task', None)

            if task_id:
                self.wait_for_task(sid, task_id, timeout)

                for target in devices:
                    device = target.get('name', None)
                    vdom = target.get('vdom', None)

                    if device:
                        # step 2 : trigger the preview report generation
                        payload = {
                            'id': 1,
                            'method': 'exec',
                            'params': [
                                {
                                    'url': '/securityconsole/install/preview',
                                    'data': {
                                        'adom': adom,
                                        'flags': ['none'],
                                        'scope': [{'name': device, 'vdom': vdom}]
                                    }
                                }
                            ],
                            'session': sid
                        }
                        self.connection_args['json'] = payload

                        response = requests.post(self.base_url, **self.connection_args).json()

                        preview_task_id = response.get('result', [{}])[0].get('data', {}).get('task', None)

                        if preview_task_id:
                            self.wait_for_task(sid, preview_task_id, timeout)

                            # step 3 : retrieve the preview result
                            payload = {
                                'id': 1,
                                'method': 'exec',
                                'params': [
                                    {
                                        'url': '/securityconsole/preview/result',
                                        'data': {
                                            'adom': adom,
                                            'scope': [{'name': device, 'vdom': vdom}]
                                        }
                                    }
                                ],
                                'session': sid
                            }
                            self.connection_args['json'] = payload

                            preview = requests.post(self.base_url, **self.connection_args).json()

                            message = preview.get('result', [{}])[0].get('data', {}).get('message', None)

                            result_dict = {
                                'device': device,
                                'vdom': vdom,
                                'preview': message
                            }
                            result.append(result_dict)

        finally:
            # step 4 : cancel the policy package install process to clear
            # the preview session
            payload = {
                'id': 1,
                'method': 'exec',
                'params': [
                    {
                        'url': '/securityconsole/package/cancel/install',
                        'data': {
                            'adom': adom
                        }
                    }
                ],
                'session': sid
            }
            self.connection_args['json'] = payload

            requests.post(self.base_url, **self.connection_args)

            self.unlock_adom(sid, adom)

        return result

    # # Wait for task : polls a task until it is finished or timeout is reached
    def wait_for_task(self, sid, task_id, timeout=120):
        task = {}
        elapsed = 0

        while elapsed < timeout:
            payload = {
                'id': 1,
                'method': 'get',
                'params': [
                    {
                        'url': f'/task/task/{task_id}'
                    }
                ],
                'session': sid
            }
            self.connection_args['json'] = payload

            response = requests.post(self.base_url, **self.connection_args).json()

            task = response.get('result', [{}])[0].get('data', {})

            if task.get('percent') == 100:
                break

            time.sleep(2)
            elapsed += 2

        return task
