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
                        'user': self.auth_credentials.get('user'),
                        'passwd': self.auth_credentials.get('passwd')
                    }
                }
            ],
            'session': None
        }
        self.connection_args['json'] = payload

        response = requests.post(f'{self.base_url}/jsonrpc', **self.connection_args).json()

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

        requests.post(f'{self.base_url}/jsonrpc', **self.connection_args)

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

        response = requests.post(f'{self.base_url}/jsonrpc', **self.connection_args).json()

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
