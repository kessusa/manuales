import requests
import urllib3
from bookmark.settings import (
    INETPORTAL_BASE_URL,
    get_inetportal_auth_credentials,
)

urllib3.disable_warnings()


class InetPortalV2:
    def __init__(self):

        self.base_url = INETPORTAL_BASE_URL
        self.auth_credentials = get_inetportal_auth_credentials()

        # Headers
        self.headers = {
            'accept': 'application/json',
            'Content-Type': 'application/json'
        }

        self.connection_args = {
            'proxies': {'https': None},
            'headers': self.headers,
            'verify': False
        }

    # # Login / Token
    def get_token(self):

        self.connection_args['headers'] = {
            'accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        auth_data = {
            'grant_type': 'password',
            'username': self.auth_credentials[0],
            'password': self.auth_credentials[1],
            'scope': '',
            'client_id': 'string',
            'client_secret': ''
        }

        response = requests.post(f'{self.base_url}/api/v1/token', data=auth_data, **self.connection_args).json()
        return response.get('access_token')

    # # Loadbalancers
    def get_loadbalancers(self, token, page=0, limit=30, search_string=None, searched_backend=None, techno='All'):

        self.connection_args['headers'] = {**self.headers, 'Authorization': f'Bearer {token}'}

        params = {
            'page': page,
            'limit': limit,
            'techno': techno
        }
        if search_string:
            params['search_string'] = search_string
        if searched_backend:
            params['searched_backend'] = searched_backend

        response = requests.get(f'{self.base_url}/api/v1/loadbalancer', params=params, **self.connection_args).json()

        if not response.get('data'):
            return None

        return {
            'loadbalancers': [
                {
                    'data_fetched_time': item.get('data_fetched_time'),
                    'hosting_device': item.get('hosting_device'),
                    'partition': item.get('partition'),
                    'certificate': item.get('certificate', []),
                    'ssl_client': item.get('ssl_client', False),
                    'tls_client': item.get('tls_client', []),
                    'name': item.get('name'),
                    'enabled': item.get('enabled', False),
                    'administrative': [
                        {
                            'golden_app_id': admin.get('golden_app_id'),
                            'application_name': admin.get('application_name'),
                            'continuity_level': admin.get('continuity_level'),
                            'criticality': admin.get('criticality'),
                            'it_cluster': admin.get('it_cluster'),
                            'it_subcluster': admin.get('it_subcluster'),
                            'auid': admin.get('auid')
                        }
                        for admin in item.get('administrative', [])
                    ],
                    'frontend': {
                        'ip': item.get('frontend', {}).get('ip'),
                        'mask': item.get('frontend', {}).get('mask'),
                        'port': item.get('frontend', {}).get('port', []),
                        'description': item.get('frontend', {}).get('description'),
                        'profil': item.get('frontend', {}).get('profil', []),
                        'protocol': item.get('frontend', {}).get('protocol')
                    },
                    'pool': [
                        {
                            'algorithm': pool.get('algorithm'),
                            'name': pool.get('name'),
                            'monitor': pool.get('monitor', []),
                            'ssl_srv': pool.get('ssl_srv', False),
                            'tls_srv': pool.get('tls_srv', []),
                            'state': pool.get('state'),
                            'members': [
                                {
                                    'ip': member.get('ip'),
                                    'reason': member.get('reason'),
                                    'port': member.get('port'),
                                    'state': member.get('state')
                                }
                                for member in pool.get('members', [])
                            ],
                            'state_historic': [
                                {
                                    'timestamp': state.get('timestamp'),
                                    'state': state.get('state')
                                }
                                for state in pool.get('state_historic', [])
                            ],
                            'last_state_chg': pool.get('last_state_chg'),
                            'persistence': pool.get('persistence', [])
                        }
                        for pool in item.get('pool', [])
                    ]
                }
                for item in response['data']
            ],
            'page': response.get('page', 0),
            'next': response.get('next', 0),
            'total': response.get('total', 0)
        }


if __name__ == '__main__':
    inet_obj = InetPortalV2()
    token = inet_obj.get_token()
    print(f'Token: {token}')

    if token:
        loadbalancers = inet_obj.get_loadbalancers(
            token=token,
            page=0,
            limit=1,
            search_string='fxplus-inter-pres-fr-https-stg'
        )
        print(loadbalancers)
