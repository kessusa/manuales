import json
import requests
from API_cnx.playflows import PlayflowsAPI

obj_playflows = PlayflowsAPI(env='emea')
sid = obj_playflows.get_sid()
obj_playflows.connection_args['json'] = {
    'sid': sid,
    'pattern': 'GECD_FORCE_PROD',
    'version': 'upcoming',
    'flavours': ['use_watch'],
}
response = requests.post(f'{obj_playflows.base_url}/search', **obj_playflows.connection_args).json()
obj_playflows.logout(sid)

with open('media/group_comparator_sample.json', 'w') as sample_file:
    json.dump(response, sample_file, indent=2)

print(json.dumps(response['implicit-results'][0], indent=2)[:3000])
