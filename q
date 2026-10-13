import json
from pathlib import Path

SAMPLE_PATH = Path(__file__).resolve().parent.parent / 'media' / 'group_comparator_sample.json'


def summarize(value):
    if isinstance(value, list) and len(value) > 5:
        return f'list[{len(value)}]: {value[:3]}...'
    return value


with open(SAMPLE_PATH) as sample_file:
    response = json.load(sample_file)

print('top-level keys:', list(response.keys()))
print('implicit-results:', len(response['implicit-results']))

for item in response['implicit-results'][:3]:
    print('TAG', item['tag'], 'keys:', list(item.keys()))
    for match in item['matches']:
        print('   ', {key: summarize(value) for key, value in match.items()})
