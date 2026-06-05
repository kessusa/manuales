{
  "size": 0,
  "track_total_hits": true,
  "query": {
    "bool": {
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "now-15d/d",
              "lte": "now"
            }
          }
        },
        {
          "match_phrase": {
            "rule.id": "{{ $json.id }}"
          }
        },
        {
          "match_phrase": {
            "fortinet.vd": "{{ $json.vdom.toLowerCase() }}"
          }
        },
        {
          "bool": {
            "minimum_should_match": 1,
            "should": {{ JSON.stringify($json.installation_targets.map(target => ({ "match_phrase": { "deviceHostName": target } }))) }}
          }
        }
      ]
    }
  }
}
