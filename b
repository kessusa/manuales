{
  "size": 0,
  "track_total_hits": true,
  "query": {
    "bool": {
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "now-60d/d",
              "lte": "now"
            }
          }
        },
        {
          "match_phrase": {
            "rule.id": {{ JSON.stringify($json.id) }}
          }
        },
        {
          "match_phrase": {
            "fortinet.vd": {{ JSON.stringify($json.vdom.toLowerCase()) }}
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
