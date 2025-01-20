package elasticsearch

var mapping = `
{
    "index_patterns": ["falco-talon*"],
    "template": {
      "settings": {
        "number_of_shards": ${SHARDS},
        "number_of_replicas": ${REPLICAS}
      },
      "mappings": {
        "_source": {
          "enabled": true
        },
        "properties": {
          "action": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 128
              }
            }
          },
          "actionner": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 128
              }
            }
          },
          utils.ErrorStr: {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          },
          "event": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 1024
              }
            }
          },
          "message": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 128
              }
            }
          },
          "output": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 2048
              }
            }
          },
          "result": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 2048
              }
            }
          },
          "objects": {
            "properties": {
              "namespace": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 128
                  }
                }
              },
              "pod": {
                "type": "text",
                "fields": {
                  "keyword": {
                    "type": "keyword",
                    "ignore_above": 128
                  }
                }
              }
            }
          },
          "rule": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 128
              }
            }
          },
          "status": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 128
              }
            }
          },
          "trace_id": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          }
        }
      }
    },
    "_meta": {
      "description": "index template for falco talon logs"
    }
  }
`
