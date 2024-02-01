---
title: List of Notifiers
weight: 5
description: >
  Available notifiers
---

## K8s Events

This notifiers creates a [k8s event](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.19/##event-v1-events-k8s-io) in the target resource namespace. No configuration is requested.

## Slack

|    Setting    |                                      Default                                      |        Description         |         |
| ------------- | --------------------------------------------------------------------------------- | -------------------------- | ------- |
| `webhook_url` | n/a                                                                               | Webhook URL                |         |
| `icon`        | `https://upload.wikimedia.org/wikipedia/commons/2/26/Circaetus_gallicus_claw.jpg` | Avatar for messages        |         |
| `username`    | `Falco Talon`                                                                     | Username for messages      |         |
| `footer`      | `https://github.com/Issif/falco-talon`                                            | Footer for messages        |         |
| `format`      | `long`                                                                            | Format for messages (`long | short`) |

### Results:

with `format: short`:

![images/slack_short.png](../images/slack_short.png)

with `format: long`:

![images/slack_long.png](../images/slack_long.png)

## Loki

|     Setting      | Default |         Description          |
| ---------------- | ------- | ---------------------------- |
| `url`            | n/a     | http://{domain or ip}:{port} |
| `user`           | n/a     | User for Grafana Logs        |
| `api_key`        | n/a     | API Key for Grafana Logs     |
| `tenant`         | n/a     | Add the Tenant header        |
| `custom_headers` | n/a     | Custom HTTP Headers          |

## Elasticsearch

|         Setting         |    Default    |                                    Description                                    |
| ----------------------- | ------------- | --------------------------------------------------------------------------------- |
| `host_port`             | n/a           | http://{domain or ip}:{port}                                                      |
| `user`                  | n/a           | User for Grafana Logs                                                             |
| `password`              | n/a           | Password for Grafana Logs                                                         |
| `index`                 | `falco-talon` | Elasticsearch index                                                               |
| `suffix`                | `daily`       | Date suffix for index rotation : `daily` (default), `monthly`, `annually`, `none` |
| `create_index_template` | `true`        | Create the index template at the init if it doesn't exist                         |
| `number_of_shards`      | `3`           | Number of shards for the index  (if `create_index_template` is `true`)            |
| `number_of_replicas`    | `3`           | Number of replicas for the index (if `create_index_template` is `true`)           |
| `custom_headers`        | n/a           | Custom HTTP Headers                                                               |

## SMTP

|   Setting   | Default |              Description              |
| ----------- | ------- | ------------------------------------- |
| `host_port` | n/a     | Host:Port of SMTP server              |
| `user`      | n/a     | User for SMTP                         |
| `password`  | n/a     | Password for SMTP                     |
| `from`      | n/a     | From                                  |
| `to`        | n/a     | To (comma separated list of adresses) |
| `format`    | `html`  | Format of the email (`text`, `html`)  |
| `tls`       | `false` | Use TLS connection                    |

### Results:

with `format: html`:

![./images/smtp_html.png](../images/smtp_html.png)

with `format: text`:

![images/smtp_text.png](../images/smtp_text.png)

## Webhook

|     Setting      |              Default              |     Description     |
| ---------------- | --------------------------------- | ------------------- |
| `url`            | n/a                               | URL                 |
| `http_method`    | `POST`                            | HTTP Method         |
| `user_agent`     | `Falco-Talon`                     | User Agent          |
| `content_type`   | `application/json; charset=utf-8` | Content Type        |
| `custom_headers` | n/a                               | Custom HTTP Headers |

Results:
```json
{"pod":"test","namespace":"default","action":"kubernetes:labelize","status":"success"}
```