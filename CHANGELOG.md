# Changelog

## 0.1.0 - 2024-09-05 - *First GA release.*

Official website for the docs: [https://docs.falco-talon.org/](https://docs.falco-talon.org/)

This release contains:
- the **rule engine to match the Falco events with the actions to perform**
- basic **CLI** features: **check** of the rules, **list** the available actionners, outputs, notifiers, start the **web server** to receive the Falco events
- **metrics** in **Prometheus** and **OTEL format**
- export of **OTEL traces**
- deduplication of the Falco events with **NATS Jetstream**
- 13 **actionners**:
  - `kubernetes:terminate`
  - `kubernetes:label`
  - `kubernetes:networkpolicy`
  - `kubernetes:exec`
  - `kubernetes:script`
  - `kubernetes:log`
  - `kubernetes:delete`
  - `kubernetes:drain`
  - `kubernetes:download`
  - `kubernetes:tcpdump`
  - `aws:lambda`
  - `calico:networkpolicy`
  - `cilium:networkpolicy`
- 6 **notifiers**:
  - `elasticsearch`
  - `k8s events`
  - `loki`
  - `slack`
  - `smtp`
  - `webhook`
- 3 **outputs**:
  - `local:file`
  - `aws:s3`
  - `minio:s3`
- 2 **context** enrichments:
  - `aws` (with IMDS)
  - `k8s`
