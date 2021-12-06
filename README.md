# Falco Talon

`Falco Talon` is a Response Engine for managing threats in your Kubernetes. It enhances the solutions proposed by Falco community with a dedicated, no-code, solution. With easy rules, you can `Terminate` or `Labelize` compromised pods.

```
┌──────────┐                 ┌───────────────┐                    ┌─────────────┐
│  Falco   ├─────────────────► Falcosidekick ├────────────────────► Falco Talon │
└──────────┘                 └───────────────┘                    └─────────────┘
```

## Configuration

```
usage: falco-talon [<flags>]

Flags:
      --help                Show context-sensitive help (also try --help-long and --help-man).
  -a, --address="0.0.0.0"   Listen Address
  -p, --port=2803           Listen Port
  -r, --rules=./rules.yaml  Rules file
```

## Rules

Actions to trigger for events are set with rules with this syntax:

```yaml
- name: <string>
  match:
    rules: 
      - <string>
      - <string>
    priority: <string>
    tags: 
      <string>: <string>
      <string>: <string>
  action:
    name: <string>
    options: 
      <string>: <string>
      <string>: <string>
```

With:

* `name`: (*mandatory*) Name of your rule
* `match`:
  * `rules`: (*list*) (`OR` logic) Falco rules to match. If empty, all rules match.
  * `priority`: Priority to match. If empty, all priorities match. Syntax is like `>=Critical`.
  * `tags`: (*list*) (`AND` logic) Tags to match. If empty, all tags match.
  * `output_fields`: (*list*) (`AND`) Output fields to match. If emtpy, all output fields match.
* `action`:
  * `name`: `terminate` or `label`
  * `options`:
    * for `terminate`:
      * `gracePeriodSeconds`: (*numeric*) Time to wait before terminate the pod
    * for `label`:
      * `"key": "value"`: (*list*) Labels to *add*/*modify*. If `value` is empty, the label is removed.

> :bulb: Rules with `terminate` as action are compared first, if one matches, all other rules are ignored.

Examples:

```yaml
- name: Rule 0
  match:
    rules:
      - Terminal shell in container
      - Contact K8S API Server From Container
  action:
    name: terminate
    options:
      gracePeriodSeconds: 3
- name: Rule 1
  match:
    priority: "<Critical"
  action:
    name: label
    options:
      suspicious: "true"
```

