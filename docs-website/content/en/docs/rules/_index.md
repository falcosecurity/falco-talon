---
title: Rules
weight: 4
description: >
  The rules define the mapping between the Falco events and the actions to run
---

{{% alert title="Info" color="info" %}}
The rules are evaluated from top to bottom.

Multiple rules files can be used (repeat the `-r` flag), the first file is overriden by the following ones (strings are replaced, lists are appended, ...).
{{% /alert %}}

The syntax for the rules files is:

```yaml
- action: <string,mandatory>
  actionner: <string,mandatory>
  continue: <bool>
  ignore_errors: <bool>
  parameters:
    <string>: <string>
    <string>:
      - <string>
      - <string>
    <string>:
      <string>: <string>
      <string>: <string>

- rule: <string,mandatory>
  match:
    rules:
      - <string>
      - <string>
    priority: <string>
    tags:
      - <string>, <string>, <string>
      - <string>, <string>
    output_fields:
      - <string>=<string>, <string>=<string>
      - <string>!=<string>, <string>=<string>
  continue: <bool>
  dry_run: <bool>
  actions:
    - action: <string,mandatory>
    - action: <string,mandatory>
      actionner: <string,mandatory>
      continue: <bool>
      ignore_errors: <bool>
      parameters:
        <string>: <string>
        <string>:
          - <string>
          - <string>
        <string>:
          <string>: <string>
          <string>: <string>
  notifiers:
    - <string>
    - <string>
```

The rules files contain 2 types of blocks: 
* `action`: defines an action that can be reused by different rules
* `rule`: defines a rule to match with events and run actions

For the `action` block, the settings are:
* `action`: (*mandatory*) name of action to trigger
* `actionner`: name of the actionner to use
* `continue`: if `true`, no more action are applied after this one (each actionner has its own default value).
* `ignore_errors`: if `true`, ignore the errors and avoid to stop at this action.
* `parameters`: key:value map of parameters for the action. value can be a string, an array (slice) or a map.

For the `rule` block, the settings are:
* `rule`: (*mandatory*) Name of your rule
* `match`: the section to define the criterias to match
  * `rules`: (*list*) (`OR` logic) Falco rules to match. If empty, all rules match.
  * `priority`: Priority to match. If empty, all priorities match. Syntax is like: `>=Critical`, `<Warning`, `Debug`.
  * `tags`: (*list*) (`OR` logic) Comma separated lists of Tags to match (`AND` logic). If empty, all tags match.
  * `output_fields`: (*list*) (`OR` logic) Comma separated lists of key:comparison:value for Output fields to match (`AND` logic). If emtpy, all output fields match.
* `actions`: the list of actions to sequentially run, they can refer to an `action` block or defined locally 
  * `action`: (*mandatory*) name of action to trigger, can refer to an `action` block
  * `actionner`: name of the actionner to use
  * `continue`: if `true`, no more action are applied after this one (each actionner has its own default value).
  * `ignore_errors`: if `true`, ignore the errors and avoid to stop at this action.
  * `parameters`: key:value map of parameters for the action. value can be a string, an array (slice) or a map.
* `continue`: if `true`, no more rule are compared after the rule has been triggered (default is `true`).
* `dry_run`: if `true`; the action is not applied (default: `false`).
* `notifiers`: list of notifiers to enabled for the action, in addition with the defaults.

Examples:

```yaml
- action: Terminate Pod
  actionner: kubernetes:terminate
  parameters:
    ignoreDaemonsets: false
    ignoreStatefulsets: true

- action: Disable outbound connections
  actionner: kubernetes:networkpolicy
  parameters:
    allow:
      - "192.168.1.0/24"
      - "172.17.0.0/16"
      - "10.0.0.0/32"

- rule: Suspicious outbound connection
  match:
    rules:
      - Unexpected outbound connection destination
  actions:
    - action: Disable outbound connections
      ignore_errors: true
    - action: Terminate Pod # ref to a re-usable action
      parameters:
        gracePeriods: 2
```