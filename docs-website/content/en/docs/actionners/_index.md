---
title: Actionners
weight: 5
description: >
  Actionners are the built-it actions to react to the events
---

The `Actionners` define the actions to apply when an event matches a rule, they are named with pattern `category:action`.
The `category` allows to group `actions` and avoid multiple initializations (eg, multi Kubernetes API client, multi AWS clients, ...).

Each `actionner` is configured with:
* `parameters`: `key:value` map of parameters passed to the action, the value can be a string, a list (array) or a map (map[string]string). Example: list of `labels` for `kubernetes:labelize`.

{{% alert title="Warning" color="warning" %}}
Some actionners have by default the `Continue: false` setting, this stops the evaluation of the next actions of the rule. It can be overridden.
{{% /alert %}}