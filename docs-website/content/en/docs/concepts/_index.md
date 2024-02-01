---
title: Concepts
weight: 2
description: >
  What does your user need to understand about your project in order to use it - or potentially contribute to it?
---

# Concepts

* Tailor made for the Falco events
* No-code for the users
* UX close to Falco with the rules (yaml files with append, override mechanisms)
* Allow to set up sequential actions to run
* Structured logs (with a trace id)
* Helm chart
* The actions are triggered if match:
  * Falco rule name `(=)`
  * priority (`=`, `>=`)
  * tags (`=`)
  * output fields (`=`, `!=`)

## Architecture

`Falco Talon` can receive the `events` from [`Falco`](https://falco.org) or [`Falcosidekick`](https://github.com/falcosecurity/falcosidekick):


```
┌──────────┐      ┌───────────────┐      ┌─────────────┐
│  Falco   ├──────► Falcosidekick ├──────► Falco Talon │
└──────────┘      └───────────────┘      └─────────────┘
or
┌──────────┐      ┌─────────────┐
│  Falco   ├──────► Falco Talon │
└──────────┘      └─────────────┘
```

## Glossary

* `event`: an event detected by `Falco` and sent to its outputs
* `rule`: defines criterias for linking the events with the actions to apply
* `action`: each rule can sequentially run actions, each action refers to an actionner
* `actionner`: defines what to the action will do
* `notifier`: defines what outputs to notify with the result of the action
