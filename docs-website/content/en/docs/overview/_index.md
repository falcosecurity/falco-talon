---
title: Overview
description: What's Falco Talon?
weight: 1
---

{{% alert title="Warning" color="warning" %}}
Falco Talon is under active development and still in the alpha stage, some breaking changes may happen at any time and the docs might not be up to date.
{{% /alert %}}


## What is the Falco Talon project?

`Falco Talon` is a Response Engine for managing threats in your Kubernetes. It enhances the solutions proposed by the Falco community with a no-code tailor made solution. With easy rules, you can react to `events` from [`Falco`](https://falco.org) in milliseconds.

## Why having created Falco Talon?

Over the years, the Falco community proposed different methods to react to the Falco Events, what we call a response engine. All these methods rely on a 3rd party FaaS (Function as a Service) and come with drawbacks:

* all actions must be developped by the users to manage:
  * the errors
  * the Falco event format
  * the authentication
  * the K8s SDK complexity
  * the security
  * the upgrades of the deps
* latency
* complexity to manage sequential actions
* intrication between the function and its configuration

This is why we started to develop a custom solution especially built for [`Falco`](https://falco.org): `Falco Talon`.

* Tailor made for the Falco events
* **No-code for the users**
* UX close to Falco with the rules (yaml files with append, override mechanisms)
* Allow to set up sequential actions to run
* Structured logs (with a trace id)
* An official Helm chart for the deployment in K8s

The match for the rule can be based on the:
* Falco rule name `(=)`
* priority (`=`, `>=`)
* tags (`=`)
* output fields (`=`, `!=`)

#### What is it good for?:

* React in real-time to the Falco Events
* Allow fine granularity to match the events to react to
* Having default rules and specific overrides 

#### What is it not good for?: 

* Complex reaction worflows with conditions between the steps

#### What is it *not yet* good for?

See this [issue on Github](https://github.com/Issif/falco-talon/issues/136) to know more about the upcoming. features.

## Where should I go next?

Start by learning the [Concepts](/docs/concepts/).
